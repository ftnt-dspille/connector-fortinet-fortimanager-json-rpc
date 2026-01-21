#!/bin/bash
# FortiManager Concurrent Test Script
# This script tests concurrent creation and deletion of address objects in FortiManager
# by spawning multiple processes using curl commands with the API key

# Configuration - defaults that can be overridden by .env
FMG_HOST=""
FMG_PORT="443"
API_KEY=""
ADOM="root"
NUM_OBJECTS=100
NUM_CONCURRENT=10  # Number of concurrent processes to run

# Load environment variables if available
if [ -f .env ]; then
  echo "Loading environment variables from .env file"
  while IFS='=' read -r key value || [ -n "$key" ]; do
    # Skip comments and empty lines
    [[ "$key" =~ ^[[:space:]]*#.*$ ]] && continue
    [[ -z "$key" ]] && continue
    
    # Trim whitespace from key and value
    key=$(echo "$key" | xargs)
    value=$(echo "$value" | xargs)
    
    # Remove quotes from value if present
    value=$(echo "$value" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
    
    case "$key" in
      ADDRESS)
        FMG_HOST=$(echo "$value" | sed 's|https://||' | sed 's|http://||' | sed 's|/.*||')
        ;;
      PORT)
        FMG_PORT="$value"
        ;;
      API_KEY)
        API_KEY="$value"
        ;;
    esac
  done < .env
fi

# Create a log file for output
LOG_FILE="fmg_concurrent_test.log"
> "$LOG_FILE"  # Clear the log file

# Function to log messages
log() {
  local timestamp
  timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  echo "[$timestamp] $1" | tee -a "$LOG_FILE"
}

# Function to generate a random IP address (last octet)
random_ip() {
  echo "10.0.$1.$(( (RANDOM % 254) + 1 ))"
}

# Function to create a single address object
create_address() {
  local index=$1
  local name="bash-test-host-$index"
  local ip=$(random_ip "$index")

  log "Process $$ - Creating address object: $name ($ip)"

  # Prepare JSON data
  local json_data='{
    "method": "add",
    "params": [
      {
        "url": "/pm/config/adom/'"$ADOM"'/obj/firewall/address/",
        "data": [
          {
            "name": "'"$name"'",
            "subnet": ["'"$ip"'", "255.255.255.255"],
            "type": "ipmask"
          }
        ]
      }
    ],
    "id": "'"$index"'",
    "session": null
  }'

  # Send request to FortiManager
  local response
  response=$(curl -s -k -X POST "https://$FMG_HOST:$FMG_PORT/jsonrpc" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "$json_data")

  # Extract status from response
  local status
  status=$(echo "$response" | grep -o '"code":[^,}]*' | head -1 | cut -d':' -f2)

  if [ "$status" = "0" ]; then
    log "Process $$ - Successfully created object: $name"
    echo "$name"
  else
    error=$(echo "$response" | grep -o '"message":"[^"]*' | head -1 | cut -d'"' -f4)
    log "Process $$ - Failed to create object $name: status=$status, error=$error"
    log "Process $$ - Response: $response"
    echo ""
  fi
}

# Function to delete a single address object
delete_address() {
  local name=$1

  if [ -z "$name" ]; then
    return 1
  fi

  log "Process $$ - Deleting address object: $name"

  # Prepare JSON data
  local json_data='{
    "method": "delete",
    "params": [
      {
        "url": "/pm/config/adom/'"$ADOM"'/obj/firewall/address/'"$name"'"
      }
    ],
    "id": "delete-'"$name"'",
    "session": null
  }'

  # Send request to FortiManager
  local response
  response=$(curl -s -k -X POST "https://$FMG_HOST:$FMG_PORT/jsonrpc" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "$json_data")

  # Extract status from response
  local status
  status=$(echo "$response" | grep -o '"code":[^,}]*' | head -1 | cut -d':' -f2)

  if [ "$status" = "0" ]; then
    log "Process $$ - Successfully deleted object: $name"
    return 0
  else
    error=$(echo "$response" | grep -o '"message":"[^"]*' | head -1 | cut -d'"' -f4)
    log "Process $$ - Failed to delete object $name: status=$status, error=$error"
    log "Process $$ - Response: $response"
    return 1
  fi
}

# Test API key permissions
test_permissions() {
  log "Testing API key permissions..."

  # Check if we can access system status
  local json_data='{
    "method": "get",
    "params": [
      {
        "url": "/sys/status"
      }
    ],
    "id": "test-permissions",
    "session": null
  }'

  local response
  response=$(curl -s -k -X POST "https://$FMG_HOST:$FMG_PORT/jsonrpc" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "$json_data")

  if echo "$response" | grep -q '"code": 0'; then
    log "API key has basic access to FortiManager"
  else
    log "ERROR: API key does not have basic access to FortiManager"
    log "Response: $response"
    return 1
  fi

  # Test creating a test object
  local test_name="bash-permission-test-object"
  local test_data='{
    "method": "add",
    "params": [
      {
        "url": "/pm/config/adom/'"$ADOM"'/obj/firewall/address/",
        "data": [
          {
            "name": "'"$test_name"'",
            "subnet": ["1.1.1.1", "255.255.255.255"],
            "type": "ipmask"
          }
        ]
      }
    ],
    "id": "test-create",
    "session": null
  }'

  response=$(curl -s -k -X POST "https://$FMG_HOST:$FMG_PORT/jsonrpc" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d "$test_data")

  if echo "$response" | grep -q '"code": 0'; then
    log "API key has permission to create address objects"

    # Clean up test object
    local delete_data='{
      "method": "delete",
      "params": [
        {
          "url": "/pm/config/adom/'"$ADOM"'/obj/firewall/address/'"$test_name"'"
        }
      ],
      "id": "test-delete",
      "session": null
    }'

    curl -s -k -X POST "https://$FMG_HOST:$FMG_PORT/jsonrpc" \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer $API_KEY" \
      -d "$delete_data" > /dev/null

    return 0
  else
    local error
    error=$(echo "$response" | grep -o '"message":"[^"]*' | head -1 | cut -d'"' -f4)
    log "ERROR: API key does not have permission to create address objects"
    log "Status: $(echo "$response" | grep -o '"code":[^,}]*' | head -1 | cut -d':' -f2), Error: $error"
    log "Response: $response"
    return 1
  fi
}

# Main function
main() {
  local start_time
  start_time=$(date +%s)

  log "Starting FortiManager Concurrent Test"
  log "Host: $FMG_HOST:$FMG_PORT, ADOM: $ADOM"
  log "Number of objects: $NUM_OBJECTS, Concurrent processes: $NUM_CONCURRENT"

  # Test permissions
  if ! test_permissions; then
    log "Permission test failed. Please check your API key and try again."
    exit 1
  fi

  # Create temporary file to store object names
  local objects_file
  objects_file=$(mktemp)

  log "Creating address objects concurrently..."

  # Start creation processes in batches
  local i=1
  while [ $i -le $NUM_OBJECTS ]; do
    local running=0
    local batch_end=$((i + NUM_CONCURRENT - 1))

    if [ $batch_end -gt $NUM_OBJECTS ]; then
      batch_end=$NUM_OBJECTS
    fi

    for j in $(seq $i $batch_end); do
      # Run the create function in background
      create_address "$j" >> "$objects_file" &

      # Increment counter for running processes
      running=$((running + 1))

      # Small delay to avoid overwhelming the system
      sleep 0.1
    done

    # Wait for all background processes to complete
    wait

    log "Completed batch from $i to $batch_end"
    i=$((batch_end + 1))
  done

  # Count successful creations
  local created_count
  created_count=$(grep -v "^$" "$objects_file" | wc -l)
  log "Successfully created $created_count objects out of $NUM_OBJECTS"

  # Delete objects
  log "Deleting address objects concurrently..."

  # Read object names from file
  local objects
  mapfile -t objects < "$objects_file"

  # Start deletion processes in batches
  local deleted_count=0
  local failed_deletions=0
  i=0

  while [ $i -lt ${#objects[@]} ]; do
    local running=0
    local batch_end=$((i + NUM_CONCURRENT - 1))

    if [ $batch_end -ge ${#objects[@]} ]; then
      batch_end=$((${#objects[@]} - 1))
    fi

    for j in $(seq $i $batch_end); do
      # Skip empty lines
      if [ -n "${objects[$j]}" ]; then
        # Run the delete function in background and capture its exit status
        delete_address "${objects[$j]}" &> /dev/null &
        local pid=$!
        wait $pid
        if [ $? -eq 0 ]; then
          deleted_count=$((deleted_count + 1))
        else
          failed_deletions=$((failed_deletions + 1))
        fi

        # Increment counter for running processes
        running=$((running + 1))

        # Small delay to avoid overwhelming the system
        sleep 0.1
      fi
    done

    # Wait for all background processes to complete
    wait

    log "Completed deletion batch from $i to $batch_end"
    i=$((batch_end + 1))
  done

  # Clean up temporary file
  rm -f "$objects_file"

  # Calculate and report total execution time
  local end_time
  end_time=$(date +%s)
  local duration=$((end_time - start_time))

  log "Test completed in $duration seconds"
  log "Created $created_count objects out of $NUM_OBJECTS"
  log "Deleted $deleted_count objects, $failed_deletions failed deletions"
}

# Execute main function
main