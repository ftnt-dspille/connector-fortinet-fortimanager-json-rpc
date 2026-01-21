#!/usr/bin/env python3
"""
Simple FortiManager Concurrent Test
Uses requests library to test concurrent API operations without any extra complexity
"""

import os
import time
import json
import random
import logging
import urllib3
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

# Suppress insecure HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger('fmg-concurrent-test')

# Load environment variables from .env file
load_dotenv()

# Configuration parameters
HOST = "X.X.X.X"
PORT = 443
API_KEY = "API_KEY"
VERIFY_SSL = False
BASE_URL = f"https://{HOST}:{PORT}/jsonrpc"
ADOM = "root"

# Test parameters
NUM_OBJECTS = 6
CONCURRENT_WORKERS = 3


def make_api_call(method, params, request_id=None):
    """Make a JSON-RPC request to the FortiManager API."""
    if request_id is None:
        request_id = str(random.randint(1, 10000))

    payload = {
        "id": request_id,
        "method": method,
        "params": params,
        "session": None,
        "verbose": 1
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {API_KEY}"
    }

    try:
        response = requests.post(
            BASE_URL,
            headers=headers,
            data=json.dumps(payload),
            verify=VERIFY_SSL,
            timeout=30
        )

        response.raise_for_status()
        result = response.json()

        if "error" in result:
            return -1, result["error"]

        if "result" in result:
            response_data = result["result"]

            if isinstance(response_data, list) and len(response_data) > 0:
                status = response_data[0].get("status", {}).get("code", -1)
                return status, response_data[0]
            else:
                return -1, {"error": "Invalid response format"}
        else:
            return -1, {"error": "No result in response"}

    except Exception as e:
        logger.error(f"API request error: {str(e)}")
        return -1, {"error": str(e)}


def create_address_object(index):
    """Create a single address object."""
    ip_last_octet = random.randint(1, 254)
    object_name = f"simple-test-{index}-{ip_last_octet}"
    ip_address = f"10.0.{index % 255}.{ip_last_octet}"

    params = [{
        "url": f"/pm/config/adom/{ADOM}/obj/firewall/address/",
        "data": [{
            "name": object_name,
            "subnet": [ip_address, "255.255.255.255"],
            "type": "ipmask"
        }]
    }]

    logger.info(f"Creating address object: {object_name} ({ip_address})")
    status, response = make_api_call("add", params, f"create-{index}")

    if status == 0:
        logger.info(f"✅ Successfully created: {object_name}")
        return object_name
    else:
        error_message = "Unknown error"
        if isinstance(response, dict) and "status" in response:
            error_message = response["status"].get("message", "Unknown error")
        logger.error(f"❌ Failed to create {object_name}: status={status}, message={error_message}")
        return None


def delete_address_object(object_name):
    """Delete a single address object."""
    if not object_name:
        return False

    params = [{
        "url": f"/pm/config/adom/{ADOM}/obj/firewall/address/{object_name}"
    }]

    logger.info(f"Deleting address object: {object_name}")
    status, response = make_api_call("delete", params, f"delete-{object_name}")

    if status == 0:
        logger.info(f"✅ Successfully deleted: {object_name}")
        return True
    else:
        error_message = "Unknown error"
        if isinstance(response, dict) and "status" in response:
            error_message = response["status"].get("message", "Unknown error")
        logger.error(f"❌ Failed to delete {object_name}: status={status}, message={error_message}")
        return False


def test_api_access():
    """Test basic API access and permissions."""
    logger.info("Testing API access...")

    # Check if we can connect and get system status
    status, response = make_api_call("get", [{"url": "/sys/status"}], "test-connection")

    if status != 0:
        logger.error(f"❌ API connection test failed with status {status}")
        logger.error(f"Response: {response}")
        return False

    logger.info("✅ Successfully connected to FortiManager API")

    # Try to create a test object to verify write permissions
    test_name = "permission-test-object"
    test_params = [{
        "url": f"/pm/config/adom/{ADOM}/obj/firewall/address/",
        "data": [{
            "name": test_name,
            "subnet": ["1.1.1.1", "255.255.255.255"],
            "type": "ipmask"
        }]
    }]

    status, response = make_api_call("add", test_params, "test-create")

    if status != 0:
        logger.error(f"❌ API permission test failed with status {status}")
        error_message = "Unknown error"
        if isinstance(response, dict) and "status" in response:
            error_message = response["status"].get("message", "Unknown error")
        logger.error(f"Error message: {error_message}")
        return False

    logger.info("✅ Successfully verified API write permissions")

    # Clean up test object
    make_api_call("delete", [{"url": f"/pm/config/adom/{ADOM}/obj/firewall/address/{test_name}"}], "test-delete")

    return True


def run_concurrent_test():
    """Run the concurrent test creating and deleting address objects."""
    # Make sure we have valid credentials and permissions
    if not test_api_access():
        logger.error("API access test failed. Please check your API key and configuration.")
        return

    # Track timing and results
    start_time = time.time()
    logger.info(f"Starting concurrent test with {NUM_OBJECTS} objects and {CONCURRENT_WORKERS} workers")

    # Create objects concurrently
    created_objects = []
    failed_create = 0

    logger.info("Creating objects concurrently...")
    with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
        future_to_index = {executor.submit(create_address_object, i): i for i in range(1, NUM_OBJECTS + 1)}

        for future in as_completed(future_to_index):
            index = future_to_index[future]
            try:
                object_name = future.result()
                if object_name:
                    created_objects.append(object_name)
                else:
                    failed_create += 1
            except Exception as e:
                logger.error(f"Worker exception for index {index}: {e}")
                failed_create += 1

    create_time = time.time() - start_time
    logger.info(f"Created {len(created_objects)} objects, {failed_create} failed in {create_time:.2f} seconds")

    # Delete objects concurrently
    delete_start = time.time()
    failed_delete = 0

    logger.info("Deleting objects concurrently...")
    with ThreadPoolExecutor(max_workers=CONCURRENT_WORKERS) as executor:
        future_to_name = {executor.submit(delete_address_object, name): name for name in created_objects}

        for future in as_completed(future_to_name):
            try:
                if not future.result():
                    failed_delete += 1
            except Exception as e:
                logger.error(f"Delete worker exception: {e}")
                failed_delete += 1

    delete_time = time.time() - delete_start
    total_time = time.time() - start_time

    # Print summary
    logger.info("\n=== TEST SUMMARY ===")
    logger.info(f"Total objects attempted: {NUM_OBJECTS}")
    logger.info(f"Objects created successfully: {len(created_objects)}")
    logger.info(f"Creation failures: {failed_create}")
    logger.info(f"Deletion failures: {failed_delete}")
    logger.info(f"Creation time: {create_time:.2f} seconds")
    logger.info(f"Deletion time: {delete_time:.2f} seconds")
    logger.info(f"Total time: {total_time:.2f} seconds")

    if failed_create > 0:
        logger.warning(f"\n⚠️ {failed_create} objects failed to create - this may indicate a concurrency issue")
        logger.warning("Check the logs above for the specific error messages")


if __name__ == "__main__":
    run_concurrent_test()