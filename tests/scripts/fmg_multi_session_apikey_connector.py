#!/usr/bin/env python3
"""
FortiManager Parallel Address Object Operations
This script creates and deletes 100 IP address objects in parallel using the API key method
and provides detailed error reporting.
"""

import os
import sys
import time
import random
import logging
import importlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('fortimanager_parallel_test.log')
    ]
)
logger = logging.getLogger('fortimanager-test')

# Load environment variables from .env file
load_dotenv()

# Dynamically import the operations module
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))
sys.path.insert(0, parent_dir)

try:
    module_name = "fortinet-fortimanager-json-rpc.operations"
    operations_module = importlib.import_module(module_name)
    operations = operations_module.operations
except ImportError as e:
    logger.error(f"Failed to import operations module: {e}")
    sys.exit(1)


def get_api_config():
    """Get the API key configuration from environment variables."""
    config = {
        "auth_method": "API Key",
        "api_key": os.getenv("API_KEY"),
        "address": os.getenv("ADDRESS"),
        "port": os.getenv("PORT"),
        "verify_ssl": os.getenv("VERIFY_SSL", "False").lower() in ("true", "1", "t"),
        "debug_connection": os.getenv("DEBUG_CONNECTION", "False").lower() in ("true", "1", "t"),
        "verbose_json": os.getenv("VERBOSE_JSON", "True").lower() in ("true", "1", "t"),
    }

    # Validate required config
    required_fields = ["api_key", "address", "port"]
    missing_fields = [field for field in required_fields if not config.get(field)]

    if missing_fields:
        logger.error(f"Missing required configuration: {', '.join(missing_fields)}")
        sys.exit(1)

    return config


def create_address_object(config, index):
    """Create a single address object."""
    ip_last_octet = random.randint(1, 254)
    object_name = f"test-host-{index}-{ip_last_octet}"
    ip_address = f"10.0.{index % 255}.{ip_last_octet}"

    params_add = {
        "url": "/pm/config/adom/root/obj/firewall/address/",
        "data": [{
            "name": object_name,
            "subnet": [ip_address, "255.255.255.255"],
            "type": "ipmask"
        }]
    }

    try:
        logger.info(f"Creating address object: {object_name} ({ip_address})")
        add_response = operations['json_rpc_add'](config, params_add)

        status = add_response.get("status")
        if status != 0:
            error_message = add_response.get("add_response", {}).get("status", {}).get("message", "Unknown error")
            logger.error(f"Failed to create {object_name}: status={status}, message={error_message}")
            return None

        logger.info(f"Successfully created address object: {object_name}")
        return object_name
    except Exception as e:
        logger.error(f"Exception creating address object {object_name}: {str(e)}")
        return None


def delete_address_object(config, object_name):
    """Delete a single address object."""
    if not object_name:
        return False

    params_delete = {
        "url": f"/pm/config/adom/root/obj/firewall/address/{object_name}"
    }

    try:
        logger.info(f"Deleting address object: {object_name}")
        delete_response = operations['json_rpc_delete'](config, params_delete)

        status = delete_response.get("status")
        if status != 0:
            error_message = delete_response.get("delete_response", {}).get("status", {}).get("message", "Unknown error")
            logger.error(f"Failed to delete {object_name}: status={status}, message={error_message}")
            return False

        logger.info(f"Successfully deleted address object: {object_name}")
        return True
    except Exception as e:
        logger.error(f"Exception deleting address object {object_name}: {str(e)}")
        return False


def check_permissions(config):
    """Test basic API permissions to help diagnose issues."""
    logger.info("Testing API permissions...")

    # Test 1: Check health
    try:
        health_result = operations['check_health'](config)
        logger.info(f"Health check result: {health_result}")
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return False

    # Test 2: Try to get devices (should be readable with minimal permissions)
    try:
        get_params = {"url": "/dvmdb/device"}
        get_response = operations['json_rpc_get'](config, get_params)
        status = get_response.get("status")
        if status == 0:
            logger.info("Successfully retrieved device information")
        else:
            error_message = get_response.get("get_response", {}).get("status", {}).get("message", "Unknown error")
            logger.error(f"Failed to get devices: status={status}, message={error_message}")
    except Exception as e:
        logger.error(f"Exception getting devices: {str(e)}")

    # Test 3: Try to create a test object (main functionality we're testing)
    test_name = "permission-test-object"
    test_params = {
        "url": "/pm/config/adom/root/obj/firewall/address/",
        "data": [{
            "name": test_name,
            "subnet": ["1.1.1.1", "255.255.255.255"],
            "type": "ipmask"
        }]
    }

    try:
        add_response = operations['json_rpc_add'](config, test_params)
        status = add_response.get("status")
        if status == 0:
            logger.info(f"Successfully created test object '{test_name}'")

            # Clean up test object
            delete_params = {
                "url": f"/pm/config/adom/root/obj/firewall/address/{test_name}"
            }
            operations['json_rpc_delete'](config, delete_params)
            return True
        else:
            error_message = add_response.get("add_response", {}).get("status", {}).get("message", "Unknown error")
            logger.error(f"Permission test failed: status={status}, message={error_message}")
            return False
    except Exception as e:
        logger.error(f"Exception during permission test: {str(e)}")
        return False


def parallel_create_objects(config, num_objects=100, max_workers=10):
    """Create multiple address objects in parallel."""
    created_objects = []
    failed_count = 0

    logger.info(f"Creating {num_objects} address objects with {max_workers} parallel workers...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_index = {executor.submit(create_address_object, config, i): i for i in range(1, num_objects + 1)}

        # Process results as they complete
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            try:
                object_name = future.result()
                if object_name:
                    created_objects.append(object_name)
                else:
                    failed_count += 1
            except Exception as e:
                logger.error(f"Worker for index {index} generated an exception: {e}")
                failed_count += 1

    logger.info(f"Created {len(created_objects)} objects successfully, {failed_count} failed")
    return created_objects


def parallel_delete_objects(config, object_names, max_workers=10):
    """Delete multiple address objects in parallel."""
    successful_deletions = 0
    failed_deletions = 0

    logger.info(f"Deleting {len(object_names)} address objects with {max_workers} parallel workers...")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_name = {executor.submit(delete_address_object, config, name): name for name in object_names}

        # Process results as they complete
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result = future.result()
                if result:
                    successful_deletions += 1
                else:
                    failed_deletions += 1
            except Exception as e:
                logger.error(f"Worker for object {name} generated an exception: {e}")
                failed_deletions += 1

    logger.info(f"Deleted {successful_deletions} objects successfully, {failed_deletions} failed")
    return successful_deletions, failed_deletions


def main():
    """Main function to create and delete 100 address objects in parallel."""
    start_time = time.time()
    logger.info("Starting FortiManager Parallel Address Object Operations")

    config = get_api_config()
    logger.info(f"Using FortiManager at {config['address']}:{config['port']}")

    # Test API permissions first
    if not check_permissions(config):
        logger.error("Permission test failed. Please check your API key permissions.")
        logger.error(
            "The API key needs 'Read-Write' permission for JSON API, specifically for firewall address objects.")
        sys.exit(1)

    # Number of objects to create
    num_objects = 100

    # Number of parallel workers - adjust based on FortiManager performance
    max_workers = 10

    # Create objects in parallel
    created_objects = parallel_create_objects(config, num_objects, max_workers)

    # Delete objects in parallel
    parallel_delete_objects(config, created_objects, max_workers)

    # Calculate and log total execution time
    total_time = time.time() - start_time
    logger.info(f"Test completed in {total_time:.2f} seconds!")


if __name__ == "__main__":
    main()