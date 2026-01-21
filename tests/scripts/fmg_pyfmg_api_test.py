#!/usr/bin/env python3
"""
FortiManager Direct API Test Script
This script uses pyFMG directly with API key to create and delete address objects
to help isolate issues with concurrent vs sequential operations.
"""

import os
import sys
import time
import random
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from pyFMG.fortimgr import FortiManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('fmg_direct_api_test.log')
    ]
)
logger = logging.getLogger('fmg-direct-test')

# Load environment variables from .env file
load_dotenv()


def get_api_config():
    """Get the API key configuration from environment variables."""
    config = {
        "host": os.getenv("ADDRESS").replace("https://", "").replace("http://", ""),
        "port": os.getenv("PORT", "443"),
        "apikey": os.getenv("API_KEY"),
        "verify_ssl": os.getenv("VERIFY_SSL", "False").lower() in ("true", "1", "t"),
        "debug": os.getenv("DEBUG_CONNECTION", "False").lower() in ("true", "1", "t"),
        "verbose": os.getenv("VERBOSE_JSON", "True").lower() in ("true", "1", "t"),
    }

    # Validate required config
    required_fields = ["host", "port", "apikey"]
    missing_fields = [field for field in required_fields if not config.get(field)]

    if missing_fields:
        logger.error(f"Missing required configuration: {', '.join(missing_fields)}")
        sys.exit(1)

    return config


def create_address_object(fmg, index, adom="root"):
    """Create a single address object."""
    ip_last_octet = random.randint(1, 254)
    object_name = f"direct-test-host-{index}-{ip_last_octet}"
    ip_address = f"10.0.{index % 255}.{ip_last_octet}"

    url = f"/pm/config/adom/{adom}/obj/firewall/address/"
    data = [{
        "name": object_name,
        "subnet": [ip_address, "255.255.255.255"],
        "type": "ipmask"
    }]

    try:
        logger.info(f"Creating address object: {object_name} ({ip_address})")
        status, response = fmg.add(url=url, data=data)

        if status == 0:
            logger.info(f"Successfully created address object: {object_name}")
            return object_name
        else:
            error_message = "Unknown error"
            if isinstance(response, dict) and "status" in response:
                error_message = response["status"].get("message", "Unknown error")
            logger.error(f"Failed to create {object_name}: status={status}, message={error_message}")
            return None
    except Exception as e:
        logger.error(f"Exception creating address object {object_name}: {str(e)}")
        return None


def delete_address_object(fmg, object_name, adom="root"):
    """Delete a single address object."""
    if not object_name:
        return False

    url = f"/pm/config/adom/{adom}/obj/firewall/address/{object_name}"

    try:
        logger.info(f"Deleting address object: {object_name}")
        status, response = fmg.delete(url=url)

        if status == 0:
            logger.info(f"Successfully deleted address object: {object_name}")
            return True
        else:
            error_message = "Unknown error"
            if isinstance(response, dict) and "status" in response:
                error_message = response["status"].get("message", "Unknown error")
            logger.error(f"Failed to delete {object_name}: status={status}, message={error_message}")
            return False
    except Exception as e:
        logger.error(f"Exception deleting address object {object_name}: {str(e)}")
        return False


def check_permissions(fmg, adom="root"):
    """Test basic API permissions to help diagnose issues."""
    logger.info("Testing API permissions...")

    # Test 1: Check health by getting system status
    try:
        status, response = fmg.get(url="/sys/status")
        if status == 0:
            logger.info("Successfully connected to FortiManager")
        else:
            logger.error(f"Failed to get system status: status={status}")
            return False
    except Exception as e:
        logger.error(f"Exception getting system status: {str(e)}")
        return False

    # Test 2: Try to get devices
    try:
        status, response = fmg.get(url="/dvmdb/device")
        if status == 0:
            logger.info("Successfully retrieved device information")
        else:
            logger.error(f"Failed to get devices: status={status}")
    except Exception as e:
        logger.error(f"Exception getting devices: {str(e)}")

    # Test 3: Try to create a test object
    test_name = "direct-permission-test-object"
    url = f"/pm/config/adom/{adom}/obj/firewall/address/"
    data = [{
        "name": test_name,
        "subnet": ["1.1.1.1", "255.255.255.255"],
        "type": "ipmask"
    }]

    try:
        status, response = fmg.add(url=url, data=data)
        if status == 0:
            logger.info(f"Successfully created test object '{test_name}'")

            # Clean up test object
            delete_url = f"/pm/config/adom/{adom}/obj/firewall/address/{test_name}"
            fmg.delete(url=delete_url)
            return True
        else:
            error_message = "Unknown error"
            if isinstance(response, dict) and "status" in response:
                error_message = response["status"].get("message", "Unknown error")
            logger.error(f"Permission test failed: status={status}, message={error_message}")
            return False
    except Exception as e:
        logger.error(f"Exception during permission test: {str(e)}")
        return False


def sequential_operations(fmg, num_objects=100, adom="root"):
    """Execute operations sequentially."""
    logger.info(f"Starting sequential creation of {num_objects} address objects...")

    created_objects = []
    failed_create_count = 0

    # Create objects sequentially
    for i in range(1, num_objects + 1):
        object_name = create_address_object(fmg, i, adom)
        if object_name:
            created_objects.append(object_name)
        else:
            failed_create_count += 1

        # Small delay to avoid overwhelming the FortiManager
        time.sleep(0.1)

    logger.info(f"Created {len(created_objects)} objects successfully, {failed_create_count} failed")

    # Delete objects sequentially
    failed_delete_count = 0

    logger.info(f"Starting sequential deletion of {len(created_objects)} address objects...")
    for object_name in created_objects:
        if not delete_address_object(fmg, object_name, adom):
            failed_delete_count += 1

        # Small delay to avoid overwhelming the FortiManager
        time.sleep(0.1)

    logger.info(
        f"Deleted {len(created_objects) - failed_delete_count} objects successfully, {failed_delete_count} failed")

    return len(created_objects), failed_create_count, failed_delete_count


def concurrent_operations(fmg, num_objects=100, max_workers=10, adom="root"):
    """Execute operations concurrently."""
    logger.info(f"Starting concurrent creation of {num_objects} address objects with {max_workers} workers...")

    created_objects = []
    failed_create_count = 0

    # Create objects concurrently
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_index = {executor.submit(create_address_object, fmg, i, adom): i for i in range(1, num_objects + 1)}

        # Process results as they complete
        for future in as_completed(future_to_index):
            index = future_to_index[future]
            try:
                object_name = future.result()
                if object_name:
                    created_objects.append(object_name)
                else:
                    failed_create_count += 1
            except Exception as e:
                logger.error(f"Worker for index {index} generated an exception: {e}")
                failed_create_count += 1

    logger.info(f"Created {len(created_objects)} objects successfully, {failed_create_count} failed")

    # Delete objects concurrently
    failed_delete_count = 0

    logger.info(f"Starting concurrent deletion of {len(created_objects)} address objects with {max_workers} workers...")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_name = {executor.submit(delete_address_object, fmg, name, adom): name for name in created_objects}

        # Process results as they complete
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result = future.result()
                if not result:
                    failed_delete_count += 1
            except Exception as e:
                logger.error(f"Worker for object {name} generated an exception: {e}")
                failed_delete_count += 1

    logger.info(
        f"Deleted {len(created_objects) - failed_delete_count} objects successfully, {failed_delete_count} failed")

    return len(created_objects), failed_create_count, failed_delete_count


def main():
    """Main function to process arguments and run tests."""
    parser = argparse.ArgumentParser(description="FortiManager Direct API Test Script")
    parser.add_argument("--mode", choices=["sequential", "concurrent", "both"], default="both",
                        help="Operation mode: sequential, concurrent, or both")
    parser.add_argument("--objects", type=int, default=100, help="Number of objects to create and delete")
    parser.add_argument("--workers", type=int, default=10, help="Number of concurrent workers")
    parser.add_argument("--adom", default="root", help="ADOM to use for operations")

    args = parser.parse_args()

    start_time = time.time()
    logger.info(f"Starting FortiManager Direct API Test in {args.mode} mode")

    config = get_api_config()
    logger.info(f"Using FortiManager at {config['host']}:{config['port']}")

    try:
        with FortiManager(config["host"], user=None, passwd=None, apikey=config["apikey"],
                          verify_ssl=config["verify_ssl"], debug=config["debug"], verbose=config["verbose"],
                          disable_request_warnings=True) as fmg:

            # Test API permissions first
            if not check_permissions(fmg, args.adom):
                logger.error("Permission test failed. Please check your API key permissions.")
                logger.error(
                    "The API key needs 'Read-Write' permission for JSON API, specifically for firewall address objects.")
                sys.exit(1)

            if args.mode in ["sequential", "both"]:
                seq_start = time.time()
                seq_created, seq_failed_create, seq_failed_delete = sequential_operations(
                    fmg, args.objects, args.adom)
                seq_duration = time.time() - seq_start
                logger.info(f"Sequential operations completed in {seq_duration:.2f} seconds")

            if args.mode in ["concurrent", "both"]:
                conc_start = time.time()
                conc_created, conc_failed_create, conc_failed_delete = concurrent_operations(
                    fmg, args.objects, args.workers, args.adom)
                conc_duration = time.time() - conc_start
                logger.info(f"Concurrent operations completed in {conc_duration:.2f} seconds")

            # Compare results if both modes were run
            if args.mode == "both":
                logger.info("\nCOMPARISON SUMMARY:")
                logger.info(f"Sequential: {seq_created} created, {seq_failed_create} failed creations, "
                            f"{seq_failed_delete} failed deletions, {seq_duration:.2f} seconds")
                logger.info(f"Concurrent: {conc_created} created, {conc_failed_create} failed creations, "
                            f"{conc_failed_delete} failed deletions, {conc_duration:.2f} seconds")

                # Check if concurrent mode had more failures
                if conc_failed_create > seq_failed_create:
                    logger.warning(
                        f"Concurrent mode had {conc_failed_create - seq_failed_create} more creation failures than sequential mode!")
                if conc_failed_delete > seq_failed_delete:
                    logger.warning(
                        f"Concurrent mode had {conc_failed_delete - seq_failed_delete} more deletion failures than sequential mode!")

    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

    total_time = time.time() - start_time
    logger.info(f"Test completed in {total_time:.2f} seconds!")


if __name__ == "__main__":
    main()