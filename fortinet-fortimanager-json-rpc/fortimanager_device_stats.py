"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import json
from typing import List, Optional

from connectors.core.connector import get_logger, ConnectorError

from .generic_json_rpc import perform_rpc_action

logger = get_logger('fortinet-fortimanager-json-rpc')


def get_fortimanager_device_stats(config: dict, params: dict) -> dict:
    """
    Gather comprehensive FortiManager device statistics including:
    - Device details from /dvmdb/device
    - Firewall policies
    - Firewall policy statistics

    Args:
        config: Connector configuration
        params: {
            "adom": ADOM to query (optional - if not provided, queries all devices across all ADOMs)
            "vdom": VDOM to query (default: "root")
            "device_filter": Optional filter for devices (default: [["os_type","==","fos"],"&&",["conn_status","==","up"]])
            "device_fields": Optional list of device fields to retrieve
            "device_options": Optional list of device options (e.g., ["extra info", "assignment info", "get meta", "loadsub"])
            "include_policies": Include firewall policies (default: True)
            "include_policy_stats": Include policy statistics (default: True)
            "policy_fields": Optional list of policy fields to retrieve
            "stat_fields": Optional list of stat fields to retrieve
            "merge_stats": Merge policy stats with policy data (default: True)
            "include_target": Include device target inside policy (default: True)
            "additional_calls": Optional list of custom sys/proxy/json calls to query for each target.
                                Each call should be a dict: {"url": "...", "return_key": "...", "action": "...", "data": {...}}
        }

    Returns:
        dict: Structured device statistics with merged policy and stats data
    """
    try:
        # Parse parameters
        adom = params.get("adom", None)  # None means query all ADOMs
        vdom = params.get("vdom", "root")
        include_policies = params.get("include_policies", True)
        include_policy_stats = params.get("include_policy_stats", True)
        merge_stats = params.get("merge_stats", True)
        include_target = params.get("include_policy_target", True)

        # Default device query parameters
        default_device_fields = [
            "name", "hostname", "extra info", "ha_slave", "platform_str",
            "os_type", "os_ver", "conn_status", "ip", "sn", "mr", "patch"
        ]
        default_device_options = ["extra info", "assignment info", "get meta", "loadsub"]
        default_device_filter = [["os_type", "==", "fos"], "&&", ["conn_status", "==", "up"]]

        # Parse device query parameters
        device_fields = params.get("device_fields", "")
        if not isinstance(device_fields, list):
            try:
                # Handle empty string as default
                if device_fields and device_fields.strip():
                    device_fields = json.loads(device_fields)
                else:
                    device_fields = default_device_fields
            except Exception as e:
                raise ConnectorError("device_fields must be a list of field names")
        if not device_fields:
            device_fields = default_device_fields

        device_options = params.get("device_options", "")
        if not isinstance(device_options, list):
            try:
                # Handle empty string as default
                if device_options and device_options.strip():
                    device_options = json.loads(device_options)
                else:
                    device_options = default_device_options
            except Exception as e:
                raise ConnectorError("device_options must be a list of option names")
        if not device_options:
            device_options = default_device_options

        device_filter = params.get("device_filter", "")
        if not isinstance(device_filter, list):
            try:
                # Handle empty string as default
                if device_filter and device_filter.strip():
                    device_filter = json.loads(device_filter)
                else:
                    device_filter = default_device_filter
            except Exception as e:
                raise ConnectorError("device_filter must be a list representing filter criteria")
        if not device_filter:
            device_filter = default_device_filter

        # Default policy field sets
        default_policy_fields = [
            "policyid", "name", "status", "action", "srcintf", "dstintf",
            "srcaddr", "dstaddr", "schedule", "service", "logtraffic", "nat", "comments"
        ]
        default_stat_fields = [
            "policyid", "bytes", "packets", "last_used", "first_used", "hit_count"
        ]

        policy_fields = params.get("policy_fields", "")
        stat_fields = params.get("stat_fields", "")

        if not isinstance(policy_fields, list):
            try:
                # Handle empty string as default
                if policy_fields and policy_fields.strip():
                    policy_fields = json.loads(policy_fields)
                else:
                    policy_fields = default_policy_fields
            except Exception as e:
                raise ConnectorError("policy_fields must be a list of policy fields")
        if not policy_fields:
            policy_fields = default_policy_fields

        if not isinstance(stat_fields, list):
            try:
                # Handle empty string as default
                if stat_fields and stat_fields.strip():
                    stat_fields = json.loads(stat_fields)
                else:
                    stat_fields = default_stat_fields
            except Exception as e:
                raise ConnectorError("stat_fields must be a list of stat_fields")
        if not stat_fields:
            stat_fields = default_stat_fields

        # Additional calls processing
        additional_calls = params.get("additional_calls", [])
        if isinstance(additional_calls, str) and additional_calls.strip():
            try:
                additional_calls = json.loads(additional_calls)
            except Exception as e:
                raise ConnectorError(f"additional_calls must be a list of JSON objects: {str(e)}")

        if not isinstance(additional_calls, list):
            additional_calls = []

        # Query devices from /dvmdb/device
        devices_data = _get_devices_from_dvmdb(config, adom, device_fields, device_options, device_filter)

        if not devices_data:
            return {
                "status": 200,
                "devices": [],
                "summary": {
                    "total_devices": 0,
                    "devices_processed": 0,
                    "devices_failed": 0
                },
                "message": "No devices found matching the criteria"
            }

        # Extract device targets for policy queries
        device_targets = [f"/device/{device['name']}" for device in devices_data]

        # Initialize result structure
        result = {
            "status": 200,
            "devices": [],
            "summary": {
                "total_devices": len(devices_data),
                "devices_processed": 0,
                "devices_failed": 0
            }
        }

        # Batch get firewall policies for all devices
        policies_map = {}
        if include_policies:
            policies_map = _get_firewall_policies_batch(config, device_targets, vdom, policy_fields)

        # Batch get firewall policy statistics for all devices
        stats_map = {}
        if include_policy_stats:
            stats_map = _get_firewall_stats_batch(config, device_targets, vdom, stat_fields)

        # Execute additional calls if provided
        additional_results_map = {}
        if additional_calls:
            additional_results_map = _get_additional_calls_batch(config, device_targets, additional_calls)

        # Process each device with batched data
        for idx, device_info in enumerate(devices_data):
            device_target = device_targets[idx]
            device_data = {
                "target": device_target,
                "status": "pending",
                "errors": [],
                "device_info": device_info  # Include the device info from /dvmdb/device
            }

            try:
                # Add firewall policies
                policies = []
                if include_policies and device_target in policies_map:
                    policies = policies_map[device_target]
                    device_data["policies"] = policies
                    device_data["policy_count"] = len(policies)

                # Add firewall policy statistics
                stats = []
                if include_policy_stats and device_target in stats_map:
                    stats = stats_map[device_target]

                # Merge stats with policies if requested
                if merge_stats and include_policies and include_policy_stats and policies and stats:
                    merged_policies = _merge_policies_and_stats(policies, stats, include_target, device_target )
                    device_data["policies"] = merged_policies

                # Add additional call results
                if device_target in additional_results_map:
                    for key, value in additional_results_map[device_target].items():
                        device_data[key] = value

                device_data["status"] = "success"
                result["summary"]["devices_processed"] += 1

            except Exception as e:
                logger.error(f"Error processing device {device_target}: {str(e)}")
                device_data["status"] = "failed"
                device_data["errors"].append(str(e))
                result["summary"]["devices_failed"] += 1

            result["devices"].append(device_data)
        print(json.dumps(result, indent=2))
        return result

    except Exception as e:
        logger.exception(f"Error in get_fortimanager_device_stats: {str(e)}")
        raise ConnectorError(str(e))


def _get_devices_from_dvmdb(config: dict, adom: Optional[str], fields: List[str],
                            options: List[str], device_filter: List) -> List[dict]:
    """
    Query devices directly from /dvmdb/device endpoint

    Args:
        config: Connector configuration
        adom: ADOM to query (None = all ADOMs)
        fields: List of fields to retrieve
        options: List of options (e.g., "extra info", "assignment info")
        device_filter: Filter criteria for devices

    Returns:
        List of device dictionaries
    """
    try:
        # Build the query parameters
        query_data = {
            "fields": fields,
            "option": options,
            "filter": device_filter
        }

        # Construct the URL - if no adom specified, query all devices
        if adom:
            url = f"/dvmdb/adom/{adom}/device"
        else:
            url = "/dvmdb/device"

        # Make the request
        dvmdb_params = {
            "url": url,
            "data": query_data
        }

        response = perform_rpc_action("get", config, dvmdb_params)

        if response.get("status") == 0 and response.get("get_response"):
            devices = response["get_response"]
            logger.info(f"Retrieved {len(devices)} devices from {url}")
            return devices
        else:
            logger.warning(f"No devices returned from {url}: {response}")
            return []

    except Exception as e:
        logger.error(f"Error querying /dvmdb/device: {str(e)}")
        raise ConnectorError(f"Failed to retrieve devices from FortiManager: {str(e)}")


def _get_firewall_policies_batch(config: dict, device_targets: List[str], vdom: str,
                                 fields: Optional[List[str]] = None) -> dict:
    """Get firewall policies for multiple devices in batch"""
    policies_map = {}

    try:
        # Build format parameter
        format_param = ""
        if fields:
            format_param = f"&format={('|'.join(fields))}"

        policy_payload = {
            "url": "/sys/proxy/json",
            "data": {
                "action": "get",
                "target": device_targets,
                "resource": f"/api/v2/cmdb/firewall/policy?vdom={vdom}{format_param}"
            }
        }

        response = perform_rpc_action("free_form", config, {
            "method": "exec",
            "data": [policy_payload]
        })

        if response.get("status") == 200 and response.get("free_form_response"):
            # Process each device's response
            for idx, result in enumerate(response["free_form_response"][0]["data"]):
                device_target = f"/device/{result['target']}" if "/" not in result["target"] else result["target"]
                policies = []

                if result.get("status", {}).get("code") == 0:
                    results = result.get("response", {}).get("results", [])
                    # Clean up policies - flatten list fields
                    for policy in results:
                        cleaned_policy = _clean_policy_data(policy)
                        policies.append(cleaned_policy)

                policies_map[device_target] = policies

    except Exception as e:
        logger.error(f"Error retrieving firewall policies in batch: {str(e)}")
        # Don't raise - allow function to continue without policies
        logger.warning("Continuing without policy data")

    return policies_map


def _get_firewall_stats_batch(config: dict, device_targets: List[str], vdom: str,
                              fields: Optional[List[str]] = None) -> dict:
    """Get firewall policy statistics for multiple devices in batch"""
    stats_map = {}

    try:
        # Build format parameter
        format_param = ""
        if fields:
            format_param = f"&format={('|'.join(fields))}"

        stats_payload = {
            "url": "/sys/proxy/json",
            "data": {
                "action": "get",
                "target": device_targets,
                "resource": f"/api/v2/monitor/firewall/policy?vdom={vdom}{format_param}"
            }
        }

        response = perform_rpc_action("free_form", config, {
            "method": "exec",
            "data": [stats_payload]
        })

        if response.get("status") == 200 and response.get("free_form_response"):
            # Process each device's response
            for idx, result in enumerate(response["free_form_response"][0]["data"]):
                device_target = f"/device/{result['target']}" if "/" not in result["target"] else result["target"]
                stats = []

                if result.get("status", {}).get("code") == 0:
                    results = result.get("response", {}).get("results", [])
                    stats = results

                stats_map[device_target] = stats

    except Exception as e:
        logger.error(f"Error retrieving firewall stats in batch: {str(e)}")
        # Don't raise - allow function to continue without stats
        logger.warning("Continuing without policy statistics")

    return stats_map


def _get_additional_calls_batch(config: dict, device_targets: List[str], additional_calls: List[dict]) -> dict:
    """Execute additional custom calls for multiple devices in batch"""
    results_map = {}
    # Initialize map for each device
    for target in device_targets:
        results_map[target] = {}

    try:
        batch_requests = []
        for call in additional_calls:
            url = call.get("url")
            return_key = call.get("return_key")
            action = call.get("action", "get")
            payload_data = call.get("data", {})

            if not url or not return_key:
                logger.warning(f"Skipping additional call due to missing url or return_key: {call}")
                continue

            # Check if it is a proxy call
            if url.startswith("/api/v2/"):
                # Wrap in sys/proxy/json
                request_payload = {
                    "url": "/sys/proxy/json",
                    "data": {
                        "action": action,
                        "target": device_targets,
                        "resource": url
                    }
                }
                # Also include any extra data if provided (though sys/proxy/json has specific format)
                if payload_data:
                    request_payload["data"].update(payload_data)
            else:
                # Direct FMG call for each target (if url contains target placeholder or similar)
                # But the requirement says "queried for each of the targets".
                # If it's a direct FMG call like /dvmdb/device/..., it might already include the target.
                # For now, let's assume if it's not a proxy call, we might still want to target it.
                # However, FMG's sys/proxy/json is the most common way to target a device.
                # If they want a direct FMG call per device, we need to know how to parameterize it.
                
                # Assuming standard proxy-like behavior if they want it "per target"
                request_payload = {
                    "url": url,
                    "data": {
                        "target": device_targets
                    }
                }
                if payload_data:
                    request_payload["data"].update(payload_data)

            batch_requests.append({
                "method": "exec" if action == "execute" else "get", # Simplified mapping
                "payload": request_payload,
                "return_key": return_key,
                "is_proxy": url.startswith("/api/v2/")
            })

        # Execute each batch request
        # Note: We could potentially bundle these even more if they use the same method, 
        # but for simplicity and because each call has its own return_key, we'll do them one by one.
        # But wait, perform_rpc_action with free_form can take a list of data.
        
        free_form_data = [req["payload"] for req in batch_requests]
        
        if not free_form_data:
            return results_map

        response = perform_rpc_action("free_form", config, {
            "method": "exec",
            "data": free_form_data
        })

        if response.get("status") == 200 and response.get("free_form_response"):
            # free_form_response is a list of responses, one for each item in free_form_data
            for idx, resp_item in enumerate(response["free_form_response"]):
                req_info = batch_requests[idx]
                return_key = req_info["return_key"]
                
                # Process the data list which contains results for each target
                resp_data = resp_item.get("data")
                if isinstance(resp_data, list):
                    for target_result in resp_data:
                        target_name = target_result.get("target")
                        if not target_name:
                            continue
                        
                        device_target = f"/device/{target_name}" if "/" not in target_name else target_name
                        
                        if device_target in results_map:
                            if target_result.get("status", {}).get("code") == 0:
                                results_map[device_target][return_key] = target_result.get("response")
                            else:
                                results_map[device_target][f"{return_key}_error"] = target_result.get("status")
                elif isinstance(resp_data, dict):
                    # Single target response
                    target_name = resp_data.get("target")
                    if target_name:
                        device_target = f"/device/{target_name}" if "/" not in target_name else target_name
                        if device_target in results_map:
                            if resp_data.get("status", {}).get("code") == 0:
                                results_map[device_target][return_key] = resp_data.get("response")
                            else:
                                results_map[device_target][f"{return_key}_error"] = resp_data.get("status")
                else:
                    # Not a multi-target response or failed
                    logger.warning(f"Additional call for {return_key} did not return expected data format: {resp_item}")

    except Exception as e:
        logger.error(f"Error executing additional calls in batch: {str(e)}")

    return results_map


def _clean_policy_data(policy: dict) -> dict:
    """Clean and flatten policy data for better readability"""
    cleaned = {}

    for key, value in policy.items():
        if isinstance(value, list):
            # Flatten list fields by extracting 'name' attribute
            if value and isinstance(value[0], dict) and 'name' in value[0]:
                cleaned[key] = ', '.join([item['name'] for item in value])
            else:
                cleaned[key] = value
        else:
            cleaned[key] = value

    return cleaned


def _merge_policies_and_stats(policies: List[dict], stats: List[dict], include_target: bool, device_target: str) -> List[dict]:
    """
    Merge firewall policy statistics with policy data based on policyid

    Args:
        policies: List of policy dictionaries
        stats: List of statistics dictionaries

    Returns:
        List of merged policy dictionaries with statistics included
    """
    # Create a lookup dictionary for stats by policyid
    stats_lookup = {}
    for stat in stats:
        policy_id = stat.get("policyid")
        if policy_id is not None:
            stats_lookup[policy_id] = stat

    # Merge stats into policies
    merged_policies = []
    for policy in policies:
        policy_id = policy.get("policyid")
        merged_policy = policy.copy()

        if policy_id in stats_lookup:
            stat_data = stats_lookup[policy_id]
            # Add stats as nested object
            merged_policy["statistics"] = {
                "bytes": stat_data.get("bytes", 0),
                "packets": stat_data.get("packets", 0),
                "hit_count": stat_data.get("hit_count", 0),
                "first_used": stat_data.get("first_used"),
                "last_used": stat_data.get("last_used")
            }
        else:
            # No stats available for this policy
            merged_policy["statistics"] = {
                "bytes": 0,
                "packets": 0,
                "hit_count": 0,
                "first_used": None,
                "last_used": None
            }
        if include_target:
            merged_policy["device_target"] = device_target

        merged_policies.append(merged_policy)

    return merged_policies
