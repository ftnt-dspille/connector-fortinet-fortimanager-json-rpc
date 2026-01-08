"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from typing import List, Optional

from connectors.core.connector import get_logger, ConnectorError

from .generic_json_rpc import perform_rpc_action
import json
logger = get_logger('fortinet-fortimanager-json-rpc')


def get_fortimanager_device_stats(config: dict, params: dict) -> dict:
    """
    Gather comprehensive FortiManager device statistics including:
    - Device details (uptime, firmware, HA status)
    - Firewall policies
    - Firewall policy statistics

    Args:
        config: Connector configuration
        params: {
            "device_targets": List of device paths (e.g., ["device/FGT1", "device/FGT2"])
            "vdom": VDOM to query (default: "root")
            "include_device_info": Include device details (default: True)
            "include_policies": Include firewall policies (default: True)
            "include_policy_stats": Include policy statistics (default: True)
            "policy_fields": Optional list of policy fields to retrieve
            "stat_fields": Optional list of stat fields to retrieve
            "merge_stats": Merge policy stats with policy data (default: True)
        }

    Returns:
        dict: Structured device statistics with merged policy and stats data
    """
    try:
        # Parse parameters
        device_targets = params.get("device_targets", [])
        if not device_targets:
            raise ConnectorError("device_targets parameter is required and must be a non-empty list")

        if not isinstance(device_targets, list):
            try:
                device_targets = json.loads(device_targets)
            except Exception as e:
                raise ConnectorError("device_targets must be a list of device paths")

        vdom = params.get("vdom", "root")
        include_device_info = params.get("include_device_info", True)
        include_policies = params.get("include_policies", True)
        include_policy_stats = params.get("include_policy_stats", True)
        merge_stats = params.get("merge_stats", True)

        # Default field sets
        default_policy_fields = [
            "policyid", "name", "status", "action", "srcintf", "dstintf",
            "srcaddr", "dstaddr", "schedule", "service", "logtraffic", "nat", "comments"
        ]
        default_stat_fields = [
            "policyid", "bytes", "packets", "last_used", "first_used", "hit_count"
        ]

        policy_fields = params.get("policy_fields", [])
        stat_fields = params.get("stat_fields", [])

        if not isinstance(policy_fields, list):
            try:
                policy_fields = json.loads(policy_fields)
                if not policy_fields:
                    policy_fields = default_policy_fields
            except Exception as e:
                raise ConnectorError("policy_fields must be a list of policy fields")

        if not isinstance(stat_fields, list):
            try:
                stat_fields = json.loads(stat_fields)
                if not stat_fields:
                    stat_fields = default_stat_fields
            except Exception as e:
                raise ConnectorError("stat_fields must be a list of stat_fields")

        # Initialize result structure
        result = {
            "status": 200,
            "devices": [],
            "summary": {
                "total_devices": len(device_targets),
                "devices_processed": 0,
                "devices_failed": 0
            }
        }

        # Batch get device information for all devices
        device_info_map = {}
        if include_device_info:
            device_info_map = _get_device_info_batch(config, device_targets, vdom)

        # Batch get firewall policies for all devices
        policies_map = {}
        if include_policies:
            policies_map = _get_firewall_policies_batch(config, device_targets, vdom, policy_fields)

        # Batch get firewall policy statistics for all devices
        stats_map = {}
        if include_policy_stats:
            stats_map = _get_firewall_stats_batch(config, device_targets, vdom, stat_fields)

        # Process each device with batched data
        for device_target in device_targets:
            device_data = {
                "target": device_target,
                "status": "pending",
                "errors": []
            }

            try:
                # Add device information
                if include_device_info and device_target in device_info_map:
                    device_data.update(device_info_map[device_target])

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
                    # device_data["policy_stats"] = stats

                # Merge stats with policies if requested
                if merge_stats and include_policies and include_policy_stats and policies and stats:
                    merged_policies = _merge_policies_and_stats(policies, stats)
                    device_data["policies"] = merged_policies
                    # Keep raw stats for reference
                    # device_data["raw_policy_stats"] = stats

                device_data["status"] = "success"
                result["summary"]["devices_processed"] += 1

            except Exception as e:
                logger.error(f"Error processing device {device_target}: {str(e)}")
                device_data["status"] = "failed"
                device_data["errors"].append(str(e))
                result["summary"]["devices_failed"] += 1

            result["devices"].append(device_data)
        print(json.dumps(result, indent=4))
        return result

    except Exception as e:
        logger.exception(f"Error in get_fortimanager_device_stats: {str(e)}")
        raise ConnectorError(str(e))


def _get_device_info_batch(config: dict, device_targets: List[str], vdom: str) -> dict:
    """Get device information for multiple devices in batch"""
    device_info_map = {}

    try:
        # Batch request for system status
        status_payload = {
            "url": "/sys/proxy/json",
            "data": {
                "action": "get",
                "target": device_targets,
                "resource": f"/api/v2/monitor/system/status?vdom={vdom}"
            }
        }

        response = perform_rpc_action("free_form", config, {
            "method": "exec",
            "data": [status_payload]
        })

        if response.get("status") == 200 and response.get("free_form_response"):
            # Process each device's response
            for idx, result in enumerate(response["free_form_response"][0]["data"]):
                device_target = device_targets[idx]
                device_info_map[device_target] = {
                    "device_details": {},
                    "ha_status": {}
                }

                if result.get("status", {}).get("code") == 0:
                    sys_status = result.get("response", {})
                    print(json.dumps(sys_status, indent=4))
                    device_info_map[device_target]["device_details"] = {
                        "serial": sys_status.get("serial"),
                        "hostname": sys_status.get("hostname"),
                        "version": sys_status.get("version"),
                        "uptime": sys_status.get("uptime"),
                        "model": sys_status.get("model"),
                        "operation_mode": sys_status.get("operation_mode")
                    }
                else:
                    device_info_map[device_target]["errors"] = [f"Failed to get system status: {result.get('status', {}).get('message')}"]

        # Batch request for HA status
        ha_payload = {
            "url": "/sys/proxy/json",
            "data": {
                "action": "get",
                "target": device_targets,
                "resource": f"/api/v2/monitor/system/ha-peer?vdom={vdom}"
            }
        }

        ha_response = perform_rpc_action("free_form", config, {
            "method": "exec",
            "data": [ha_payload]
        })

        if ha_response.get("status") == 200 and ha_response.get("free_form_response"):
            # Process each device's HA response
            for idx, result in enumerate(ha_response["free_form_response"][0]["data"]):
                device_target = device_targets[idx]

                if device_target in device_info_map and result.get("status", {}).get("code") == 0:
                    ha_data = result.get("response", {})
                    device_info_map[device_target]["ha_status"] = {
                        "ha_enabled": len(ha_data.get("results", [])) > 0,
                        "ha_peers": ha_data.get("results", [])
                    }

    except Exception as e:
        logger.warning(f"Could not retrieve device info in batch: {str(e)}")
        # Initialize empty structures for all devices on error
        for device_target in device_targets:
            if device_target not in device_info_map:
                device_info_map[device_target] = {
                    "device_details": {},
                    "ha_status": {},
                    "errors": [f"Device info retrieval error: {str(e)}"]
                }

    return device_info_map


def _get_device_info(config: dict, device_target: str, vdom: str) -> dict:
    """Get device information including uptime, firmware version, HA status"""
    device_info = {
        "device_details": {},
        "ha_status": {}
    }

    try:
        # Get system status
        status_payload = {
            "url": "/sys/proxy/json",
            "data": {
                "action": "get",
                "target": [device_target],
                "resource": f"/api/v2/monitor/system/status?vdom={vdom}"
            }
        }

        response = perform_rpc_action("free_form", config, {
            "method": "exec",
            "data": [status_payload]
        })

        if response.get("status") == 200 and response.get("free_form_response"):
            sys_status = response["free_form_response"][0]["data"][0]["response"]
            device_info["device_details"] = {
                "serial": sys_status.get("serial"),
                "hostname": sys_status.get("hostname"),
                "version": sys_status.get("version"),
                "uptime": sys_status.get("uptime"),
                "model": sys_status.get("model"),
                "operation_mode": sys_status.get("operation_mode")
            }

        # Get HA status
        ha_payload = {
            "url": "/sys/proxy/json",
            "data": {
                "action": "get",
                "target": [device_target],
                "resource": f"/api/v2/monitor/system/ha-peer?vdom={vdom}"
            }
        }

        ha_response = perform_rpc_action("free_form", config, {
            "method": "exec",
            "data": [ha_payload]
        })

        if ha_response.get("status") == 200 and ha_response.get("free_form_response"):
            ha_data = ha_response["free_form_response"][0]["data"][0]["response"]
            device_info["ha_status"] = {
                "ha_enabled": len(ha_data.get("results", [])) > 0,
                "ha_peers": ha_data.get("results", [])
            }

    except Exception as e:
        logger.warning(f"Could not retrieve device info for {device_target}: {str(e)}")
        device_info["errors"] = [f"Device info retrieval error: {str(e)}"]

    return device_info


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
                device_target = device_targets[idx]
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
        raise

    return policies_map


def _get_firewall_policies(config: dict, device_target: str, vdom: str,
                           fields: Optional[List[str]] = None) -> List[dict]:
    """Get firewall policies for a device"""
    policies = []

    try:
        # Build format parameter
        format_param = ""
        if fields:
            format_param = f"&format={('|'.join(fields))}"

        policy_payload = {
            "url": "/sys/proxy/json",
            "data": {
                "action": "get",
                "target": [device_target],
                "resource": f"/api/v2/cmdb/firewall/policy?vdom={vdom}{format_param}"
            }
        }

        response = perform_rpc_action("free_form", config, {
            "method": "exec",
            "data": [policy_payload]
        })

        if response.get("status") == 200 and response.get("free_form_response"):
            results = response["free_form_response"][0]["data"][0]["response"].get("results", [])

            # Clean up policies - flatten list fields
            for policy in results:
                cleaned_policy = _clean_policy_data(policy)
                policies.append(cleaned_policy)

    except Exception as e:
        logger.error(f"Error retrieving firewall policies for {device_target}: {str(e)}")
        raise

    return policies


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
                device_target = device_targets[idx]
                stats = []

                if result.get("status", {}).get("code") == 0:
                    results = result.get("response", {}).get("results", [])
                    stats = results

                stats_map[device_target] = stats

    except Exception as e:
        logger.error(f"Error retrieving firewall stats in batch: {str(e)}")
        raise

    return stats_map


def _get_firewall_stats(config: dict, device_target: str, vdom: str,
                        fields: Optional[List[str]] = None) -> List[dict]:
    """Get firewall policy statistics for a device"""
    stats = []

    try:
        # Build format parameter
        format_param = ""
        if fields:
            format_param = f"&format={('|'.join(fields))}"

        stats_payload = {
            "url": "/sys/proxy/json",
            "data": {
                "action": "get",
                "target": [device_target],
                "resource": f"/api/v2/monitor/firewall/policy?vdom={vdom}{format_param}"
            }
        }

        response = perform_rpc_action("free_form", config, {
            "method": "exec",
            "data": [stats_payload]
        })

        if response.get("status") == 200 and response.get("free_form_response"):
            results = response["free_form_response"][0]["data"][0]["response"].get("results", [])
            stats = results

    except Exception as e:
        logger.error(f"Error retrieving firewall stats for {device_target}: {str(e)}")
        raise

    return stats


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


def _merge_policies_and_stats(policies: List[dict], stats: List[dict]) -> List[dict]:
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

        merged_policies.append(merged_policy)

    return merged_policies