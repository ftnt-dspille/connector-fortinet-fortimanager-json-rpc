""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json
from json import JSONDecodeError

from connectors.core.connector import get_logger

# from .utils import create_fmg_session
from .generic_json_rpc import perform_rpc_action  # ty:ignore[unresolved-import]

logger = get_logger('fortinet-fortimanager-policy-management')


def parse_fields(fields):
    if isinstance(fields, str) and fields.startswith("["):
        try:
            fields = json.loads(fields)
        except JSONDecodeError:
            pass
    elif isinstance(fields, str):
        fields = fields.split(",")

    if not isinstance(fields, list):
        fields = None
    return fields


def _get_package_policies(config, params):
    adom = params.get("adom")
    policy_package = params.get("policy_package")
    fields = parse_fields(params.get("fields"))

    firewall_params = {
        "url": f"/pm/config/adom/{adom}/pkg/{policy_package}/firewall/policy",
        "fields": fields,
    }
    if not fields:
        firewall_params.pop("fields")

    policies = perform_rpc_action("get", config, firewall_params).get("get_response", {})
    adom_addresses = perform_rpc_action(
        "get", config, {"url": f"/pm/config/adom/{adom}/obj/firewall/address"}
    ).get("get_response", {})
    adom_address_groups = perform_rpc_action(
        "get", config, {"url": f"/pm/config/adom/{adom}/obj/firewall/addrgrp"}
    ).get("get_response", {})
    adom_services = perform_rpc_action(
        "get", config, {"url": f"/pm/config/adom/{adom}/obj/firewall/service/custom"}
    ).get("get_response", {})
    adom_service_groups = perform_rpc_action(
        "get", config, {"url": f"/pm/config/adom/{adom}/obj/firewall/service/group"}
    ).get("get_response", {})

    adom_address_names = [address["name"] for address in adom_addresses]
    adom_group_names = [group["name"] for group in adom_address_groups]
    adom_service_names = [service["name"] for service in adom_services]
    adom_service_group_names = [service_group["name"] for service_group in adom_service_groups]

    # loop through each policy in policies, and resolve the srcaddr and dstaddr members.
    # each policy has a 'srcaddr' and dstaddr key, which is a list of address names or address group names.
    # Groups can store either addresses or other groups.
    # If the name is in the group_names list, then we need to look at the members key of the group object.
    # it is possible for a group to be a member of another group, so we need to recursively resolve the members
    # If the name is in the address_names list, then we need to store the address object on the policy
    # we want to replace the list of address names with a list of address objects.

    def resolve_members(group):
        for member in group["member"]:
            if member in adom_group_names:
                nested_group = next(group for group in adom_address_groups if group["name"] == member)
                resolve_members(nested_group)
            elif member in adom_address_names:
                resolved_members.append(
                    next(address for address in adom_addresses if address["name"] == member))

    def check_address(_address_name):
        # if the address name is in the group_names list
        if _address_name in adom_group_names:
            # find the group object
            group = next(group for group in adom_address_groups if group["name"] == _address_name)
            # recursively resolve the members
            resolve_members(group)
        # if the address name is in the address_names list
        elif _address_name in adom_address_names:
            # find the address object
            resolved_members.append(next(
                address_object for address_object in adom_addresses if address_object["name"] == _address_name))

    # Need to do the same thing for services to unpack the service objects
    # A list of services is present in the policy['service'] key
    # Each service is a name, which is present in the service_names list
    # We need to replace the list of service names with a list of service objects

    def resolve_service_members(group):
        for member in group["member"]:
            if member in adom_service_group_names:
                nested_group = next(group for group in adom_service_group_names if group["name"] == member)
                resolve_service_members(nested_group)
            elif member in adom_service_names:
                resolved_members.append(
                    next(service for service in adom_services if service["name"] == member))

    def check_service(_service_name):
        # if the service name is in the service_names list
        if _service_name in adom_service_group_names:
            # find the group object
            service_group = next(group for group in adom_service_groups if group["name"] == _service_name)
            # recursively resolve the members
            resolve_service_members(service_group)
        elif _service_name in adom_service_names:
            # find the service object
            resolved_members.append(next(
                service_object for service_object in adom_services if service_object["name"] == _service_name))

    # loop through each policy in policies
    for policy in policies:
        resolved_members = []
        # loop through each address name in the srcaddr list
        for address_name in policy["srcaddr"]:
            check_address(address_name)
        policy["srcaddr_resolved"] = resolved_members

        resolved_members = []
        # loop through each address name in the dstaddr list
        for address_name in policy["dstaddr"]:
            check_address(address_name)
        policy["dstaddr_resolved"] = resolved_members

        resolved_members = []
        # loop through each service name in the service list
        for service_name in policy["service"]:
            check_service(service_name)
        policy["service_resolved"] = resolved_members

    return policies
