"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError
from .generic_json_rpc import perform_rpc_action
from .fortimanager_device_stats import get_fortimanager_device_stats

logger = get_logger('fortinet-fortimanager-json-rpc')


def _check_health(config: dict) -> bool:
    params = {"url": "/sys/status", "data": {}}
    try:
        response = perform_rpc_action("get", config, params)
        if response['get_response']:
            return True
    except Exception as e:
        raise ConnectorError(str(e) + " - Unable to get system status")


def json_rpc_add(config: dict, params: dict) -> dict:
    action = "add"
    try:
        response = perform_rpc_action(action, config, params)
        return response
    except Exception as e:
        raise ConnectorError(str(e))


def json_rpc_set(config: dict, params: dict) -> dict:
    action = "set"
    try:
        response = perform_rpc_action(action, config, params)
        return response
    except Exception as e:
        raise ConnectorError(str(e))


def json_rpc_get(config: dict, params: dict) -> dict:
    action = "get"
    try:
        response = perform_rpc_action(action, config, params)
        return response
    except Exception as e:
        raise ConnectorError(str(e))


def json_rpc_execute(config: dict, params: dict) -> dict:
    action = "execute"
    try:
        response = perform_rpc_action(action, config, params)
        return response
    except Exception as e:
        raise ConnectorError(str(e))


def json_rpc_delete(config: dict, params: dict) -> dict:
    action = "delete"
    try:
        response = perform_rpc_action(action, config, params)
        return response
    except Exception as e:
        raise ConnectorError(str(e))


def json_rpc_freeform(config: dict, params: dict) -> dict:
    action = "free_form"
    try:
        response = perform_rpc_action(action, config, params)
        return response
    except Exception as e:
        raise ConnectorError(str(e))


operations = {
    'json_rpc_add': json_rpc_add,
    'json_rpc_set': json_rpc_set,
    'json_rpc_get': json_rpc_get,
    'json_rpc_execute': json_rpc_execute,
    'json_rpc_delete': json_rpc_delete,
    'json_rpc_freeform': json_rpc_freeform,
    'get_fortimanager_device_stats': get_fortimanager_device_stats,
    'check_health': _check_health
}
