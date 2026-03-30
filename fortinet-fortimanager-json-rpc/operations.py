"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

from connectors.core.connector import ConnectorError, get_logger

from .fortimanager_device_stats import get_fortimanager_device_stats  # ty:ignore[unresolved-import]
from .generic_json_rpc import perform_rpc_action  # ty:ignore[unresolved-import]
from .gui_json_rpc import get_device_vulnerabilities as gui_get_vulnerabilities  # ty:ignore[unresolved-import]
from .gui_json_rpc import perform_gui_action  # ty:ignore[unresolved-import]
from .policies import _get_package_policies  # ty:ignore[unresolved-import]

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

def get_package_policies(config, params):
    try:
        response = _get_package_policies(config, params)
        return response
    except Exception as e:
        raise ConnectorError(str(e))


def json_rpc_gui(config: dict, params: dict) -> dict:
    """
    Perform a GUI login-based action on FortiManager.
    This action uses the GUI authentication endpoint instead of JSON-RPC.

    :param config: Connector configuration
    :param params: Action parameters (gui_method, url, data)
    :return: Response dictionary
    """
    try:
        response = perform_gui_action(config, params)
        return response
    except Exception as e:
        raise ConnectorError(str(e))

def get_device_vulnerabilities(config: dict, params: dict) -> dict:
    try:
        response = gui_get_vulnerabilities(config, params)
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
    'get_package_policies': get_package_policies,
    'get_fortimanager_device_stats': get_fortimanager_device_stats,
    'json_rpc_gui': json_rpc_gui,
    'get_device_vulnerabilities': get_device_vulnerabilities,
    'check_health': _check_health
}
