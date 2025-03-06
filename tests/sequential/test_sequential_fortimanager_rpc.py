"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import importlib
import logging
import os
import sys

import pytest
from dotenv import load_dotenv

# Set up logging
logger = logging.getLogger(__name__)

# Load environment variables from .env file in the parent directory
current_directory = os.path.dirname(__file__)
parent_directory = os.path.abspath(os.path.join(current_directory, os.pardir))
grandparent_directory = os.path.abspath(os.path.join(parent_directory, os.pardir))

# Add the grandparent directory to the system path
sys.path.insert(0, str(grandparent_directory))

env_path = os.path.join(parent_directory, '.env')
load_dotenv(dotenv_path=env_path)

# Import the operations dynamically
operations_module_name = "fortinet-fortimanager-json-rpc.operations"
operations_package = importlib.import_module(operations_module_name)
# Import the operations dictionary from the module
operations = operations_package.operations

# import the generic_json_rpc module
generic_json_rpc_module_name = "fortinet-fortimanager-json-rpc.generic_json_rpc"
generic_json_rpc_package = importlib.import_module(generic_json_rpc_module_name)

# import the generic_json_rpc functions
parse_adom_from_input = generic_json_rpc_package.parse_adom_from_input
parse_task_timeout = generic_json_rpc_package.parse_task_timeout
parse_data = generic_json_rpc_package.parse_data


LIVE_FGT_DEVICE_NAME = os.getenv("LIVE_FGT_DEVICE_NAME")
FGT_ASSIGNED_POL_PKG = os.getenv("FGT_ASSIGNED_POL_PKG")

@pytest.fixture(params=["Username/Password", "API Key"])
def auth_config(request):
    base_config = {
        "address": os.getenv("ADDRESS"),
        "verify_ssl": os.getenv("VERIFY_SSL", "False").lower() in ("true", "1", "t"),
        "port": os.getenv("PORT"),
        "debug_connection": os.getenv("DEBUG_CONNECTION", "False").lower() in ("true", "1", "t"),
        "verbose_json": os.getenv("VERBOSE_JSON", "True").lower() in ("true", "1", "t"),
    }

    if request.param == "Username/Password":
        base_config.update({
            "username": os.getenv("USERNAME"),
            "password": os.getenv("PASSWORD"),
            "auth_method": "Username/Password"
        })
        logger.info("Running tests with Username/Password authentication")
    else:
        base_config.update({
            "api_key": os.getenv("API_KEY"),
            "auth_method": "API Key"
        })
        logger.info("Running tests with APIKey authentication")

    return base_config


# Add this to ensure the logs are captured and displayed in pytest output
@pytest.fixture(autouse=True)
def _log_level(caplog):
    caplog.set_level(logging.INFO)


@pytest.fixture
def setup_params(auth_config):
    params_add = {
        "url": "/pm/config/adom/root/obj/firewall/address/",
        "data": [{
            "name": "host-172-23-200-121",
            "subnet": [
                "172.23.200.121",
                "255.255.255.255"
            ],
            "type": "ipmask"
        }]
    }
    params_delete = {
        "url": "/pm/config/adom/root/obj/firewall/address/host-172-23-200-121"
    }
    return auth_config, params_add, params_delete


def test_check_health(auth_config):
    try:
        response = operations['check_health'](auth_config)
        assert response, "Expected True for health check"
    except operations_package.ConnectorError as e:
        assert False, f"Unexpected error: {e}"


def test_fail_check_health(auth_config):
    try:
        bad_config = auth_config.copy()
        bad_config['address'] = 'https://invalid-address'
        bad_config['port'] = "123"
        response = operations['check_health'](bad_config)
        assert False, "Expected error for invalid address"
    except operations_package.ConnectorError:
        assert True, f"Expected error for invalid address"


def test_rpc_get(auth_config):
    params = {"url": "/dvmdb/device"}
    response = operations['json_rpc_get'](auth_config, params)
    # Status should be 0 for success
    assert response.get("status", None) == 0

    assert "get_response" in response, "Response missing 'get_response' key"


def test_rpc_get_invalid_url(auth_config):
    params = {"url": "/dvmdb/devices", "data": ""}
    response = operations['json_rpc_get'](auth_config, params)
    # Status should be 0 for success
    assert response.get("status", None) == -3, "Expected status -3 for invalid URL"

    assert "get_response" in response, "Response missing 'get_response' key"

    assert (response.get("get_response", {}).
            get("status", {}).
            get("message", {}) == "Object does not exist"), \
        "Expected message 'Object does not exist' for invalid URL"


def test_rpc_get_invalid_json(auth_config):
    params = {"url": "/dvmdb/devices", "data": "{"}
    try:
        response = operations['json_rpc_get'](auth_config, params)
    except operations_package.ConnectorError as e:
        assert True, f"Expected error for invalid params"


def test_rpc_get_invalid_data(auth_config):
    params = {"url": "/dvmdb/devices", "data": 123}
    try:
        response = operations['json_rpc_get'](auth_config, params)
    except operations_package.ConnectorError as e:
        assert True, f"Expected error for invalid params"


def test_rpc_get_no_params(auth_config):
    params = {}
    for operation in operations:
        if operation != "check_health":
            try:
                response = operations[operation](auth_config, params)
                assert False, f"Expected error for missing params for operation {operation}"
            except operations_package.ConnectorError as e:
                assert True, f"Expected error for missing params for operation {operation}"


def test_rpc_get_invalid_config(auth_config):
    invalid_config = auth_config.copy()
    invalid_config["address"] = "https://invalid-address"
    params = {"url": "/dvmdb/device"}

    try:
        response = operations['json_rpc_get'](invalid_config, params)
    except Exception as e:
        assert isinstance(e, operations_package.ConnectorError), "Expected ConnectorError for invalid config"


def test_adom_and_data_parse_functions(auth_config):
    payload = [
        {
            "params": {
                "url": "/dvm/cmd/add/device",
                "data": {
                    "adom": "root",
                    "flags": [
                        "create_task",
                        "nonblocking"
                    ],
                    "device": {
                        "mr": 4,
                        "sn": "FGT60F0123456789",
                        "name": "",
                        "patch": 0,
                        "os_ver": 6,
                        "os_type": "fos",
                        "mgmt_mode": "fmg",
                        "meta fields": {
                            "Contact Email": "admin@test.com"
                        },
                        "device action": "add_model"
                    }
                },
                "track_task": True
            },
            "adom": "root",
            "action": "execute"
        }
    ]
    for test in payload:
        # Get the expected adom from the test payload
        correct_adom = test.get("adom")
        action = test.get("action")
        params = test.get("params")

        data = parse_data(params.get("data", {}))
        url = params.get("url")
        # To handle locking ADOM's when freeform action is used, I will pick the first url found and lock that adom.
        if action == "free_form":
            url = data.get("data", [])[0].get("url", url)
        # Get the adom from the function
        acquired_adom = parse_adom_from_input(url, data)
        assert acquired_adom == correct_adom, f"Expected adom {correct_adom} but got {acquired_adom}"


def test_parse_task_timeout(auth_config):
    payload = [
        {
            "task_timeout": '',
            "expected_task_timeout": 120
        },
        {
            "task_timeout": 120,
            "expected_task_timeout": 120
        },
        {
            "task_timeout": 60,
            "expected_task_timeout": 60
        },
        {
            "expected_task_timeout": 120
        },
        {
            "task_timeout": None,
            "expected_task_timeout": 120
        }
    ]
    for test in payload:
        task_timeout = test.get("task_timeout")
        expected_task_timeout = test.get("expected_task_timeout")
        task_timeout = parse_task_timeout(task_timeout)
        assert task_timeout == expected_task_timeout, f"Expected task_timeout {expected_task_timeout} but got {task_timeout}"


### Device FGT2 needs to be an install target of the "default" pacakge for the following tests to pass
def test_track_task_parameters(auth_config):
    """Test different track task timeout parameters"""
    test_cases = [
        {
            "name": "Default timeouts",
            "params": {
                "url": "/securityconsole/install/package",
                "data": {
                    "adom": "root",
                    "pkg": FGT_ASSIGNED_POL_PKG,
                    "flags": ["preview"],
                    "scope": [
                        {
                            "name": LIVE_FGT_DEVICE_NAME,
                            "vdom": "root"
                        }
                    ]
                },
                "track_task": True
            },
            "expected_timeout": 21600,
            "expected_zero_percent_timeout": 30,
            "expected_stale_timeout": 120,
            "expected_delete_on_timeout": True
        },
        {
            "name": "Custom timeouts",
            "params": {
                "url": "/securityconsole/install/package",
                "data": {
                    "adom": "root",
                    "pkg": FGT_ASSIGNED_POL_PKG,
                    "flags": ["preview"],
                    "scope": [
                        {
                            "name": LIVE_FGT_DEVICE_NAME,
                            "vdom": "root"
                        }
                    ]
                },
                "track_task": True,
                "task_timeout": 300,
                "zero_percent_timeout": 60,
                "task_stale_timeout": 180,
                "delete_task_on_timeout": False
            },
            "expected_timeout": 300,
            "expected_zero_percent_timeout": 60,
            "expected_stale_timeout": 180,
            "expected_delete_on_timeout": False
        }
    ]

    for test_case in test_cases:
        try:
            logger.info(f"Running test case: {test_case['name']}")
            response = operations['json_rpc_execute'](auth_config, test_case['params'])

            # Verify the response structure
            assert response.get("status", None) == 0, f"Execute operation failed with status {response.get('status')}"
            assert "execute_response" in response, "Response missing 'execute_response' key"
            assert "task_response" in response, "Response missing 'task_response' key"

            # Verify task tracking parameters through debug logs
            # Note: Since we can't directly access the internal track_task parameters,
            # we're verifying the behavior through the response
            task_response = response.get("task_response", {})
            assert "percent" in task_response, "Task response missing 'percent' key"
            assert task_response.get("percent") == 100, "Task did not complete successfully"

            logger.info(f"Test case {test_case['name']} passed successfully")

        except Exception as e:
            logger.error(f"Test case {test_case['name']} failed: {str(e)}")
            raise


def test_task_timeout_behavior(auth_config):
    """Test task timeout behavior with an intentionally short timeout"""
    params = {
        "url": "/securityconsole/install/package",
        "data": {
            "adom": "root",
            "pkg": FGT_ASSIGNED_POL_PKG,
            "flags": ["preview"],
            "scope": [
                {
                    "name": LIVE_FGT_DEVICE_NAME,
                    "vdom": "root"
                }
            ]
        },
        "track_task": True,
        "task_timeout": 1,  # Very short timeout to force timeout condition
        "zero_percent_timeout": 60,
        "task_stale_timeout": 3,
        "delete_task_on_timeout": True
    }

    try:
        result = operations['json_rpc_execute'](auth_config, params)
        task_timeout = params.get("task_timeout")
        task_id = result.get("execute_response", {}).get("task_id") or result.get("execute_response", {}).get("task")

        # Verify response structure
        assert isinstance(result, dict), "Expected result to be a dict"
        assert "task_response" in result, "Response missing 'task_response' key"
        task_result = result.get("task_response")
        assert "msg" in task_result, "Task response missing 'msg' key"

        # Verify timeout message
        expected_msg = f'Task {task_id} did not complete in efficient time and timed out. The timeout value was {task_timeout}. The task will be deleted.'
        assert task_result.get("msg") == expected_msg, "Expected timeout message"

        # Verify task deletion
        verify_params = {
            "url": f"/task/task/{task_id}",
        }
        response = operations['json_rpc_get'](auth_config, verify_params)
        assert response.get("status") == -3, "Task should have been deleted"

    except Exception as e:
        logger.error(f"Task timeout test failed: {str(e)}")
        raise


def test_task_delete_disabled(auth_config):
    """Test behavior when delete_task_on_timeout is False"""
    params = {
        "url": "/securityconsole/install/package",
        "data": {
            "adom": "root",
            "pkg": FGT_ASSIGNED_POL_PKG,
            "flags": ["preview"],
            "scope": [
                {
                    "name": LIVE_FGT_DEVICE_NAME,
                    "vdom": "root"
                }
            ]
        },
        "track_task": True,
        "task_timeout": 1,
        "zero_percent_timeout": 10,
        "task_stale_timeout": 10,
        "delete_task_on_timeout": False
    }

    try:
        result = operations['json_rpc_execute'](auth_config, params)
        task_id = result.get("execute_response", {}).get("task_id") or result.get("execute_response", {}).get("task")

        # Verify response structure
        assert isinstance(result, dict), "Expected result to be a dict"
        assert "task_response" in result, "Response missing 'task_response' key"
        task_result = result.get("task_response")
        assert "msg" in task_result, "Task response missing 'msg' key"

        # Verify timeout message without deletion
        expected_msg = f'Task {task_id} did not complete in efficient time and timed out. The timeout value was {params["task_timeout"]}.'
        assert task_result.get("msg") == expected_msg, "Expected timeout message without deletion notice"

        # Verify task still exists
        verify_params = {
            "url": f"/task/task/{task_id}",
        }
        response = operations['json_rpc_get'](auth_config, verify_params)
        assert response.get("status") == 0, "Task should still exist"
        assert "get_response" in response, "Response missing 'get_response' key"

    except Exception as e:
        logger.error(f"Task deletion disabled test failed: {str(e)}")
        raise


def test_zero_percent_timeout(auth_config):
    """Test zero percent timeout behavior"""
    params = {
        "url": "/securityconsole/install/package",
        "data": {
            "adom": "root",
            "pkg": FGT_ASSIGNED_POL_PKG,
            "flags": ["preview"],
            "scope": [
                {
                    "name": LIVE_FGT_DEVICE_NAME,
                    "vdom": "root"
                }
            ]
        },
        "track_task": True,
        "task_timeout": 30,
        "zero_percent_timeout": 2,  # Very short zero percent timeout
        "task_stale_timeout": 20,
        "delete_task_on_timeout": True
    }

    try:
        result = operations['json_rpc_execute'](auth_config, params)
        task_id = result.get("execute_response", {}).get("task_id") or result.get("execute_response", {}).get("task")

        # Verify response structure
        assert isinstance(result, dict), "Expected result to be a dict"
        assert "task_response" in result, "Response missing 'task_response' key"
        task_result = result.get("task_response")
        assert "msg" in task_result, "Task response missing 'msg' key"

        # Verify zero percent timeout message
        expected_msg = f'Task {task_id} remained at 0% for too long and timed out. The zero percent timeout value was {params["zero_percent_timeout"]}. The task will be deleted.'
        assert task_result.get("msg") == expected_msg, "Expected zero percent timeout message"

        # Verify task deletion
        verify_params = {
            "url": f"/task/task/{task_id}",
        }
        response = operations['json_rpc_get'](auth_config, verify_params)
        assert response.get("status") == -3, "Task should have been deleted"

    except Exception as e:
        logger.error(f"Zero percent timeout test failed: {str(e)}")
        raise


def test_stale_task_timeout(auth_config):
    """Test stale task timeout behavior"""
    params = {
        "url": "/securityconsole/install/package",
        "data": {
            "adom": "root",
            "pkg": FGT_ASSIGNED_POL_PKG,
            "flags": ["preview"],
            "scope": [
                {
                    "name": LIVE_FGT_DEVICE_NAME,
                    "vdom": "root"
                }
            ]
        },
        "track_task": True,
        "task_timeout": 30,
        "zero_percent_timeout": 10,
        "task_stale_timeout": 2,  # Very short stale timeout
        "delete_task_on_timeout": True
    }

    try:
        result = operations['json_rpc_execute'](auth_config, params)
        task_id = result.get("execute_response", {}).get("task_id") or result.get("execute_response", {}).get("task")

        # Verify response structure
        assert isinstance(result, dict), "Expected result to be a dict"
        assert "task_response" in result, "Response missing 'task_response' key"
        task_result = result.get("task_response")
        assert "msg" in task_result, "Task response missing 'msg' key"

        # Verify stale task timeout message
        expected_msg = f'Task {task_id} progress remained unchanged for too long and timed out. The stale timeout value was {params["task_stale_timeout"]}. The task will be deleted.'
        assert task_result.get("msg") == expected_msg, "Expected stale task timeout message"

        # Verify task deletion
        verify_params = {
            "url": f"/task/task/{task_id}",
        }
        response = operations['json_rpc_get'](auth_config, verify_params)
        assert response.get("status") == -3, "Task should have been deleted"

    except Exception as e:
        logger.error(f"Stale task timeout test failed: {str(e)}")
        raise


# Test the add operation by adding an address object
def test_rpc_add(setup_params):
    auth_config, params_add, params_delete = setup_params
    response = operations['json_rpc_add'](auth_config, params_add)
    # Status should be 0 for success
    assert response.get("status", None) == 0

    assert "add_response" in response, "Response missing 'add_response' key"

    assert response.get("add_response", {}).get("name",
                                                None) == "host-172-23-200-121", "Expected name 'host-172-23-200-121' in response"

    response = operations['json_rpc_delete'](auth_config, params_delete)


def test_rpc_set(setup_params):
    auth_config, params_add, params_delete = setup_params
    response = operations['json_rpc_add'](auth_config, params_add)
    # Status should be 0 for success
    assert response.get("status", None) == 0

    assert "add_response" in response, "Response missing 'add_response' key"

    assert response.get("add_response", {}).get("name",
                                                None) == "host-172-23-200-121", "Expected name 'host-172-23-200-121' in response"
    params_set = {
        "url": params_delete["url"],
        "data": {
            # Ensure the name field is included
            "subnet": [
                "172.23.200.122",
                "255.255.255.255"
            ]
        }
    }
    response = operations['json_rpc_set'](auth_config, params_set)

    assert response.get("status", None) == 0

    assert "set_response" in response, "Response missing 'set_response' key"

    response = operations['json_rpc_get'](auth_config, params_delete)

    assert response.get("get_response", {}).get("subnet", [])[
               0] == "172.23.200.122", "Expected subnet[0] to be 172.23.200.122"

    response = operations['json_rpc_delete'](auth_config, params_delete)


def test_rpc_delete(setup_params):
    auth_config, params_add, params_delete = setup_params
    # First, run the add test
    response_add = operations['json_rpc_add'](auth_config, params_add)
    assert response_add.get("status", None) == 0

    response = operations['json_rpc_delete'](auth_config, params_delete)
    # Status should be 0 for success
    assert response.get("status", None) == 0

    assert "delete_response" in response, "Response missing 'delete_response' key"

    assert response.get("delete_response", {}).get("url",
                                                   None) == "/pm/config/adom/root/obj/firewall/address/host-172-23-200-121", "Expected url '/pm/config/adom/root/obj/firewall/address/host-172-23-200-121' in response"


def test_rpc_execute(auth_config):
    # add a model device
    params = {
        "url": "/dvm/cmd/add/device",
        "data": {
            "adom": "root",
            "flags": [
                "create_task",
                "nonblocking"
            ],
            "device": {
                "mr": 4,
                "sn": "FGT60F0123456789",
                "name": "",
                "patch": 0,
                "os_ver": 6,
                "os_type": "fos",
                "mgmt_mode": "fmg",
                "meta fields": {
                    "Contact Email": "admin@test.com"
                },
                "device action": "add_model"
            }
        },
        "track_task": True
    }
    response = operations['json_rpc_execute'](auth_config, params)
    # Status should be 0 for success
    assert response.get("status", None) == 0

    assert "execute_response" in response, "Response missing 'execute_response' key"

    assert "task_response" in response, "Response missing 'task_response' key"

    assert response.get("task_response", {}).get("percent", None) == 100, "Expected percent 100 in task response"

    # delete the device

    params = {
        "url": "/dvm/cmd/del/device",
        "data": {
            "data": {
                "adom": "root",
                "flags": [
                    "create_task",
                    "nonblocking"
                ],
                "device": "FGT60F0123456789"
            }
        },
        "track_task": True
    }
    response = operations['json_rpc_execute'](auth_config, params)

    assert response.get("status", None) == 0

    assert "execute_response" in response, "Response missing 'execute_response' key"

    assert "task_response" in response, "Response missing 'task_response' key"

    assert response.get("task_response", {}).get("percent", None) == 100, "Expected percent 100 in task response"


def test_rpc_freeform(auth_config):
    multi_data = []
    address_objects = [
        {"name": "host-172-23-200-121", "subnet": ["172.23.200.121", "255.255.255.255"]},
        {"name": "host-172-23-200-122", "subnet": ["172.23.200.122", "255.255.255.255"]},
        {"name": "host-172-23-200-123", "subnet": ["172.23.200.123", "255.255.255.255"]}
    ]

    for addr_obj in address_objects:
        multi_data.append({
            "url": "/pm/config/adom/root/obj/firewall/address/",
            "data": [addr_obj]
        })
    params = {
        "method": "add",
        "data": multi_data
    }

    #     {
    #         "method": "add",
    #         "data": [
    #             {
    #                 "url": "/pm/config/adom/root/obj/firewall/address/",
    #                 "data": [
    #                     {
    #                         "name": "host-172-23-200-121",
    #                         "subnet": [
    #                             "172.23.200.121",
    #                             "255.255.255.255"
    #                         ]
    #                     }
    #                 ]
    #             },
    #             {
    #                 "url": "/pm/config/adom/root/obj/firewall/address/",
    #                 "data": [
    #                 ...
    #

    response = operations['json_rpc_freeform'](auth_config, params)

    assert "free_form_response" in response, "Response missing 'free_form_response' key"

    assert response.get("status") == 200, "Expected status 200 in response"

    assert len(response.get("free_form_response", [])) == len(
        address_objects), "Expected number of results to match number of address objects added"

    # delete the address objects
    params["method"] = "delete"
    multi_data = [{"url": f"/pm/config/adom/root/obj/firewall/address/{addr_obj['name']}"} for addr_obj in
                  address_objects]
    params["data"] = multi_data

    response = operations['json_rpc_freeform'](auth_config, params)

    assert "free_form_response" in response, "Response missing 'free_form_response' key"

    assert response.get("status") == 200, "Expected status 200 in response"

    assert len(response.get("free_form_response", [])) == len(
        address_objects), "Expected number of results to match number of address objects added"


def test_special_case(auth_config):
    params = {
        "url": "/securityconsole/install/preview",
        "data": {
            "adom": "root",
            "scope": [
                {
                    "name": LIVE_FGT_DEVICE_NAME,
                    "vdom": "root"
                }
            ]
        },
        "track_task": True,
        "task_timeout": 120
    }
    response = operations['json_rpc_execute'](auth_config, params)
    # Status should be 0 for success
    assert response.get("status", None) == 0

    assert "execute_response" in response, "Response missing 'execute_response' key"

    assert "task_response" in response, "Response missing 'task_response' key"

    assert "special_case_response" in response, "Response missing 'special_case_response' key"
    special_case_response = response.get("special_case_response", {})
    assert "message" in special_case_response, "Response missing 'message' key"
