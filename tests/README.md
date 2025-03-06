## Testing the JSON RPC Connector

### Setting Up FMG

#### Create Administrator accounts for API testing

1. Log in to the FortiManager GUI.
2. Navigate to **System Setting > Administrators**.
3. Create a new administrator with the following settings:
    - **Name**: `pytest`
    - **Password**: `your_own_password`
    - **Permission Profile**: `Super_User`
    - **JSON API Access**: `Read-Write`
4. Create a new REST API Admin with the following settings:
    - **Name**: `pytest_api`
    - **Permission Profile**: `Super_User`
    - **Trust Host**: `your_ip_address`
5. Generate a new API key for the REST API Admin and save it for later use.

#### Set up live device

1. Add a FortiGate device to the FortiManager.
2. Assign a policy package to the device.

### Running the tests

1. cd into the `tests` directory.
    ```bash
    cd fortimanager-json-rpc/tests
    ```
2. Rename the `.env.example` file
    ```bash
    mv .env.example .env
    ```
3. Update the .env file with the required values to point to a FortiManager instance.
    - You must have a valid Hostname, Username, Password, and Port.
        - Set the HOSTNAME, USERNAME, PASSWORD, and PORT variables in the `.env` file based on your super admin user
    - You must have a REST API user created on the FMG, and provide the key to the `API_KEY` variable.
        - The REST API user must have read-write JSON API permissions.
        - Make sure the IP of the machine running the tests is added on the FMG as a trusted host
    - Set the `LIVE_FGT_DEVICE_NAME` variable to the name of the FortiGate device you added to the FMG.
    - Set the `FGT_ASSIGNED_POL_PKG` variable to the name of the policy package assigned to the FortiGate device.
4. Create a virtual environment.
    ```bash
    python -m venv .venv
    ```

5. Install the required packages.
    ```bash
    pip install -r requirements.txt
    ```
6. Run the following command to execute the tests.
   ```bash
   python run_tests.py
   ```
    - Each dot represents a test that passed.
    - **The tests are split into two sections, sequential and concurrent.**
    - **The tests are ran twice, once with the FMG in workspace mode enabled and once with workspace mode disabled.**
    - Every test is run once using user/password, and once using API key.
    - Note that the exact number of tests may vary depending on updates to the test suite.

- Sample output
   ```bash
    (.venv) dylanspille@dylanspille-mac tests % python run_tests.py
    Current workspace mode: 1
    ============================================================================= test session starts ==============================================================================
    platform darwin -- Python 3.12.3, pytest-8.2.1, pluggy-1.5.0
    rootdir: /Users/dylanspille/PycharmProjects/Github_FSR_Connectors/fortimanager-json-rpc/tests
    plugins: cov-5.0.0, xdist-3.6.1
    collected 13 items                                                                                                                                                             
    
    sequential/test_sequential_fortimanager_rpc.py .............                                                                                                             [100%]
    
    ============================================================================= 13 passed in 47.34s ==============================================================================
    ============================================================================= test session starts ==============================================================================
    platform darwin -- Python 3.12.3, pytest-8.2.1, pluggy-1.5.0 -- /Users/dylanspille/PycharmProjects/Github_FSR_Connectors/fortimanager-json-rpc/.venv/bin/python
    cachedir: .pytest_cache
    rootdir: /Users/dylanspille/PycharmProjects/Github_FSR_Connectors/fortimanager-json-rpc/tests
    plugins: cov-5.0.0, xdist-3.6.1
    4 workers [4 items]     
    scheduling tests via LoadScheduling
    
    concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent3] 
    concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent0] 
    concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent1] 
    concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent2] 
    [gw1] [ 25%] PASSED concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent1] 
    [gw2] [ 50%] PASSED concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent2] 
    [gw3] [ 75%] PASSED concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent3] 
    [gw0] [100%] PASSED concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent0] 
    
    ============================================================================== 4 passed in 18.74s ==============================================================================
    All tests passed
    Setting workspace mode to 0
    ============================================================================= test session starts ==============================================================================
    platform darwin -- Python 3.12.3, pytest-8.2.1, pluggy-1.5.0
    rootdir: /Users/dylanspille/PycharmProjects/Github_FSR_Connectors/fortimanager-json-rpc/tests
    plugins: cov-5.0.0, xdist-3.6.1
    collected 13 items                                                                                                                                                             
    
    sequential/test_sequential_fortimanager_rpc.py .............                                                                                                             [100%]
    
    ============================================================================= 13 passed in 31.37s ==============================================================================
    ============================================================================= test session starts ==============================================================================
    platform darwin -- Python 3.12.3, pytest-8.2.1, pluggy-1.5.0 -- /Users/dylanspille/PycharmProjects/Github_FSR_Connectors/fortimanager-json-rpc/.venv/bin/python
    cachedir: .pytest_cache
    rootdir: /Users/dylanspille/PycharmProjects/Github_FSR_Connectors/fortimanager-json-rpc/tests
    plugins: cov-5.0.0, xdist-3.6.1
    4 workers [4 items]     
    scheduling tests via LoadScheduling
    
    concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent3] 
    concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent0] 
    concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent1] 
    concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent2] 
    [gw2] [ 25%] PASSED concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent2] 
    [gw1] [ 50%] PASSED concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent1] 
    [gw3] [ 75%] PASSED concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent3] 
    [gw0] [100%] PASSED concurrent/test_concurrent_fortimanager_rpc.py::test_rpc_add_concurrent[setup_params_concurrent0] 
    
    ============================================================================== 4 passed in 3.76s ===============================================================================
    All tests passed
    Setting workspace mode to 1
   ```
