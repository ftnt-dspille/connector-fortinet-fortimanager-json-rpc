"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import json
import random
import re
import time
from typing import Union

from connectors.core.connector import get_logger, ConnectorError
from pyFMG.fortimgr import FortiManager

logger = get_logger('fortinet-fortimanager-json-rpc')

# Set the maximum number of retries to acquire a lock on an ADOM
MAX_RETRY_LIMIT = 1500

# URLs that do not require workspace locking. These are exec actions that install
# or push already-committed config to devices -- they read from the ADOM config
# but do not modify it, so locking the workspace is unnecessary and would block
# other concurrent workers.
NO_LOCK_URLS = frozenset({
    "/securityconsole/install/device",
    "/securityconsole/install/package",
    "/securityconsole/install/preview",
})


def get_config(config: dict) -> tuple:
    auth_method = config.get("auth_method")
    server_url = clean_server_url(config.get('address', ''), config.get('port'))
    username = config.get("username", None)
    password = config.get("password", None)
    api_key = config.get("api_key", None)
    verify_ssl = config.get("verify_ssl", True)
    if auth_method == "API Key":
        return server_url, None, None, api_key, verify_ssl
    else:
        return server_url, username, password, None, verify_ssl


def clean_server_url(server_url: str, port: Union[str, None]) -> str:
    server_host = server_url.strip('/').replace("http://", "").replace("https://", "")

    # Append port if specified and not the default port
    if port and port not in ["443", 443]:
        server_host = f"{server_host}:{port}"

    return server_host


def parse_data(data: Union[list, bool, str, dict]):
    if isinstance(data, str):
        try:
            return json.loads(data) if data else {}
        except json.JSONDecodeError as e:
            raise ConnectorError(f"Could not parse JSON: {e}")
    if isinstance(data, list):
        return {"data": data}
    if not isinstance(data, dict):
        raise ConnectorError(f"Unexpected data type: {type(data)}. Please pass a string, list, or dict.")
    return data


def parse_task_timeout(task_timeout, default=120):
    """
    Function to parse task_timeout from params.

    :param task_timeout: task_timeout from params
    :param default: Default timeout value if parsing fails.
    :return: Parsed integer timeout value.
    """
    task_timeout = task_timeout or default
    try:
        task_timeout = int(task_timeout)
    except ValueError:
        task_timeout = default
    return task_timeout


def parse_adom_from_input(url: str, data: Union[list, dict]) -> str:
    match = re.search(r'/adom/([^/]+)/', url)
    if match:
        return match.group(1)

    # If the adom is not found in the URL, check the data
    def extract_adom(nested_data):
        if isinstance(nested_data, dict):
            if 'url' in nested_data:
                nested_match = re.search(r'/adom/([^/]+)/', nested_data['url'])
                if nested_match:
                    return nested_match.group(1)
            if 'adom' in nested_data:
                return nested_data['adom']
            for key, value in nested_data.items():
                result = extract_adom(value)
                if result:
                    return result
        elif isinstance(nested_data, list):
            for item in nested_data:
                result = extract_adom(item)
                if result:
                    return result
        return None

    adom = extract_adom(data)
    return adom if adom else "global"


def parse_track_task_params(params):
    """
    Parse all track task related parameters with their defaults.

    Args:
        params (dict): Parameters from the request

    Returns:
        dict: Dictionary containing all track task parameters with their values
    """
    track_task_params = {
        'timeout': parse_task_timeout(params.get('task_timeout', 21600)),
        'timeout_only': False,  # Always set to False as per requirements
        'zero_percent_timeout': parse_task_timeout(params.get('zero_percent_timeout', 30)),
        'task_stale_timeout': parse_task_timeout(params.get('task_stale_timeout', 120)),
        'delete_task_on_timeout': params.get('delete_task_on_timeout', True)
    }
    return track_task_params


def lock_adom(fmg, adom, url, data):
    for attempt in range(MAX_RETRY_LIMIT):
        status, _ = fmg.lock_adom(adom)
        # If the lock was acquired, break the loop
        if status == 0:
            logger.debug(f"Acquired lock for ADOM: {adom} using URL: {url} with PAYLOAD: {data}.")
            return True
        # status == -9 means that the command for the url is invalid. This happens when an adom is attempted to be
        # locked when workspaces isn't enabled. This is a workaround for a pyFMG bug where uses_workspace is True when
        # it should be False. That happens because pyFMG checks a 0 or 1 int, but verbose mode returns a string.
        if status == -9:
            logger.debug(f"Workspaces not enabled. Locking ADOM: {adom} not required.")
            return True
        # status == -6 when URL is invalid. This could occur when a nonexistent adom is attempted to be locked.
        if status == -6:
            logger.error(f"URL is invalid. ADOM: {adom} does not exist.")
            return False
        if attempt < MAX_RETRY_LIMIT - 1:
            # Sleep for a random amount of time between 1 and 10 seconds
            sleep_time = random.randint(1, 10)
            logger.debug(
                f"Failed to acquire lock for ADOM: {adom} using URL: {url} with PAYLOAD: {data}. Sleeping {sleep_time} seconds and retrying...")
            time.sleep(sleep_time)
        else:
            logger.error(
                f"Max retry limit reached. Could not acquire lock for ADOM: {adom} using URL: {url} with PAYLOAD: {data}.")
            return False
    return False


def parse_minimal_lock_scope(url: str, known_packages=None) -> tuple:
    """
    Determine the minimal workspace lock scope from a URL.

    Checks for policy package scope first (more specific), then device scope.
    Returns (scope_type, scope_id) where scope_type is 'pkg' or 'dev',
    or (None, None) to signal fallback to ADOM-level locking.

    known_packages is the ADOM's list of full package paths (see list_adom_packages).
    It is what makes packages nested in folders resolve correctly; without it a
    nested package degrades to its folder name, which FMG rejects with -6.

    For free_form actions the scope is resolved by parse_free_form_lock_scope,
    which requires every request in the batch to share one scope.
    """
    # Package scope: /pm/config/adom/{adom}/pkg/{pkg}/...
    # A package may live inside one or more package folders, in which case its
    # addressable name is the whole folder path ("folder1/package1"). The folder
    # alone is not a valid object, so guessing the first segment yields a lock URL
    # FMG rejects with -6. When the caller supplies the ADOM's real package list we
    # take the longest package path that prefixes the URL; otherwise we fall back to
    # the single-segment guess, which is correct for packages not in a folder.
    pkg_match = re.search(r'/pm/config/adom/[^/]+/pkg/(.+)', url)
    if pkg_match:
        remainder = pkg_match.group(1)
        if known_packages:
            matches = [
                package for package in known_packages
                if remainder == package or remainder.startswith(package + "/")
            ]
            if matches:
                return "pkg", max(matches, key=len)
        return "pkg", remainder.split("/")[0]

    # Device scope: only the known device-database roots count. The segment is
    # anchored to the start of the URL so an unrelated path that merely contains
    # a "/dev/" or "/device/" segment (e.g. /cli/global/system/admin/user/device/x)
    # is not mistaken for a device scope, which would lock the wrong object.
    dev_match = re.match(
        r'^/(?:dvmdb(?:/adom/[^/]+)?|pm/config)/(?:dev|device)/([^/]+)', url
    )
    if dev_match:
        return "dev", dev_match.group(1)

    return None, None


def list_adom_packages(fmg, adom: str) -> list:
    """
    Return every policy package in an ADOM as a full addressable path.

    Packages can be nested in package folders, and only the full path
    ("folder1/package1") is addressable -- the folder on its own is not an object.
    The package tree is returned by /pm/pkg/adom/{adom}, with folders carrying
    their children under "subobj". Returns [] if the lookup fails, which makes the
    caller fall back to parsing the package name straight out of the URL.
    """
    try:
        status, packages = fmg.get(url=f"/pm/pkg/adom/{adom}")
    except Exception as lookup_error:
        logger.debug(f"Could not list packages for ADOM {adom}: {lookup_error}")
        return []
    if status != 0 or not isinstance(packages, list):
        logger.debug(f"Could not list packages for ADOM {adom}: status {status}")
        return []

    paths = []

    def walk(entries, prefix):
        for entry in entries or []:
            if not isinstance(entry, dict) or not entry.get("name"):
                continue
            path = f"{prefix}{entry['name']}"
            if entry.get("type") == "folder":
                walk(entry.get("subobj"), f"{path}/")
            else:
                paths.append(path)

    walk(packages, "")
    return paths


def parse_free_form_lock_scope(data: dict, known_packages=None) -> tuple:
    """
    Determine the minimal lock scope covering every request in a free_form batch.

    A free_form payload may carry several URLs. A lock only grants write access to
    the object it names, so locking the first URL's scope while the batch also
    writes elsewhere makes FMG reject the other writes. Only return a minimal
    scope when every request in the batch resolves to the same one; otherwise
    return (None, None) so the caller falls back to ADOM-level locking.
    """
    requests = data.get("data")
    if not isinstance(requests, list) or not requests:
        return None, None

    scopes = set()
    for request in requests:
        request_url = request.get("url") if isinstance(request, dict) else None
        if not request_url:
            return None, None
        scopes.add(parse_minimal_lock_scope(request_url, known_packages))

    if len(scopes) == 1:
        return scopes.pop()
    return None, None


def lock_minimal_scope(fmg, adom: str, scope_type: str, scope_id: str, url: str, data) -> bool:
    """
    Acquire a workspace lock at package or device scope with the same retry
    logic as lock_adom.
    """
    lock_url = f"/dvmdb/adom/{adom}/workspace/lock/{scope_type}/{scope_id}"
    for attempt in range(MAX_RETRY_LIMIT):
        status, _ = fmg.execute(url=lock_url)
        if status == 0:
            logger.debug(f"Acquired minimal lock for {scope_type}/{scope_id} in ADOM: {adom} (URL: {url}).")
            return True
        # -9 means the workspace command is invalid, i.e. workspace mode is not
        # enabled on this ADOM -- no lock required.
        if status == -9:
            logger.debug(f"Workspaces not enabled. Locking {scope_type}/{scope_id} not required.")
            return True
        # -6 means the URL is invalid -- the ADOM, package, or device does not exist.
        if status == -6:
            logger.error(f"URL is invalid. {scope_type}/{scope_id} in ADOM: {adom} does not exist.")
            return False
        if attempt < MAX_RETRY_LIMIT - 1:
            sleep_time = random.randint(1, 10)
            logger.debug(
                f"Failed to acquire minimal lock for {scope_type}/{scope_id} in ADOM: {adom}. "
                f"Sleeping {sleep_time}s and retrying..."
            )
            time.sleep(sleep_time)
        else:
            logger.error(
                f"Max retry limit reached. Could not acquire minimal lock for "
                f"{scope_type}/{scope_id} in ADOM: {adom} (URL: {url})."
            )
            return False
    return False


def commit_minimal_scope(fmg, adom: str, scope_type: str, scope_id: str) -> None:
    """Commit workspace changes at package or device scope."""
    commit_url = f"/dvmdb/adom/{adom}/workspace/commit/{scope_type}/{scope_id}"
    fmg.execute(url=commit_url)


def unlock_minimal_scope(fmg, adom: str, scope_type: str, scope_id: str) -> None:
    """Release a workspace lock at package or device scope."""
    unlock_url = f"/dvmdb/adom/{adom}/workspace/unlock/{scope_type}/{scope_id}"
    fmg.execute(url=unlock_url)


def handle_special_cases(fmg, url, data, action_response, task_response=None):
    special_cases = {
        "/securityconsole/install/preview": {
            "extra_url": "/securityconsole/preview/result",
            "action": "execute"
        },
        # Add more special cases here as needed
    }

    if url in special_cases:
        case = special_cases[url]
        action_func = getattr(fmg, case["action"])
        status, extra_response = action_func(url=case["extra_url"], **data)
        return extra_response
    return None


def perform_rpc_action(action: str, config: dict, params: dict) -> dict:
    server_host, username, password, api_key, verify_ssl = get_config(config)
    try:
        with FortiManager(server_host, username, password, apikey=api_key, verify_ssl=verify_ssl,
                          debug=config.get("debug_connection", False),
                          verbose=config.get("verbose_json", True), disable_request_warnings=True) as fmg:
            action_func = getattr(fmg, action)
            data = parse_data(params.get("data", {}))
            url = params.get("url")
            # To handle locking ADOM's when freeform action is used, I will pick the first url found and lock that adom.
            if action == "free_form":
                # make sure data is a list before accessing the first instance
                if not isinstance(data.get("data", None), list):
                    raise ConnectorError("Payload must be a list")
                url = data["data"][0].get("url", url)
            adom = parse_adom_from_input(url, data)
            response = {}

            # Determine whether a workspace lock is needed for this request.
            # Read-only (get) actions and URLs in NO_LOCK_URLS never require a lock.
            needs_lock = (
                action not in ["get"]
                and fmg._lock_ctx.uses_workspace
                and url not in NO_LOCK_URLS
            )

            # Resolve the lock scope. With minimal_locking enabled the connector
            # attempts to lock only the policy package or device referenced in the
            # URL instead of the entire ADOM, reducing contention in environments
            # with concurrent automation workers. Falls back to ADOM-level locking
            # when no finer scope can be parsed, or when the ADOM is "global".
            scope_type, scope_id = None, None
            if needs_lock and config.get("minimal_locking", False) and adom != "global":
                # Ask the appliance for the ADOM's package paths so packages nested in
                # folders resolve to the path FMG actually accepts in a lock URL.
                known_packages = list_adom_packages(fmg, adom) if "/pkg/" in (url or "") else []
                if action == "free_form":
                    scope_type, scope_id = parse_free_form_lock_scope(data, known_packages)
                else:
                    scope_type, scope_id = parse_minimal_lock_scope(url, known_packages)

            if needs_lock:
                if scope_type is not None:
                    if not lock_minimal_scope(fmg, adom, scope_type, scope_id, url, data):
                        raise ConnectorError(
                            f"Failed to acquire minimal lock for {scope_type}/{scope_id} in ADOM: {adom}"
                        )
                else:
                    if not lock_adom(fmg, adom, url, data):
                        raise ConnectorError(f"Failed to lock ADOM: {adom}")

            # Minimal-scope locks are taken with execute(), so pyFMG's __exit__ does
            # not know about them and will not release them the way it releases ADOMs
            # registered through lock_adom(). Without a finally the lock survives any
            # mid-flight failure and blocks every other worker on that package or
            # device, so the release is guaranteed here instead.
            minimal_lock_held = needs_lock and scope_type is not None
            try:
                if action == "free_form":
                    method = params.get("method")
                    status, action_response = action_func(method, **data)
                else:
                    status, action_response = action_func(url=url, **data)

                if needs_lock and scope_type is None:
                    fmg.commit_changes(adom)
                    # Consider unlocking the adom here, but not sure if it's safe to do so if there is a task to track
                    # Not unlocking here could potentially cause delays in other workers that need to lock the same adom
                elif minimal_lock_held:
                    commit_minimal_scope(fmg, adom, scope_type, scope_id)

                response[f"{action}_response"] = action_response
                # If the action is execute and track_task is set to True, track the task
                # Also need to make sure that the response is a dict because some exec actions like sys/proxy/info can return a list
                if action == 'execute' and params.get("track_task", False) and isinstance(action_response, dict):
                    task = action_response.get('task') or action_response.get('taskid')
                    # handle case where no task id is found and there is an attempt to track task
                    if not task:
                        response["task_response"] = None
                        # Surface the FMG status message (e.g. "No devices") when present,
                        # so callers know *why* no task was created instead of a generic
                        # "no task id" message.
                        fmg_status = action_response.get('status')
                        if fmg_status and fmg_status not in ('Success', 'OK', 0, '0'):
                            response["error"] = "FMG returned status '{status}' with no task id (track_task=True).".format(status=fmg_status)
                        else:
                            response["error"] = "No task id found in execute_response and track_task is set to True."
                    else:
                        track_task_params = parse_track_task_params(params)
                        status, task_response = fmg.track_task(task, **track_task_params)
                        response["task_response"] = task_response

                        # Handle special cases. Putting this here because the task needs to be tracked first for exec actions
                        special_case_result = handle_special_cases(fmg, url, data, action_response, task_response)
                        if special_case_result:
                            response["special_case_response"] = special_case_result

                    # I'm not sure if we need to commit changes here after the task is tracked, but leaving it here for now
                    # The minimal-scope path already committed above and commits again on
                    # release, so only the ADOM path needs the extra commit/unlock here.
                    if needs_lock and scope_type is None:
                        fmg.commit_changes(adom)
                        fmg.unlock_adom(adom)
            finally:
                if minimal_lock_held:
                    # Releasing as early as possible keeps other workers moving. Errors are
                    # logged rather than raised so a failed unlock cannot mask the real
                    # exception that sent us into this finally block.
                    try:
                        unlock_minimal_scope(fmg, adom, scope_type, scope_id)
                    except Exception as unlock_error:
                        logger.error(
                            f"Failed to release minimal lock for {scope_type}/{scope_id} "
                            f"in ADOM: {adom}: {unlock_error}"
                        )

            response["status"] = status
            logger.debug(response)
            return response
    except Exception as e:
        raise ConnectorError(e)
