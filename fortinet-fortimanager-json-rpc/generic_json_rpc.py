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

# URLs that do not require workspace locking, so taking one would only block other
# concurrent workers for nothing. Membership here is measured, not assumed: each URL
# was run against a live appliance in workspace mode both with and without a lock, and
# the queued task was followed to completion. See tests/live/lock_matrix_probe.py.
#
# These calls return status 0 and a task id whether or not the lock was needed; only
# the finished task reports the failure. This list therefore cannot be verified by
# reading RPC status codes alone.
#
# /securityconsole/install/package is deliberately NOT here. Installing a package
# without the workspace lock produces a task that fails with "no write permission"
# while the RPC still reports success, so it must take a lock like any other write.
#
# /securityconsole/install/device is deliberately NOT here either. It used to be, on
# the strength of a measurement taken with nothing pending: with no staged device-DB
# change both arms trivially "succeed". Re-measured 2/2 with a real pending change,
# the unlocked arm copies and then fails the save ("Copy to device done",
# "install and save finished status=FAILED") while a dev/<device> lock held across the
# task finishes "install and save finished status=OK". A device lock is sufficient, so
# under minimal locking this costs no ADOM serialisation.
NO_LOCK_URLS = frozenset({
    # Generates a preview only; verified identical locked and unlocked.
    "/securityconsole/install/preview",
    # Proxies a REST call straight to the managed device and never touches an FMG
    # database, so no workspace lock applies. Without this entry the connector cannot
    # parse an ADOM from the URL or payload and falls back to locking the *global*
    # ADOM, serialising every worker behind an operation that needs no lock at all.
    "/sys/proxy/json",
    # Firmware upgrade. Two-arm verified end to end on a live 7.6.7 appliance against a
    # licensed FortiGate: unlocked, 7.6.7-b3704 -> 7.6.6-b3652 finished "Upgrade done
    # successfully"; with dev/<device> held across the whole upgrade, 7.6.6 -> 7.6.7 did
    # the same. The lock is neither required nor harmful, so taking one is pure overhead.
    # It matters because callers pass an ADOM here: without this entry an upgrade with a
    # real adom takes that ADOM's lock and, when track_task is set, holds it for the
    # entire upgrade -- serialising every other worker in the ADOM for minutes.
    "/um/image/upgrade/ext",
    # Read-only firmware queries. These take an `adom` in the payload, which is enough
    # for parse_adom_from_input to resolve a lockable ADOM, so before this entry the
    # connector locked that ADOM to run a *read*. Measured three-arm on a live 7.6.7
    # appliance for both URLs:
    #
    #   no adom in payload            -> proceeds unlocked, status 0
    #   adom in payload, ADOM free    -> takes an ADOM lock it does not need
    #   adom in payload, ADOM held    -> BLOCKED, cannot acquire the lock
    #
    # The third arm is the damaging one: called directly while another session held the
    # ADOM lock, both URLs still returned status 0 with full results, so the lock is not
    # merely unnecessary, it is the only reason the read can fail. In a change window
    # that turns a firmware image list into a call that retries for up to
    # MAX_RETRY_LIMIT * 10s behind an unrelated writer.
    "/um/image/list/ext",
    "/um/image/version/list",
    # The rest of the read-only `/um/` surface, found by sweeping for further instances
    # of the same class (tests/live/readonly_exec_sweep_probe.py). Each was called
    # unlocked while a second session held the ADOM lock and still returned its full
    # payload -- an image list, a device inventory, a version matrix, an upgrade status
    # -- so none of them needs the lock the connector used to take.
    "/um/image/list",
    "/um/image/version/list/ext",
    "/um/device/list",
    "/um/image/upgrade/status",
})


# Install flag that asks FortiManager to take and release the workspace lock itself.
# Callers that already send it (the shipped ZTP flow does, on every install/package)
# must not also be locked by the connector: measured on a live 7.6.7 appliance, an
# auto_lock_ws install fired while this session holds a *package* lock produces a task
# that fails with "failed to lock adom", because FMG's own auto-lock is ADOM-wide and a
# held pkg lock blocks the ADOM lock outright. Unlocked, the same install completes
# ("Installation to real device done"). See tests/live/auto_lock_ws_probe.py.
#
# The server-side lock lives on the *session*, and the install happens in a queued task
# after the exec returns, so callers must also set track_task=True: otherwise the
# connector logs out before FMG installs anything and the task fails with
# "no write permission". The same timing applies to the connector's own locks.
AUTO_LOCK_FLAG = "auto_lock_ws"


# URLs whose lock must still be held while the *queued task* runs, not just until the
# RPC returns. Measured three-arm on a live 7.6.7 appliance, each arm preceded by a
# freshly staged pending change (lock held across the task / lock released at RPC
# return / no lock at all):
#
#   install/package    ok / fail "Copy to device done" num_err=1 / fail
#   install/device     ok / fail "Copy to device done" num_err=1 / fail
#   reinstall/package  ok / fail num_err=1             / rejected at the RPC, status -1
#
# Script execution does NOT belong here: the lock authorises the run, but releasing it
# at RPC return does not break the queued script.
#
# For these URLs the connector follows the task before releasing the lock even when the
# caller did not ask for task tracking -- without it the connector commits, unlocks and
# logs out while FMG is still copying, and the install fails inside a task the caller
# never sees while the RPC reports success. The cost is hold time: an install's lock is
# now held for the task duration (seconds to a couple of minutes), and only for callers
# whose installs were silently failing before.
HOLD_LOCK_UNTIL_TASK_URLS = frozenset({
    "/securityconsole/install/package",
    "/securityconsole/install/device",
    "/securityconsole/reinstall/package",
})


def holds_lock_until_task(url: str) -> bool:
    return url in HOLD_LOCK_UNTIL_TASK_URLS


# URL families that can only be locked at ADOM level, so minimal-scope resolution must
# not be attempted for them however device-shaped their payload looks.
#
# Measured for /dvm/cmd/add/device, /dvm/cmd/add/dev-list and /dvm/cmd/del/device on a
# live 7.6.7 appliance, three arms each: unlocked all fail -11, the ADOM lock succeeds,
# and the device scope is unavailable in both directions -- for a device that does not
# exist yet the lock URL itself is rejected -10, and for a device that does exist the
# lock is granted 0 and the delete is still refused -11. Device onboarding therefore
# serialises per ADOM by the appliance's design, not by a connector shortcoming.
ADOM_ONLY_URL_PREFIXES = ("/dvm/cmd/",)


def requires_adom_lock(url: str) -> bool:
    return any((url or "").startswith(prefix) for prefix in ADOM_ONLY_URL_PREFIXES)


def requests_server_side_lock(data) -> bool:
    """True when the payload asks FMG to handle workspace locking itself."""

    def has_flag(node) -> bool:
        if isinstance(node, dict):
            flags = node.get("flags")
            if isinstance(flags, str) and flags == AUTO_LOCK_FLAG:
                return True
            if isinstance(flags, (list, tuple)) and AUTO_LOCK_FLAG in flags:
                return True
            return any(has_flag(value) for value in node.values())
        if isinstance(node, list):
            return any(has_flag(item) for item in node)
        return False

    return has_flag(data)


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
    # An unresolved ADOM is returned as "" -- it used to be reported as "global", which
    # is not the same thing and was load-bearing in the wrong direction: "global" cannot
    # be locked on 7.6.7 (/dvmdb/global/workspace/lock -> -9, the documented
    # /dvmdb/adom/global/... -> -6), and lock_adom() read that -9 as "this appliance has
    # no workspace mode" and returned success. Locking was therefore silently skipped for
    # any payload with no ADOM, on any URL. See adom_is_lockable().
    return adom if adom else ""


def adom_is_lockable(adom: str) -> bool:
    """
    Whether a workspace lock can be taken for this ADOM at all.

    "global" cannot: neither documented global lock URL is accepted on 7.6.7. An empty
    ADOM names nothing to lock. Both proceed unlocked -- global object writes do work
    unlocked on this appliance and must keep working -- but they say so in the log
    instead of arriving there through a misread -9.

    The empty case is the dangerous one and this guard is what stops it. pyFMG's
    lock_adom(adom) falls back to **root** for a falsy adom (verified: lock_adom("")
    issues /dvmdb/adom/root/workspace/lock and returns 0). Without this check, a payload
    with no ADOM would lock the root ADOM and then commit it -- publishing whatever
    another worker had staged there.
    """
    return bool(adom) and adom != "global"


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


# Lock statuses that will never succeed on a retry: the URL names something that does not
# exist. Everything else (notably -20055 / -20078 / -20079, the contention codes) is worth
# waiting on. Without this split a mistyped device or package name costs a worker the full
# MAX_RETRY_LIMIT budget -- ~2.3 hours -- instead of failing immediately.
PERMANENT_LOCK_FAILURES = frozenset({-6, -10})


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
            # -9 means the lock URL itself is not a valid command. Two different causes,
            # which this branch used to conflate:
            #  * a real ADOM on an appliance where workspace mode is off, in which case
            #    there is no lock to take and the call should continue. Note the reason
            #    once given for this branch -- "pyFMG mis-detects workspace mode because
            #    it compares an int while verbose mode returns a string" -- does not hold
            #    in pyFMG 0.8.6.3: FMGLockContext.check_mode() accepts both forms
            #    (`not in [0, "disabled"]`), and it was verified against a live appliance
            #    to report uses_workspace correctly with verbose on and off. The branch
            #    stays as defence in depth for other appliances and pyFMG versions, not
            #    because of that bug.
            #  * an ADOM that is simply not lockable ("global", or none at all). Those
            #    are filtered out before we get here by adom_is_lockable(); reaching
            #    this line with one means the caller bypassed that check, so fail rather
            #    than report a lock that was never taken.
            if not adom_is_lockable(adom):
                logger.error(
                    f"ADOM: {adom!r} cannot be locked and no lock was taken for URL: {url}.")
                return False
            logger.debug(f"Workspaces not enabled. Locking ADOM: {adom} not required.")
            return True
        # status == -6 when URL is invalid. This could occur when a nonexistent adom is
        # attempted to be locked. -10 is the same class of permanent rejection; see
        # PERMANENT_LOCK_FAILURES.
        if status in PERMANENT_LOCK_FAILURES:
            logger.error(f"Lock URL rejected with status {status}. ADOM: {adom} does not exist.")
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


def resolve_package_path(package: str, known_packages=None) -> Union[str, None]:
    """
    Expand a bare package name to the full path FMG addresses it by.

    A package inside a folder is only addressable as "folder1/package1", but a payload
    may name it either way. Returns None when the name is ambiguous (the same leaf in
    two folders), so the caller can fall back to ADOM-level locking rather than lock
    the wrong package.
    """
    if not known_packages or package in known_packages:
        return package
    matches = [path for path in known_packages if path.endswith("/" + package)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        logger.debug(f"Package name {package} is ambiguous: {matches}. Falling back to ADOM lock.")
        return None
    return package


def parse_payload_lock_scope(data: dict, known_packages=None) -> tuple:
    """
    Determine the minimal lock scope from a request payload.

    Several operations carry no scope in the URL but name one in the body: script
    execution passes the target device in "scope" or the target policy package in
    "package", and a package install passes both "pkg" and the device "scope". Without
    this the connector locks the whole ADOM for every one of them, which is the bulk of
    real automation traffic.

    Package wins over device when both are present. Verified on a live appliance:
    installing a package while holding only the device lock fails with
    "no write permission", while the package lock alone succeeds.

    Returns (None, None) when the payload names several devices, since one lock cannot
    cover them and ADOM-level locking is the safe answer.

    /securityconsole/reinstall/package carries its packages differently again, in a
    target[] list of {pkg, scope} pairs, which is what lets one call install several
    packages to several devices. single_target_package() handles that shape.
    """
    if not isinstance(data, dict):
        return None, None

    package = data.get("package") or data.get("pkg") or single_target_package(data)
    if isinstance(package, str) and package:
        resolved = resolve_package_path(package, known_packages)
        if resolved:
            return "pkg", resolved
        return None, None

    scope = data.get("scope")
    if isinstance(scope, list) and len(scope) == 1 and isinstance(scope[0], dict):
        device = scope[0].get("name")
        if isinstance(device, str) and device:
            return "dev", device

    return None, None



def single_target_package(data: dict):
    """
    Return the one package named by a reinstall-style target[] payload, else None.

    /securityconsole/reinstall/package takes target: [{"pkg": ..., "scope": [...]}],
    so the package never appears under "pkg" at the top level and the connector locked
    the whole ADOM for every reinstall. Measured on a live 7.6.7 appliance:

      one target, package lock          -> accepted, task completes (group scope too)
      two targets, lock on one package  -> rejected outright, status -1
      any target, no lock               -> rejected outright, status -1

    So a package lock is correct for a single-package reinstall and wrong the moment a
    second package joins the call; several packages fall back to the ADOM lock, which is
    the same rule the multi-device case already follows.
    """
    targets = data.get("target")
    if not isinstance(targets, list) or not targets:
        return None
    packages = {entry.get("pkg") for entry in targets
                if isinstance(entry, dict) and isinstance(entry.get("pkg"), str)}
    if len(packages) != 1 or len(targets) != 1:
        return None
    package = packages.pop()
    return package or None

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
        # -10 is the same class of answer for a scope lock: FMG rejects the lock URL for
        # a device or package that is not there ("The data is invalid for selected url").
        # Measured while probing device onboarding: locking dev/<name> before the device
        # is registered returns -10, and the identical URL returns 0 once it exists.
        # Both are permanent, so retrying is 1500 attempts of 1-10s -- about 2.3 hours of
        # a worker doing nothing over a name that will never resolve.
        if status in PERMANENT_LOCK_FAILURES:
            logger.error(
                f"Lock URL rejected with status {status}. {scope_type}/{scope_id} in "
                f"ADOM: {adom} does not exist; not retrying.")
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


def _held_for(started_at) -> str:
    """Human-readable hold time for a lock acquired at `started_at` (time.monotonic())."""
    if started_at is None:
        return "not held"
    return f"{time.monotonic() - started_at:.2f}s"


def commit_minimal_scope(fmg, adom: str, scope_type: str, scope_id: str) -> None:
    """Commit workspace changes at package or device scope."""
    commit_url = f"/dvmdb/adom/{adom}/workspace/commit/{scope_type}/{scope_id}"
    status, _ = fmg.execute(url=commit_url)
    if status != 0:
        logger.warning(
            f"Commit returned status {status} for {scope_type}/{scope_id} in ADOM: {adom}. "
            "The write may not have been persisted.")


def unlock_minimal_scope(fmg, adom: str, scope_type: str, scope_id: str) -> None:
    """Release a workspace lock at package or device scope."""
    unlock_url = f"/dvmdb/adom/{adom}/workspace/unlock/{scope_type}/{scope_id}"
    status, _ = fmg.execute(url=unlock_url)
    # A non-zero status here used to be discarded. An unlock that silently fails leaves
    # the scope locked for every other worker until the session ends, which is exactly
    # the failure that is hardest to diagnose after the fact -- so say so loudly.
    if status != 0:
        logger.error(
            f"Failed to release {scope_type}/{scope_id} lock in ADOM: {adom} (status {status}). "
            "The lock stays held until this session ends.")
    else:
        logger.debug(f"Released {scope_type}/{scope_id} lock in ADOM: {adom}.")


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
                and not requests_server_side_lock(data)
            )

            # Name the reason. "Did this call lock, and if not why not?" is the first
            # question asked when a workspace goes wrong, and until this line the
            # no-lock path was entirely silent in the log.
            if not needs_lock:
                if action == "get":
                    skip_reason = "read-only get action"
                elif not fmg._lock_ctx.uses_workspace:
                    skip_reason = "workspace mode is not enabled on this appliance"
                elif url in NO_LOCK_URLS:
                    skip_reason = "URL is exempt (read-only or locks server-side)"
                else:
                    skip_reason = "payload asked FMG to lock server-side (auto_lock_ws)"
                logger.debug(f"No workspace lock taken for URL: {url} -- {skip_reason}.")

            # An ADOM that cannot be locked is not the same as an operation that needs
            # no lock. Say so once, here, and proceed unlocked -- global-ADOM writes are
            # accepted unlocked on 7.6.7, and there is no lock URL to take for them.
            if needs_lock and not adom_is_lockable(adom):
                logger.warning(
                    f"No lockable ADOM resolved (adom={adom!r}) for URL: {url}. "
                    "Proceeding without a workspace lock; pass an explicit adom if this "
                    "request writes to a lockable ADOM.")
                needs_lock = False

            # Resolve the lock scope. With minimal_locking enabled the connector
            # attempts to lock only the policy package or device referenced in the
            # URL instead of the entire ADOM, reducing contention in environments
            # with concurrent automation workers. Falls back to ADOM-level locking
            # when no finer scope can be parsed, or when the ADOM is "global".
            scope_type, scope_id = None, None
            if needs_lock and config.get("minimal_locking", False) and not requires_adom_lock(url):
                # Ask the appliance for the ADOM's package paths so packages nested in
                # folders resolve to the path FMG actually accepts in a lock URL. Only
                # worth the extra call when a package could actually be involved.
                names_package = "/pkg/" in (url or "") or bool(
                    isinstance(data, dict) and (data.get("package") or data.get("pkg")
                                                or single_target_package(data)))
                known_packages = list_adom_packages(fmg, adom) if names_package else []

                if action == "free_form":
                    scope_type, scope_id = parse_free_form_lock_scope(data, known_packages)
                else:
                    scope_type, scope_id = parse_minimal_lock_scope(url, known_packages)
                    if scope_type is None:
                        # Nothing in the URL, but the body may still name the single
                        # package or device the request touches.
                        scope_type, scope_id = parse_payload_lock_scope(data, known_packages)

            lock_acquired_at = None
            adom_released_here = False
            if needs_lock:
                if config.get("minimal_locking", False) and scope_type is None:
                    # Minimal locking was asked for but nothing finer than the ADOM could
                    # be resolved. That is the difference between a worker running beside
                    # its peers and one serialising them, so it should never be silent.
                    logger.info(
                        f"Minimal locking is enabled but no package or device scope could be "
                        f"resolved for URL: {url}. Falling back to locking the whole ADOM: {adom}.")
                lock_acquired_at = time.monotonic()
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
                    # Deliberately no unlock here. Releasing at this point is unsafe for
                    # the install URLs: the queued task copies config to the device after
                    # the RPC returns, and dropping the lock mid-copy lets another worker
                    # write the ADOM underneath a running install -- which is why
                    # HOLD_LOCK_UNTIL_TASK_URLS exists. For every other URL the release
                    # happens a few statements later (or at session teardown, which pyFMG
                    # does on __exit__), so an early unlock here would buy back only the
                    # duration of the task-tracking block while adding that hazard.
                elif minimal_lock_held:
                    commit_minimal_scope(fmg, adom, scope_type, scope_id)

                response[f"{action}_response"] = action_response
                # If the action is execute and track_task is set to True, track the task
                # Also need to make sure that the response is a dict because some exec actions like sys/proxy/info can return a list
                # Installs need the lock held while the queued task copies to the
                # device, so for those URLs the task is followed here whether or not the
                # caller asked for tracking -- the release below must not happen first.
                track_requested = bool(params.get("track_task", False))
                hold_until_task = needs_lock and holds_lock_until_task(url)
                if action == 'execute' and (track_requested or hold_until_task) and isinstance(action_response, dict):
                    task = action_response.get('task') or action_response.get('taskid')
                    # handle case where no task id is found and there is an attempt to track task
                    if not task and not track_requested:
                        # Nothing to wait on and the caller never asked for a task, so
                        # there is no lock-lifetime problem and nothing to report.
                        pass
                    elif not task:
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
                        track_status, task_response = fmg.track_task(task, **track_task_params)
                        response["task_response"] = task_response
                        # A caller who did not ask for tracking still gets the task
                        # outcome -- it is how an install reports failure -- but keeps
                        # the RPC's own status as the top-level one.
                        if track_requested:
                            status = track_status

                        # Handle special cases. Putting this here because the task needs to be tracked first for exec actions
                        special_case_result = handle_special_cases(fmg, url, data, action_response, task_response)
                        if special_case_result:
                            response["special_case_response"] = special_case_result

                    # The commit is redundant in the common case -- the write was already
                    # committed above and a queued task does not add ADOM changes of its
                    # own -- but it is safe to repeat: workspace/commit is idempotent,
                    # returning status 0 with nothing pending and even with no lock held.
                    # It is kept because the special-case handlers above can write, and
                    # costs one round trip. Note the corollary: a commit returning 0 is
                    # not evidence that a write landed, so never judge one by its status.
                    # The minimal-scope path already committed above and commits again on
                    # release, so only the ADOM path needs the extra commit/unlock here.
                    if needs_lock and scope_type is None:
                        fmg.commit_changes(adom)
                        fmg.unlock_adom(adom)
                        adom_released_here = True
                        logger.debug(
                            f"Released ADOM lock: {adom} after tracking the task "
                            f"({_held_for(lock_acquired_at)}).")
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
                # Hold time is the number this whole lock-scoping effort is about: it is
                # what other workers wait on. Emit it once per call so a slow workspace
                # can be diagnosed from the log alone, without re-running a probe.
                if lock_acquired_at is not None:
                    scope_label = f"{scope_type}/{scope_id}" if scope_type else f"adom/{adom}"
                    # Minimal scopes are released just above, and the ADOM is released
                    # explicitly only on the task-tracking path. Otherwise pyFMG drops it
                    # when the session closes, moments after this line -- so report that
                    # rather than implying the lock is already free.
                    if scope_type is not None or adom_released_here:
                        tail = "released"
                    else:
                        tail = "released when the session closes, shortly after this"
                    logger.info(f"Workspace lock {scope_label} held for "
                                f"{_held_for(lock_acquired_at)} on URL: {url} ({tail}).")

            response["status"] = status
            logger.debug(response)
            return response
    except Exception as e:
        raise ConnectorError(e)
