"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
Live end-to-end check that minimal locking takes the right lock and still works.

The lock matrix probe answers "does this operation need a lock". This answers the
next question: with minimal_locking enabled, does the connector take a *narrower*
lock than the whole ADOM, and does the operation still succeed with only that lock?

Both halves matter. A narrower lock that FMG accepts but that does not grant write
permission is worse than no optimisation at all: the lock call returns 0, the
connector believes it holds the lock, and the operation then fails with a permission
error that looks nothing like a locking problem.

Every workspace call the connector makes is recorded, so the assertion is on the
actual lock URL, not on a log message.

    python verify_minimal_locking.py --address <host> --username <u> --password <p> \
        --adom root --device <device> --package <pkg>
"""

import argparse
import importlib
import json
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore")

current_directory = os.path.dirname(os.path.abspath(__file__))
tests_directory = os.path.abspath(os.path.join(current_directory, os.pardir))
repo_root = os.path.abspath(os.path.join(tests_directory, os.pardir))
sys.path.insert(0, tests_directory)
sys.path.insert(0, repo_root)

import conftest  # noqa: F401,E402  installs the connectors.core stub

generic_json_rpc = importlib.import_module(
    "fortinet-fortimanager-json-rpc.generic_json_rpc")

SAFE_PREFIX = "zz_minlock"


# Every workspace URL the connector touches, across all sessions in one case.
WORKSPACE_CALLS = []


def record_workspace_calls(fmg):
    """
    Wrap execute() and lock_adom() so every lock this connector takes is captured.

    pyFMG calls execute() positionally, so the wrapper must forward *args untouched
    rather than re-passing url as a keyword. ADOM-level locks go through lock_adom()
    and never reach execute(), so they are recorded separately.
    """
    original_execute = fmg.execute
    original_lock_adom = fmg.lock_adom

    def execute(*args, **kwargs):
        url = kwargs.get("url") or (args[0] if args else None)
        if isinstance(url, str) and "/workspace/" in url:
            WORKSPACE_CALLS.append(url)
        return original_execute(*args, **kwargs)

    def lock_adom(adom=None, *args, **kwargs):
        WORKSPACE_CALLS.append(f"lock_adom:{adom}")
        return original_lock_adom(adom, *args, **kwargs)

    fmg.execute = execute
    fmg.lock_adom = lock_adom


def run_case(config, label, action, params, expected_lock):
    """Run one connector call and report the lock it took and whether the work landed."""
    WORKSPACE_CALLS.clear()
    try:
        response = generic_json_rpc.perform_rpc_action(action, config, params)
        error = None
    except Exception as exc:
        response, error = None, exc

    locks = [u for u in WORKSPACE_CALLS
             if "/workspace/lock" in u or u.startswith("lock_adom:")]
    if not locks:
        took = "(no lock taken)"
    elif locks[0].startswith("lock_adom:"):
        took = "(ADOM-wide)"
    else:
        took = locks[0].split("/workspace/lock")[1] or "(ADOM-wide)"
    scope_ok = (expected_lock in took) if expected_lock else (took == "(ADOM-wide)")

    outcome = "raised: %s" % error if error else "ok"
    task = (response or {}).get("task_response") if isinstance(response, dict) else None
    if isinstance(task, dict):
        outcome = (f"task state={task.get('state')} num_err={task.get('num_err')} "
                   f"{(task.get('line') or [{}])[0].get('detail', '')[:55]}")
        work_ok = not task.get("num_err") and task.get("state") != 5
    else:
        work_ok = error is None

    print(f"\n{label}")
    print(f"  lock taken : {took}")
    print(f"  expected   : {expected_lock or '(ADOM-wide)'}")
    print(f"  outcome    : {outcome}")
    print(f"  ==> scope {'OK' if scope_ok else 'WRONG'} / work {'OK' if work_ok else 'FAILED'}")
    return scope_ok and work_ok


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--address", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--adom", default="root")
    parser.add_argument("--device", required=True)
    parser.add_argument("--package", required=True)
    args = parser.parse_args()

    config = {
        "address": args.address, "username": args.username, "password": args.password,
        "auth_method": "Credentials", "verify_ssl": False, "port": "443",
        "minimal_locking": True,
    }
    adom, device, package = args.adom, args.device, args.package
    script_url = f"/pm/config/adom/{adom}/obj/fmg/script"
    script_name = f"{SAFE_PREFIX}_script"

    # Capture workspace calls by wrapping the FortiManager class the connector uses.
    real_fmg = generic_json_rpc.FortiManager

    class RecordingFMG(real_fmg):
        def __enter__(self):
            instance = super().__enter__()
            record_workspace_calls(instance)
            return instance

    generic_json_rpc.FortiManager = RecordingFMG

    def make_script(target, content):
        generic_json_rpc.perform_rpc_action("delete", config, {
            "url": f"{script_url}/{script_name}", "data": {}})
        generic_json_rpc.perform_rpc_action("add", config, {
            "url": script_url,
            "data": {"name": script_name, "type": 1, "target": target,
                     "content": content, "desc": "minimal lock check, safe to delete"}})

    results = []

    # 1. Policy edit in a package: scope comes from the URL (already worked before).
    results.append(run_case(
        config, "1. policy read-modify inside a package (URL scope)", "set",
        {"url": f"/pm/config/adom/{adom}/pkg/{package}/firewall/address",
         "data": {"name": f"{SAFE_PREFIX}_addr", "subnet": ["10.255.255.251", "255.255.255.255"]}},
        f"/pkg/{package}"))
    generic_json_rpc.perform_rpc_action("delete", config, {
        "url": f"/pm/config/adom/{adom}/pkg/{package}/firewall/address/{SAFE_PREFIX}_addr",
        "data": {}})

    # 2. Device-targeted script execution: scope comes from data.scope.
    make_script(0, "config system global\nend")
    results.append(run_case(
        config, "2. script execute against a device (payload scope -> dev)", "execute",
        {"url": f"/dvmdb/adom/{adom}/script/execute", "track_task": True,
         "data": {"adom": adom, "script": script_name,
                  "scope": [{"name": device, "vdom": "root"}]}},
        f"/dev/{device}"))

    # 3. Package-targeted script execution: scope comes from data.package.
    make_script(2, f'config firewall address\nedit "{SAFE_PREFIX}_scripted"\n'
                   f'set subnet 10.255.255.250 255.255.255.255\nnext\nend')
    results.append(run_case(
        config, "3. script execute against a package (payload scope -> pkg)", "execute",
        {"url": f"/dvmdb/adom/{adom}/script/execute", "track_task": True,
         "data": {"adom": adom, "package": package, "script": script_name}},
        f"/pkg/{package}"))

    # 4. Package install: payload names both a package and a device; only the package
    #    lock grants permission, so the package must win.
    results.append(run_case(
        config, "4. install package (payload names pkg AND dev -> pkg must win)", "execute",
        {"url": "/securityconsole/install/package", "track_task": True,
         "data": {"adom": adom, "pkg": package,
                  "scope": [{"name": device, "vdom": "root"}]}},
        f"/pkg/{package}"))

    # 5. Several devices cannot be covered by one lock, so fall back to the ADOM.
    make_script(0, "config system global\nend")
    results.append(run_case(
        config, "5. script execute against TWO devices (must fall back to ADOM)", "execute",
        {"url": f"/dvmdb/adom/{adom}/script/execute", "track_task": True,
         "data": {"adom": adom, "script": script_name,
                  "scope": [{"name": device, "vdom": "root"},
                            {"name": device, "vdom": "root"}]}},
        None))

    # 6. An ADOM object write has nothing finer available.
    results.append(run_case(
        config, "6. ADOM object write (no finer scope exists -> ADOM)", "add",
        {"url": f"/pm/config/adom/{adom}/obj/firewall/address",
         "data": {"name": f"{SAFE_PREFIX}_objaddr",
                  "subnet": ["10.255.255.249", "255.255.255.255"]}},
        None))

    for url in (f"{script_url}/{script_name}",
                f"/pm/config/adom/{adom}/obj/firewall/address/{SAFE_PREFIX}_objaddr",
                f"/pm/config/adom/{adom}/obj/firewall/address/{SAFE_PREFIX}_scripted"):
        generic_json_rpc.perform_rpc_action("delete", config, {"url": url, "data": {}})

    generic_json_rpc.FortiManager = real_fmg
    print("\n" + "=" * 70)
    print(f"{sum(results)}/{len(results)} cases took the expected lock and completed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
