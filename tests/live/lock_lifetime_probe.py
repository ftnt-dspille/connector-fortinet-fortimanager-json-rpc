"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
Does a workspace lock have to outlive the task the operation queues?

The lock-necessity probe holds its lock until the queued task finishes. The connector
does not: unless the caller sets track_task=True, perform_rpc_action commits, unlocks
and logs out as soon as the exec returns, while FMG has only *accepted* the work. A
measurement taken with probe timing therefore does not describe what a caller actually
gets.

Measured on a live 7.6.7 appliance for install/package: with the lock released at RPC
return the task fails (num_err=1) even though the identical call succeeds when the lock
is held across it. This probe generalises that to every task-queuing URL.

Three arms per case, each preceded by a freshly made pending change so no arm can pass
by installing nothing:

    HELD      lock taken, task followed to completion, then released   (probe timing)
    RELEASED  lock taken, released + session closed at RPC return,     (connector timing,
              task followed from a separate session                     track_task=False)
    NONE      no lock at all, session closed at RPC return              (baseline)

    HELD ok / RELEASED ok    -> lock lifetime does not matter for this URL
    HELD ok / RELEASED fail  -> LIFETIME_MATTERS; the connector must hold until the task
                                ends, and any verdict taken with probe timing overstates
                                what callers get
    HELD fail                -> the case is broken for another reason; fix before reading

Writes go to a real managed FortiGate, so everything is gated behind --allow-device-push.

Usage
-----
    python lock_lifetime_probe.py --list
    python lock_lifetime_probe.py --address <fmg> --username <u> --password <p> \
        --adom root --device <device> --package <package> --allow-device-push
"""

import argparse
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore")

current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_directory)

from lock_matrix_probe import (  # noqa: E402
    connect, resolve_task, script_endpoint, parse_fmg_version,
    SCRIPT_TYPE_CLI, TARGET_DEVICE_DATABASE, TARGET_REMOTE_DEVICE,
)
from auto_lock_ws_probe import acquire, release  # noqa: E402

SAFE_PREFIX = "zz_locklife"

HELD = "HELD"
RELEASED = "RELEASED"
NONE = "NONE"

LIFETIME_MATTERS = "LIFETIME_MATTERS"
LIFETIME_IRRELEVANT = "LIFETIME_IRRELEVANT"
BROKEN = "BROKEN"


class Case:
    """One task-queuing operation, with the pending change that gives it work to do."""

    def __init__(self, name, url, data, lock_scope, make_pending=None, setup=None,
                 cleanup=None, notes=""):
        self.name = name
        self.url = url
        self.data = data
        self.lock_scope = lock_scope
        self.make_pending = make_pending
        self.setup = setup
        self.cleanup = cleanup
        self.notes = notes


def under_adom_lock(fmg, adom, work):
    """Run a write with the ADOM lock held, then commit and release."""
    status, _ = acquire(fmg, adom, None)
    if status != 0:
        raise RuntimeError(f"could not take the ADOM lock for setup: {status}")
    try:
        return work(fmg)
    finally:
        fmg.execute(url=f"/dvmdb/adom/{adom}/workspace/commit")
        release(fmg, adom, None)


def run_arm(case, adom, arm, connect_args, watcher, timeout):
    """
    Run one arm and return (ok, detail).

    HELD keeps the operating session and its lock alive until the task finishes.
    RELEASED and NONE close the session at RPC return, exactly as perform_rpc_action
    does without track_task, and hand the task to the watcher session to follow.
    """
    with connect(*connect_args) as fmg:
        if arm != NONE:
            status, _ = acquire(fmg, adom, case.lock_scope)
            if status != 0:
                return False, f"could not take {case.lock_scope}: status={status}"
        try:
            status, response = fmg.execute(url=case.url, data=dict(case.data))
            if status != 0:
                return False, f"rpc status={status}"
            task = response.get("task") or response.get("taskid") if isinstance(response, dict) else None
            if not task:
                return False, f"no task queued: {response}"
            if arm == HELD:
                ok, detail = resolve_task(fmg, {"task": task}, timeout=timeout)
                return bool(ok), detail
        finally:
            if arm != NONE:
                scope_type, scope_id = case.lock_scope
                fmg.execute(
                    url=f"/dvmdb/adom/{adom}/workspace/commit/{scope_type}/{scope_id}")
                release(fmg, adom, case.lock_scope)
    # Session is closed; the work, if any, is now happening without it.
    ok, detail = resolve_task(watcher, {"task": task}, timeout=timeout)
    return bool(ok), detail


def classify(results):
    held = results.get(HELD, (False, ""))[0]
    released = results.get(RELEASED, (False, ""))[0]
    if not held:
        return BROKEN
    return LIFETIME_IRRELEVANT if released else LIFETIME_MATTERS


def build_cases(adom, device, package, vdom, version=None):
    script_url = script_endpoint(adom, version)
    policy_url = f"/pm/config/adom/{adom}/pkg/{package}/firewall/policy/1"
    scope = [{"name": device, "vdom": vdom}]
    remote_script = f"{SAFE_PREFIX}_remote"
    devdb_script = f"{SAFE_PREFIX}_devdb"

    # Toggling a trailing space in a policy comment is the smallest pending change that
    # a package install will actually push, and it restores itself on the next flip.
    marker = {"count": 0}

    def pending_policy_edit(fmg):
        marker["count"] += 1
        comment = "lock lifetime probe" + ("." * (marker["count"] % 2))
        under_adom_lock(fmg, adom, lambda f: f.update(url=policy_url,
                                                      data={"comments": comment}))

    def device_db_body(fmg):
        """Rewrite the device's own hostname: a real device-DB change that is inert."""
        status, current = fmg.get(url=f"/pm/config/device/{device}/global/system/global",
                                  fields=["hostname"])
        hostname = current.get("hostname") if isinstance(current, dict) else None
        if status != 0 or not hostname:
            raise RuntimeError("could not read the device hostname for the probe script")
        return f"config system global\nset hostname {hostname}\nend"

    def make_script(name, target, body_fn):
        def setup(fmg):
            def work(f):
                f.delete(url=f"{script_url}/{name}")
                return f.add(url=script_url, data={
                    "name": name, "type": SCRIPT_TYPE_CLI, "target": target,
                    "content": body_fn(f),
                    "desc": "lock lifetime probe, safe to delete"})
            status, response = under_adom_lock(fmg, adom, work)
            if status != 0:
                raise RuntimeError(f"could not create probe script {name}: {status} {response}")
        return setup

    def delete_script(name):
        def cleanup(fmg):
            under_adom_lock(fmg, adom, lambda f: f.delete(url=f"{script_url}/{name}"))
        return cleanup

    def pending_device_db_change(fmg):
        """Run the device-DB script so install/device has something to push."""
        status, response = fmg.execute(
            url=f"/dvmdb/adom/{adom}/script/execute",
            data={"adom": adom, "script": devdb_script, "scope": scope})
        # The script itself needs a lock; run it the way the probe knows works.
        if status != 0:
            raise RuntimeError(f"could not stage a device-DB change: {status} {response}")
        resolve_task(fmg, response, timeout=120)

    def staged_device_db_change(fmg):
        under_adom_lock(fmg, adom, pending_device_db_change)

    return [
        Case("install/package (policy)", "/securityconsole/install/package",
             {"adom": adom, "pkg": package, "scope": scope}, ("pkg", package),
             make_pending=pending_policy_edit,
             notes="known LIFETIME_MATTERS; anchors the rest"),
        # reinstall/package does NOT take adom/pkg/scope like install/package does. It
        # takes a target[] list of {pkg, scope} pairs, which is what lets one call
        # install several packages to several devices (sequentially, per FMG's docs).
        # Sent the install/package way it returns 0 with a task id that then sits at
        # state=0 percent=0 forever -- see section H.3.
        Case("reinstall/package", "/securityconsole/reinstall/package",
             {"adom": adom, "flags": ["generate_rev"],
              "target": [{"pkg": package, "scope": scope}]}, ("pkg", package),
             make_pending=pending_policy_edit,
             notes="used by the ZTP pack, absent from every list in the connector"),
        Case("install/device (config only)", "/securityconsole/install/device",
             {"adom": adom, "scope": scope}, ("dev", device),
             make_pending=staged_device_db_change,
             # Staging the pending change runs the device-DB script, so this case needs
             # that script to exist just as much as the script-exec case below does.
             setup=make_script(devdb_script, TARGET_DEVICE_DATABASE, device_db_body),
             cleanup=delete_script(devdb_script),
             notes="currently in NO_LOCK_URLS, measured with nothing pending"),
        Case("script exec -> remote device", f"/dvmdb/adom/{adom}/script/execute",
             {"adom": adom, "script": remote_script, "scope": scope}, ("dev", device),
             setup=make_script(remote_script, TARGET_REMOTE_DEVICE,
                               lambda f: "get system status"),
             cleanup=delete_script(remote_script),
             notes="runs on the FortiGate; does the lock matter after the RPC?"),
        Case("script exec -> device database", f"/dvmdb/adom/{adom}/script/execute",
             {"adom": adom, "script": devdb_script, "scope": scope}, ("dev", device),
             setup=make_script(devdb_script, TARGET_DEVICE_DATABASE, device_db_body),
             cleanup=delete_script(devdb_script),
             notes="writes the device DB inside FMG"),
    ]


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--adom", default="root")
    parser.add_argument("--device", default=os.getenv("LIVE_FGT_DEVICE_NAME", ""))
    parser.add_argument("--vdom", default="root")
    parser.add_argument("--package", default=os.getenv("FGT_ASSIGNED_POL_PKG", "default"))
    parser.add_argument("--task-timeout", type=int, default=300)
    parser.add_argument("--only", default="", help="substring filter on case name")
    parser.add_argument("--allow-device-push", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--address", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()

    cases = build_cases(args.adom, args.device, args.package, args.vdom)
    if args.only:
        cases = [c for c in cases if args.only.lower() in c.name.lower()]

    if args.list:
        print(f"Lock-lifetime cases for ADOM '{args.adom}' "
              f"(device={args.device or '<unset>'}, package={args.package}):\n")
        for case in cases:
            print(f"  {case.url}  lock={case.lock_scope}")
            print(f"      {case.name} - {case.notes}")
        return 0

    if not args.device:
        print("--device is required.")
        return 2
    if not args.allow_device_push:
        print("These cases push configuration to a real FortiGate. "
              "Rerun with --allow-device-push.")
        return 2

    connect_args = (args.address, args.username, args.password, args.api_key)
    verdicts = []
    with connect(*connect_args) as watcher:
        if not watcher._lock_ctx.uses_workspace:
            print("Workspace mode is DISABLED; this probe cannot tell anything apart.")
            return 2
        version = parse_fmg_version(watcher)
        cases = build_cases(args.adom, args.device, args.package, args.vdom, version)
        if args.only:
            cases = [c for c in cases if args.only.lower() in c.name.lower()]

        for case in cases:
            print(f"-> {case.name}")
            results = {}
            try:
                if case.setup:
                    case.setup(watcher)
                for arm in (HELD, RELEASED, NONE):
                    if case.make_pending:
                        case.make_pending(watcher)
                    ok, detail = run_arm(case, args.adom, arm, connect_args,
                                         watcher, args.task_timeout)
                    results[arm] = (ok, detail)
                    print(f"   {arm:<9} {'OK  ' if ok else 'FAIL'} {detail}")
                    time.sleep(2)
            except Exception as error:
                print(f"   ! case aborted: {error}")
                results.setdefault(HELD, (False, str(error)))
            finally:
                if case.cleanup:
                    try:
                        case.cleanup(watcher)
                    except Exception as cleanup_error:
                        print(f"   ! cleanup failed: {cleanup_error}")
            verdict = classify(results)
            verdicts.append((case, results, verdict))
            print(f"   => {verdict}")

    print("\n" + "=" * 100)
    print(f"{'VERDICT':<20} {'CASE':<34} {'HELD':<6} {'RELEASED':<10} NONE")
    print("=" * 100)
    for case, results, verdict in verdicts:
        def cell(arm):
            entry = results.get(arm)
            return "-" if entry is None else ("ok" if entry[0] else "fail")
        print(f"{verdict:<20} {case.name:<34} {cell(HELD):<6} "
              f"{cell(RELEASED):<10} {cell(NONE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
