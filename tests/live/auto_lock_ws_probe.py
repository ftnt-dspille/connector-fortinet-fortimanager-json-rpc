"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
Measure what the `auto_lock_ws` install flag actually does to workspace locking.

Real callers (a shipped FortiSOAR ZTP solution pack's FMG microservices) send
/securityconsole/install/package with flags: ["auto_lock_ws"], which asks FortiManager
to take and release the workspace lock server-side. This connector also takes a lock for
that URL. Three things follow, and none of them were measured:

  Q1  Does install/package + auto_lock_ws succeed with NO client lock held?
      If yes, the "install/package = REQUIRED" verdict does not describe real traffic.
  Q2  What does FMG's own auto-lock take -- the whole ADOM, or just the device/package
      scope? Held from a second session: a lock on an unrelated device, then a lock on
      the install target. If the unrelated-device arm blocks, the auto-lock is ADOM-wide.
  Q3  Does the connector's own lock collide with the server-side auto-lock (double
      lock)? Hold dev/ and pkg/ scopes in the calling session and fire the install.
      A failure here is a shipped bug of the same class as the install/package one.

Every arm is judged on the finished task (num_err / state), never on the RPC status:
an install returns 0 with a task id whether or not it was allowed to do anything.

This pushes the device's already-assigned policy package to a real FortiGate, so it is
gated behind --allow-device-push.

Usage
-----
    python auto_lock_ws_probe.py --list
    python auto_lock_ws_probe.py --address <fmg> --username <u> --password <p> \
        --adom root --device <device> --package <package> \
        --other-device <another device> --allow-device-push
"""

import argparse
import json
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore")

current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_directory)

from lock_matrix_probe import connect, resolve_task  # noqa: E402

INSTALL_PACKAGE = "/securityconsole/install/package"


def acquire(fmg, adom, scope=None):
    """Take a workspace lock; scope is (type, id) or None for the whole ADOM."""
    url = f"/dvmdb/adom/{adom}/workspace/lock"
    if scope:
        url = f"{url}/{scope[0]}/{scope[1]}"
    return fmg.execute(url=url)


def release(fmg, adom, scope=None):
    base = f"/dvmdb/adom/{adom}/workspace"
    suffix = f"/{scope[0]}/{scope[1]}" if scope else ""
    fmg.execute(url=f"{base}/unlock{suffix}")


def install(fmg, adom, package, device, vdom, flags, timeout):
    """Fire one install/package and follow it to a task outcome."""
    data = {"adom": adom, "pkg": package, "scope": [{"name": device, "vdom": vdom}]}
    if flags:
        data["flags"] = list(flags)
    status, response = fmg.execute(url=INSTALL_PACKAGE, data=data)
    if status != 0:
        return False, f"rpc status={status} {json.dumps(response)[:120]}"
    task_ok, detail = resolve_task(fmg, response, timeout=timeout)
    if task_ok is None:
        return False, f"no task in response: {json.dumps(response)[:120]}"
    return task_ok, detail


def run_case(name, question, fmg, adom, package, device, vdom, flags, timeout,
             client_scope=None, holder=None, holder_scope=None):
    """
    One measured install.

    client_scope  lock taken in the calling session before the install (the connector's
                  own lock; None means the connector took nothing)
    holder/holder_scope  lock held by a *different* session for the duration
    """
    print(f"-> [{question}] {name}")
    held_client = False
    held_holder = False
    try:
        if holder_scope is not None:
            status, response = acquire(holder, adom, holder_scope)
            if status != 0:
                return (name, question, None,
                        f"second session could not take {holder_scope}: {status}")
            held_holder = True
        if client_scope is not None:
            status, response = acquire(fmg, adom, client_scope)
            if status != 0:
                # A refusal here is itself the answer for Q3-style cases.
                return (name, question, False,
                        f"client lock {client_scope} refused: status={status} "
                        f"{json.dumps(response)[:100]}")
            held_client = True
        ok, detail = install(fmg, adom, package, device, vdom, flags, timeout)
        print(f"   => {'OK' if ok else 'FAIL'}  {detail}")
        return name, question, ok, detail
    finally:
        if held_client:
            release(fmg, adom, client_scope)
        if held_holder:
            release(holder, adom, holder_scope)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--adom", default="root")
    parser.add_argument("--device", default=os.getenv("LIVE_FGT_DEVICE_NAME", ""),
                        help="install target; must be a scope member of --package")
    parser.add_argument("--vdom", default="root")
    parser.add_argument("--package", default=os.getenv("FGT_ASSIGNED_POL_PKG", "default"))
    parser.add_argument("--other-device", default="",
                        help="an unrelated device in the same ADOM, for the Q2 arms")
    parser.add_argument("--task-timeout", type=int, default=180)
    parser.add_argument("--allow-device-push", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--address", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()

    dev_scope = ("dev", args.device)
    pkg_scope = ("pkg", args.package)
    other_scope = ("dev", args.other_device)

    plan = [
        ("baseline: no flag, no lock", "Q1", None, None, None),
        ("baseline: no flag, client dev lock", "Q1", None, dev_scope, None),
        ("auto_lock_ws, no client lock", "Q1", ["auto_lock_ws"], None, None),
        ("auto_lock_ws, client dev lock (double lock)", "Q3", ["auto_lock_ws"], dev_scope, None),
        ("auto_lock_ws, client pkg lock (double lock)", "Q3", ["auto_lock_ws"], pkg_scope, None),
        ("auto_lock_ws vs other session holding dev/<other>", "Q2", ["auto_lock_ws"], None, other_scope),
        ("auto_lock_ws vs other session holding dev/<target>", "Q2", ["auto_lock_ws"], None, dev_scope),
        ("auto_lock_ws vs other session holding pkg/<package>", "Q2", ["auto_lock_ws"], None, pkg_scope),
    ]

    if args.list:
        print(f"install/package probes against {args.adom}/{args.package} -> "
              f"{args.device or '<unset>'}:\n")
        for name, question, flags, client_scope, holder_scope in plan:
            print(f"  [{question}] {name}")
            print(f"          flags={flags} client_lock={client_scope} "
                  f"other_session_holds={holder_scope}")
        return 0

    if not args.device:
        print("--device is required (the install target).")
        return 2
    if not args.allow_device_push:
        print("These probes install a policy package onto a real FortiGate. "
              "Rerun with --allow-device-push.")
        return 2

    results = []
    with connect(args.address, args.username, args.password, args.api_key) as fmg, \
            connect(args.address, args.username, args.password, args.api_key) as holder:
        if not fmg._lock_ctx.uses_workspace:
            print("Workspace mode is DISABLED; this probe cannot tell anything apart.")
            return 2
        for name, question, flags, client_scope, holder_scope in plan:
            if holder_scope is not None and not holder_scope[1]:
                print(f"-- skipped [{question}] {name}: needs --other-device")
                continue
            results.append(run_case(name, question, fmg, args.adom, args.package,
                                    args.device, args.vdom, flags, args.task_timeout,
                                    client_scope, holder, holder_scope))
            time.sleep(2)

    print("\n" + "=" * 96)
    print(f"{'Q':<4} {'RESULT':<8} {'CASE':<52} DETAIL")
    print("=" * 96)
    for name, question, ok, detail in results:
        verdict = "OK" if ok else ("SKIP" if ok is None else "FAIL")
        print(f"{question:<4} {verdict:<8} {name:<52} {detail[:60]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
