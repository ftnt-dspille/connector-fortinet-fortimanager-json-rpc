"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
How does a minimal-scope workspace lock actually end?

An abandoned lock was already measured: it survives the dead session, another session's
unlock returns status 0 and does not release it, and only a CLI session-kill clears it.
That leaves the question this probe answers, which matters more now that the connector
holds install locks until the queued task finishes:

    does a CLEAN logout release a dev/pkg scope lock?

pyFMG's logout() calls run_unlock(), which releases the ADOM locks it registered through
lock_adom(). Minimal-scope locks are taken with execute() and are not in that list, so
the ADOM arm is the control that shows the observable works and the dev/pkg arms are the
measurement.

Three arms per scope:

    EXPLICIT  lock, unlock, logout                  -> must end unlocked (sanity check)
    LOGOUT    lock, logout without unlocking        -> the measurement
    ABANDONED lock, then neither unlock nor logout  -> known-held control

Each arm is judged on two independent observables, because the appliance lies about one
of them: `workspace/lockinfo` for the scope, and whether a *second* session can take the
same lock. An unlock call's status 0 is not evidence of anything.

The ABANDONED arm keeps its session handle so the probe can release the lock afterwards
rather than wedging the scope for the 8-hour API idle timeout. If the LOGOUT arm leaves a
lock behind there is no handle to release it with, and the probe prints the CLI
session-kill needed to clear it.

Everything runs against model devices and a scratch package in a scratch ADOM; no
configuration is pushed anywhere and no task is queued.

Usage
-----
    python lock_release_probe.py --adom <scratch-adom> --device <model-device> \
        --package <scratch-package>
"""

import argparse
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")

current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_directory)

from lock_matrix_probe import connect  # noqa: E402

EXPLICIT = "EXPLICIT"
LOGOUT = "LOGOUT"
ABANDONED = "ABANDONED"

RELEASED_ON_LOGOUT = "RELEASED_ON_LOGOUT"
SURVIVES_LOGOUT = "SURVIVES_LOGOUT"
BROKEN = "BROKEN"


def lock_url(adom, scope, verb="lock"):
    url = f"/dvmdb/adom/{adom}/workspace/{verb}"
    return f"{url}/{scope[0]}/{scope[1]}" if scope else url


def read_lockinfo(fmg, adom, scope):
    """
    Return (held, raw) for a scope.

    lockinfo answers for the whole ADOM as well as for a scope, and the shape differs
    between them, so 'held' is derived from whichever of the documented keys is present
    rather than from a fixed path.
    """
    status, response = fmg.get(url=lock_url(adom, scope, "lockinfo"))
    if status != 0:
        return None, f"lockinfo status={status} {json.dumps(response)[:120]}"
    holder = None
    if isinstance(response, list):
        # A held lock answers with a list of lock records; a free one answers with the
        # bare status envelope, which pyFMG hands back as a dict.
        holder = next((entry.get("lock_user") or entry.get("lock_sid")
                       for entry in response if isinstance(entry, dict)), None)
    elif isinstance(response, dict):
        holder = (response.get("lock_user") or response.get("lock_sid")
                  or response.get("user") or response.get("sid"))
        if holder is None and isinstance(response.get("status"), dict):
            inner = response["status"]
            holder = inner.get("lock_user") or inner.get("lock_sid")
    return bool(holder), json.dumps(response)[:160]


def second_session_can_lock(connect_args, adom, scope):
    """
    The observable that cannot be faked: take the same lock from a fresh session.

    Released immediately if it is granted, so this probe never becomes the thing that
    holds a lock open.
    """
    with connect(*connect_args) as other:
        status, response = other.execute(url=lock_url(adom, scope))
        if status == 0:
            other.execute(url=lock_url(adom, scope, "unlock"))
            return True, "granted"
        return False, f"status={status} {json.dumps(response)[:100]}"


def run_arm(arm, connect_args, adom, scope):
    """
    Take the lock, end the session the way this arm specifies, and report what is left.

    Returns (still_held, detail, leftover_session). leftover_session is the handle of a
    deliberately abandoned session, so the caller can clean up after measuring.
    """
    fmg = connect(*connect_args)
    fmg.login()
    status, response = fmg.execute(url=lock_url(adom, scope))
    if status != 0:
        fmg.logout()
        return None, f"could not take the lock: status={status} {json.dumps(response)[:100]}", None

    leftover = None
    if arm == EXPLICIT:
        fmg.execute(url=lock_url(adom, scope, "unlock"))
        fmg.logout()
    elif arm == LOGOUT:
        # No unlock. This is the whole question: does logout clean up a scope lock the
        # way it cleans up an ADOM lock taken through lock_adom()?
        fmg.logout()
    else:
        # Neither unlock nor logout: a crashed worker. The handle is kept only so the
        # probe can release the lock once the measurement is taken.
        leftover = fmg

    with connect(*connect_args) as observer:
        held, raw = read_lockinfo(observer, adom, scope)
    lockable, lock_detail = second_session_can_lock(connect_args, adom, scope)
    still_held = lockable is False if held is None else (held or not lockable)
    return still_held, f"lockinfo={raw} second_session={lock_detail}", leftover


def classify(results):
    explicit = results.get(EXPLICIT, (None,))[0]
    logout = results.get(LOGOUT, (None,))[0]
    abandoned = results.get(ABANDONED, (None,))[0]
    if explicit is not False or abandoned is not True:
        # The controls did not behave, so the LOGOUT reading means nothing.
        return BROKEN
    return SURVIVES_LOGOUT if logout else RELEASED_ON_LOGOUT


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--adom", required=True, help="scratch ADOM with workspace enabled")
    parser.add_argument("--device", default="", help="model device for the dev scope")
    parser.add_argument("--package", default="", help="scratch package for the pkg scope")
    parser.add_argument("--only", default="", help="substring filter on scope name")
    parser.add_argument("--address", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()

    scopes = [("adom", None, "ADOM lock: pyFMG registers this one, so logout should free it")]
    if args.device:
        scopes.append((f"dev/{args.device}", ("dev", args.device),
                       "device scope: taken with execute(), not registered with pyFMG"))
    if args.package:
        scopes.append((f"pkg/{args.package}", ("pkg", args.package),
                       "package scope: taken with execute(), not registered with pyFMG"))
    if args.only:
        scopes = [s for s in scopes if args.only.lower() in s[0].lower()]

    connect_args = (args.address, args.username, args.password, args.api_key)
    with connect(*connect_args) as fmg:
        if not fmg._lock_ctx.uses_workspace:
            print("Workspace mode is DISABLED on this appliance; nothing to measure.")
            return 2

    verdicts = []
    for name, scope, note in scopes:
        print(f"-> {name}  ({note})")
        results = {}
        for arm in (EXPLICIT, LOGOUT, ABANDONED):
            still_held, detail, leftover = run_arm(arm, connect_args, args.adom, scope)
            results[arm] = (still_held, detail)
            state = "HELD " if still_held else ("free " if still_held is False else "?    ")
            print(f"   {arm:<9} {state} {detail}")
            if leftover is not None:
                leftover.execute(url=lock_url(args.adom, scope, "unlock"))
                leftover.logout()
        verdict = classify(results)
        verdicts.append((name, verdict))
        if verdict == SURVIVES_LOGOUT:
            print(f"   !! {name} is still locked after a clean logout. Clear it with:")
            print("      diagnose system admin-session kill <sid>   (FMG CLI)")
        print()

    print("Verdicts")
    for name, verdict in verdicts:
        print(f"  {name:<28} {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
