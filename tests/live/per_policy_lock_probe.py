"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
Is there a usable lock scope below the policy package?

The connector's narrowest scope is `pkg`, which serialises every worker that touches the
same package. FortiManager has a finer scope -- one firewall policy -- gated behind the
global `per-policy-lock` setting. It is the only scope that lets two workers edit the
same package concurrently, so it is worth more than pkg scoping for the common case of
many automations pointed at one package.

Four things have to hold before the connector could use it, and this probe measures each:

    GRANTED    the lock URL is accepted
    AUTHORISES a write to the locked policy lands and survives the unlock
    SCOPED     a write to a *different* policy in the same package is denied
    CONCURRENT a second session locks a different policy in the same package and both
               changes persist

and one thing has to be checked before ever taking this lock in shipping code:

    FEATURE OFF   with `per-policy-lock` disabled the very same URL still returns 0 for
                  two sessions at once, and the subsequent write is denied -10147. The
                  lock is a no-op that reports success, so a connector that adopted this
                  scope without reading the global setting would silently break every
                  policy write on every appliance where the feature is off.

Commit scope is not what the lock scope suggests: while a policy lock is held the commit
must be issued at **pkg** scope. `/workspace/commit/pkg/<pkg>/firewall/policy/<id>` and
the plain ADOM commit both return 0 and save nothing -- the edit is discarded at unlock.

The probe writes only to the `comments` field of throwaway policies it creates itself in
a scratch package, and restores `per-policy-lock` to the value it found.

Usage
-----
    python per_policy_lock_probe.py --adom <scratch-adom> --package <scratch-package>
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

SAFE_PREFIX = "zz_probe_pol"
GLOBAL_URL = "/cli/global/system/global"
PER_POLICY_LOCK = "per-policy-lock"


def policy_url(adom, package, policyid=None):
    url = f"/pm/config/adom/{adom}/pkg/{package}/firewall/policy"
    return f"{url}/{policyid}" if policyid is not None else url


def workspace_url(adom, verb, package=None, policyid=None):
    url = f"/dvmdb/adom/{adom}/workspace/{verb}"
    if package:
        url = f"{url}/pkg/{package}"
    if policyid is not None:
        url = f"{url}/firewall/policy/{policyid}"
    return url


def read_per_policy_lock(fmg):
    status, response = fmg.get(url=GLOBAL_URL)
    if status != 0 or not isinstance(response, dict):
        raise RuntimeError(f"could not read {GLOBAL_URL}: status={status}")
    return response.get(PER_POLICY_LOCK)


def set_per_policy_lock(fmg, value):
    status, response = fmg.set(url=GLOBAL_URL, data={PER_POLICY_LOCK: value})
    if status != 0:
        raise RuntimeError(f"could not set {PER_POLICY_LOCK}={value}: "
                           f"status={status} {json.dumps(response)[:120]}")


def ensure_policies(fmg, adom, package):
    """Return two throwaway policy ids in the scratch package, creating them if needed."""
    status, existing = fmg.get(url=policy_url(adom, package))
    if status != 0:
        raise RuntimeError(f"could not list policies in {package}: status={status}")
    found = {entry.get("name"): entry.get("policyid")
             for entry in (existing or []) if isinstance(entry, dict)}
    wanted = [f"{SAFE_PREFIX}_a", f"{SAFE_PREFIX}_b"]
    missing = [name for name in wanted if name not in found]
    if missing:
        status, _ = fmg.execute(url=workspace_url(adom, "lock", package))
        if status != 0:
            raise RuntimeError(f"could not lock {package} to create probe policies: {status}")
        try:
            for name in missing:
                status, response = fmg.add(url=policy_url(adom, package), data={
                    "name": name, "srcintf": ["any"], "dstintf": ["any"],
                    "srcaddr": ["all"], "dstaddr": ["all"], "service": ["ALL"],
                    "schedule": ["always"], "action": 1})
                if status != 0:
                    raise RuntimeError(f"could not create {name}: {json.dumps(response)[:120]}")
                found[name] = response.get("policyid")
            fmg.execute(url=workspace_url(adom, "commit", package))
        finally:
            fmg.execute(url=workspace_url(adom, "unlock", package))
    return [found[name] for name in wanted]


def distinct_marker(fmg, adom, package, policyid, tag):
    """
    A comment value guaranteed to differ from what the policy already holds.

    Rewriting a field with the value it already has is accepted with status 0 even
    without the lock -- FMG has nothing to change, so it never reaches the permission
    check. Reusing a marker between arms therefore makes an unauthorised write look
    authorised, which is exactly how the first run of this probe misread the
    feature-disabled arm.
    """
    current = read_comment(fmg, adom, package, policyid)
    candidate = f"{SAFE_PREFIX}-{tag}-0"
    return candidate if candidate != current else f"{SAFE_PREFIX}-{tag}-1"


def read_comment(fmg, adom, package, policyid):
    status, response = fmg.get(url=policy_url(adom, package, policyid))
    if status != 0 or not isinstance(response, dict):
        return None
    return response.get("comments")


def single_session_arms(connect_args, adom, package, policies, results):
    """GRANTED / AUTHORISES / SCOPED, all from one session."""
    mine, other = policies
    with connect(*connect_args) as fmg:
        status, response = fmg.execute(url=workspace_url(adom, "lock", package, mine))
        results["GRANTED"] = (status == 0, f"status={status} {json.dumps(response)[:80]}")
        if status != 0:
            return
        try:
            marker = distinct_marker(fmg, adom, package, mine, "authorises")
            status, _ = fmg.update(url=policy_url(adom, package, mine),
                                   data={"comments": marker})
            wrote = status == 0
            denied_marker = distinct_marker(fmg, adom, package, other, "scoped")
            status, _ = fmg.update(url=policy_url(adom, package, other),
                                   data={"comments": denied_marker})
            results["SCOPED"] = (status != 0,
                                 f"write to the unlocked policy returned status={status}")
            # The commit that actually saves is at pkg scope; the policy-scoped commit
            # URL returns 0 and discards. Measured, not assumed -- see the docstring.
            fmg.execute(url=workspace_url(adom, "commit", package))
        finally:
            fmg.execute(url=workspace_url(adom, "unlock", package, mine))
        landed = read_comment(fmg, adom, package, mine) == marker
        results["AUTHORISES"] = (wrote and landed,
                                 f"rpc_ok={wrote} survived_unlock={landed}")


def concurrent_arm(connect_args, adom, package, policies, results, expect_writes=True):
    """Two sessions, two policies, one package."""
    first, second = policies
    with connect(*connect_args) as a, connect(*connect_args) as b:
        status_a, _ = a.execute(url=workspace_url(adom, "lock", package, first))
        status_b, _ = b.execute(url=workspace_url(adom, "lock", package, second))
        both_locked = status_a == 0 and status_b == 0
        marker_a = distinct_marker(a, adom, package, first, "concurrent-a")
        marker_b = distinct_marker(b, adom, package, second, "concurrent-b")
        write_a, _ = a.update(url=policy_url(adom, package, first), data={"comments": marker_a})
        write_b, _ = b.update(url=policy_url(adom, package, second), data={"comments": marker_b})
        a.execute(url=workspace_url(adom, "commit", package))
        b.execute(url=workspace_url(adom, "commit", package))
        a.execute(url=workspace_url(adom, "unlock", package, first))
        b.execute(url=workspace_url(adom, "unlock", package, second))
        landed = (read_comment(a, adom, package, first) == marker_a
                  and read_comment(a, adom, package, second) == marker_b)
        detail = (f"locks=({status_a},{status_b}) writes=({write_a},{write_b}) "
                  f"both_persisted={landed}")
        if expect_writes:
            results["CONCURRENT"] = (both_locked and landed, detail)
        else:
            # With the feature off, the hazard is that the locks are still GRANTED --
            # to both sessions at once -- while the writes they were meant to authorise
            # are refused. "yes" here means the hazard reproduced.
            results["FEATURE_OFF"] = (both_locked and write_a != 0 and not landed, detail)


def conflicts_arm(connect_args, adom, package, policies, results):
    """What a held policy lock excludes: the same policy, the package, the ADOM."""
    first, second = policies
    with connect(*connect_args) as a, connect(*connect_args) as b:
        if a.execute(url=workspace_url(adom, "lock", package, first))[0] != 0:
            return
        try:
            same = b.execute(url=workspace_url(adom, "lock", package, first))[0]
            pkg = b.execute(url=workspace_url(adom, "lock", package))[0]
            adom_lock = b.execute(url=workspace_url(adom, "lock"))[0]
            results["EXCLUDES"] = (
                same != 0 and pkg != 0 and adom_lock != 0,
                f"same_policy={same} pkg={pkg} adom={adom_lock}")
        finally:
            a.execute(url=workspace_url(adom, "unlock", package, first))


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--adom", required=True, help="scratch ADOM with workspace enabled")
    parser.add_argument("--package", required=True, help="scratch policy package")
    parser.add_argument("--address", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()

    connect_args = (args.address, args.username, args.password, args.api_key)
    results = {}
    with connect(*connect_args) as fmg:
        if not fmg._lock_ctx.uses_workspace:
            print("Workspace mode is DISABLED on this appliance; nothing to measure.")
            return 2
        original = read_per_policy_lock(fmg)
        policies = ensure_policies(fmg, args.adom, args.package)
    print(f"{PER_POLICY_LOCK} was {original}; probe policies are {policies}\n")

    try:
        with connect(*connect_args) as fmg:
            set_per_policy_lock(fmg, 1)
        single_session_arms(connect_args, args.adom, args.package, policies, results)
        concurrent_arm(connect_args, args.adom, args.package, policies, results)
        conflicts_arm(connect_args, args.adom, args.package, policies, results)

        with connect(*connect_args) as fmg:
            set_per_policy_lock(fmg, 0)
        concurrent_arm(connect_args, args.adom, args.package, policies, results,
                       expect_writes=False)
    finally:
        with connect(*connect_args) as fmg:
            set_per_policy_lock(fmg, original)
        print(f"restored {PER_POLICY_LOCK}={original}\n")

    for arm in ("GRANTED", "AUTHORISES", "SCOPED", "CONCURRENT", "EXCLUDES", "FEATURE_OFF"):
        ok, detail = results.get(arm, (None, "not run"))
        print(f"  {arm:<11} {'yes ' if ok else ('no  ' if ok is False else '?   ')} {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
