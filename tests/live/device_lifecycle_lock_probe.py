"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
What does device onboarding lock, and can it be narrowed?

ZTP onboarding hits device registration before it touches a package, so if that call can
only be ADOM-locked it is the real serialisation point for the whole pack -- every worker
onboarding a device queues behind every other, no matter how narrow the connector's later
locks get. Sections A-J narrowed installs and script execution; this is the one class in
front of them that was never measured.

Cases:

    add/device      one model device via /dvm/cmd/add/device
    add/dev-list    two model devices in one /dvm/cmd/add/dev-list call
    del/device      the matching teardown, /dvm/cmd/del/device

Arms per case:

    NONE   no lock at all
    DEV    a dev/<name> lock for the device being added -- the question this probe
           exists to answer: can a device scope exist before the device does?
    ADOM   the ADOM lock, held until the queued task finishes

Judged on the finished task AND on whether the device is actually in `/dvmdb/adom/{adom}/
device` afterwards, never on the RPC status: add/device returns 0 with a task id, and
del/device returns 0 with no task at all.

Everything runs on throwaway model devices (SAFE_PREFIX names, reserved serials) in a
scratch ADOM. Model devices are inert: nothing is pushed to any real appliance. Each arm
deletes what it created before the next one runs, so an arm cannot pass by finding a
device an earlier arm left behind.

Usage
-----
    python device_lifecycle_lock_probe.py --adom <scratch-adom>
"""

import argparse
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")

current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_directory)

from lock_matrix_probe import connect, resolve_task  # noqa: E402

SAFE_PREFIX = "zz_addprobe"
# Serials in a range no real appliance uses, so a probe device can never collide with a
# device someone actually owns.
SERIAL_BASE = "FGVMEV000009800"

NONE = "NONE"
DEV = "DEV"
ADOM = "ADOM"

REQUIRED = "REQUIRED"
NOT_NEEDED = "NOT_NEEDED"
ADOM_ONLY = "ADOM_ONLY"
INCONCLUSIVE = "INCONCLUSIVE"


def workspace_url(adom, verb, scope=None):
    url = f"/dvmdb/adom/{adom}/workspace/{verb}"
    return f"{url}/{scope[0]}/{scope[1]}" if scope else url


def model_device(index):
    return {
        "name": f"{SAFE_PREFIX}_{index}",
        "sn": f"{SERIAL_BASE}{index}",
        "mgmt_mode": 3,
        "device action": "add_model",
        "os_type": 0,
        "os_ver": 7,
        "mr": 6,
        "platform_str": "FortiGate-VM64",
    }


def device_names(fmg, adom):
    status, response = fmg.get(url=f"/dvmdb/adom/{adom}/device")
    if status != 0 or not isinstance(response, list):
        return set()
    return {entry.get("name") for entry in response if isinstance(entry, dict)}


def remove_devices(fmg, adom, names):
    """Delete probe devices under the ADOM lock, so each arm starts from nothing."""
    present = device_names(fmg, adom) & set(names)
    if not present:
        return
    if fmg.execute(url=workspace_url(adom, "lock"))[0] != 0:
        raise RuntimeError("could not take the ADOM lock to clean up probe devices")
    try:
        for name in sorted(present):
            fmg.execute(url="/dvm/cmd/del/device", data={"adom": adom, "device": name})
        fmg.execute(url=workspace_url(adom, "commit"))
    finally:
        fmg.execute(url=workspace_url(adom, "unlock"))


class Case:
    def __init__(self, name, url, payload, devices, expect_present, notes=""):
        self.name = name
        self.url = url
        self.payload = payload
        self.devices = devices          # names this case operates on
        self.expect_present = expect_present   # True for add, False for del
        self.notes = notes


def build_cases(adom):
    return [
        Case("add/device", "/dvm/cmd/add/device",
             {"adom": adom, "device": model_device(1),
              "flags": ["create_task", "nonblocking"]},
             [f"{SAFE_PREFIX}_1"], True,
             "single model device -- the ZTP onboarding call"),
        Case("add/dev-list", "/dvm/cmd/add/dev-list",
             {"adom": adom, "add-dev-list": [model_device(2), model_device(3)],
              "flags": ["create_task", "nonblocking"]},
             [f"{SAFE_PREFIX}_2", f"{SAFE_PREFIX}_3"], True,
             "bulk registration; two devices in one call"),
        Case("del/device", "/dvm/cmd/del/device",
             {"adom": adom, "device": f"{SAFE_PREFIX}_1"},
             [f"{SAFE_PREFIX}_1"], False,
             "teardown; returns 0 with no task, so only existence tells the truth"),
    ]


def prepare(fmg, adom, case):
    """Put the ADOM in the state the case needs before an arm runs."""
    if case.expect_present:
        remove_devices(fmg, adom, case.devices)
    else:
        # A delete case needs something to delete.
        remove_devices(fmg, adom, case.devices)
        if fmg.execute(url=workspace_url(adom, "lock"))[0] != 0:
            raise RuntimeError("could not take the ADOM lock to stage a device")
        try:
            status, response = fmg.execute(url="/dvm/cmd/add/device", data={
                "adom": adom, "device": model_device(1),
                "flags": ["create_task", "nonblocking"]})
            if status != 0:
                raise RuntimeError(f"could not stage a device: {json.dumps(response)[:120]}")
            resolve_task(fmg, response, timeout=120)
            fmg.execute(url=workspace_url(adom, "commit"))
        finally:
            fmg.execute(url=workspace_url(adom, "unlock"))


def run_arm(case, adom, arm, connect_args, watcher, timeout):
    scope = ("dev", case.devices[0]) if arm == DEV else None
    with connect(*connect_args) as fmg:
        if arm != NONE:
            status, response = fmg.execute(url=workspace_url(adom, "lock", scope))
            if status != 0:
                return False, f"lock refused: status={status} {json.dumps(response)[:90]}"
        try:
            status, response = fmg.execute(url=case.url, data=dict(case.payload))
            if status != 0:
                return False, f"rpc status={status} {json.dumps(response)[:90]}"
            task_ok, detail = resolve_task(fmg, response, timeout=timeout)
            if arm != NONE:
                fmg.execute(url=workspace_url(adom, "commit", scope))
        finally:
            if arm != NONE:
                fmg.execute(url=workspace_url(adom, "unlock", scope))

    present = device_names(watcher, adom)
    landed = all((name in present) == case.expect_present for name in case.devices)
    task_note = detail if task_ok is not None else "no task queued"
    return (task_ok is not False) and landed, f"{task_note} landed={landed}"


def classify(results):
    none_ok = results.get(NONE, (None,))[0]
    adom_ok = results.get(ADOM, (None,))[0]
    dev_ok = results.get(DEV, (None,))[0]
    if not adom_ok:
        return INCONCLUSIVE
    if none_ok:
        return NOT_NEEDED
    return ADOM_ONLY if not dev_ok else REQUIRED


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--adom", required=True, help="scratch ADOM with workspace enabled")
    parser.add_argument("--only", default="", help="substring filter on case name")
    parser.add_argument("--task-timeout", type=int, default=120)
    parser.add_argument("--address", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()

    cases = build_cases(args.adom)
    if args.only:
        cases = [c for c in cases if args.only.lower() in c.name.lower()]

    connect_args = (args.address, args.username, args.password, args.api_key)
    verdicts = []
    with connect(*connect_args) as watcher:
        if not watcher._lock_ctx.uses_workspace:
            print("Workspace mode is DISABLED; this probe cannot tell anything apart.")
            return 2
        all_probe_devices = sorted({name for case in build_cases(args.adom)
                                    for name in case.devices})
        try:
            for case in cases:
                print(f"-> {case.name}  ({case.notes})")
                results = {}
                for arm in (NONE, DEV, ADOM):
                    prepare(watcher, args.adom, case)
                    ok, detail = run_arm(case, args.adom, arm, connect_args,
                                         watcher, args.task_timeout)
                    results[arm] = (ok, detail)
                    print(f"   {arm:<5} {'OK  ' if ok else 'FAIL'} {detail}")
                verdict = classify(results)
                verdicts.append((case.name, verdict))
                print()
        finally:
            remove_devices(watcher, args.adom, all_probe_devices)
            print("probe devices removed\n")

    print("Verdicts")
    for name, verdict in verdicts:
        print(f"  {name:<14} {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
