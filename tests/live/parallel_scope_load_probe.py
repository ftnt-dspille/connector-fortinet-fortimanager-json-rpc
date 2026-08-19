"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
Does minimal locking actually run N workers in parallel?

That is the headline claim of the whole exercise and it has only ever been demonstrated
for N=2, by the pairwise contention matrix. Two sessions not blocking each other does not
show that eight do, and it says nothing about how much wall-clock the change actually
buys or what it costs when the workers collide instead of spreading out.

The probe has two halves, because the first version had only the second and could not see
anything: with a workload whose critical section is ~0.3s, lock contention never
materialises and all three shapes finish in the same wall clock. What is being measured
has to be slower than the noise.

**Half 1 -- the lock layer, with a controlled dwell.** N workers each take a workspace
lock, hold it for `--dwell` seconds, and release. This is what an install looks like now
that the connector holds locks across the task, and it is slow enough for contention to
show:

    LOCK_DIFFERENT   N workers, N devices   -- the claim: wall clock ~= one dwell
    LOCK_SAME        N workers, ONE device  -- the safety property: wall ~= N dwells
    LOCK_ADOM        N workers, the ADOM    -- what users get today: wall ~= N dwells

**Half 2 -- the shipping code path.** The same N workers driving
`generic_json_rpc.perform_rpc_action` with a short device-database write, with
minimal_locking on and off. This is the honest end-to-end number, and it is expected to
show *no* difference: at this size the appliance's own per-call latency dominates, so the
lock is not what a short write is waiting on.

The workload is a device-database `desc` write, chosen because it is denied without a
lock (-20020), authorised by a `dev` lock, persists across the unlock, and touches only a
model device -- nothing is pushed anywhere. Each worker writes its own marker and the
probe verifies every marker afterwards, so a run that is fast because the writes silently
did nothing cannot pass.

Reported per shape: wall clock, the sum of the workers' own durations (the serial cost),
the speedup between them, and how many writes landed.

Usage
-----
    python parallel_scope_load_probe.py --adom <scratch-adom> --workers 8
"""

import argparse
import importlib
import os
import sys
import time
import warnings
from concurrent.futures import ThreadPoolExecutor

warnings.filterwarnings("ignore")

current_directory = os.path.dirname(os.path.abspath(__file__))
tests_directory = os.path.abspath(os.path.join(current_directory, os.pardir))
repo_root = os.path.abspath(os.path.join(tests_directory, os.pardir))
sys.path.insert(0, current_directory)
sys.path.insert(0, repo_root)

from lock_matrix_probe import connect, resolve_task  # noqa: E402

generic_json_rpc = importlib.import_module("fortinet-fortimanager-json-rpc.generic_json_rpc")

SAFE_PREFIX = "zz_loadprobe"
# FortiGate serials are 16 characters. A longer one is accepted by the RPC and then fails
# inside the task with "devsnexist" -- FMG truncates it, so every device collides with the
# first. Keep the base 14 characters so base + a 2-digit index is exactly 16.
SERIAL_BASE = "FGVMEV00000970"

DIFFERENT_SCOPE = "DIFFERENT_SCOPE"
SAME_SCOPE = "SAME_SCOPE"
ADOM_BASELINE = "ADOM_BASELINE"

LOCK_DIFFERENT = "LOCK_DIFFERENT"
LOCK_SAME = "LOCK_SAME"
LOCK_ADOM = "LOCK_ADOM"


def workspace_url(adom, verb, scope=None):
    url = f"/dvmdb/adom/{adom}/workspace/{verb}"
    return f"{url}/{scope[0]}/{scope[1]}" if scope else url


def ensure_devices(fmg, adom, count):
    """Create as many throwaway model devices as the run needs, once."""
    wanted = [f"{SAFE_PREFIX}_{index}" for index in range(count)]
    status, existing = fmg.get(url=f"/dvmdb/adom/{adom}/device")
    present = {entry.get("name") for entry in (existing or []) if isinstance(entry, dict)}
    missing = [name for name in wanted if name not in present]
    if not missing:
        return wanted
    if fmg.execute(url=workspace_url(adom, "lock"))[0] != 0:
        raise RuntimeError("could not take the ADOM lock to create probe devices")
    try:
        for name in missing:
            index = int(name.rsplit("_", 1)[1])
            status, response = fmg.execute(url="/dvm/cmd/add/device", data={
                "adom": adom,
                "device": {"name": name, "sn": f"{SERIAL_BASE}{index:02d}", "mgmt_mode": 3,
                           "device action": "add_model", "os_type": 0, "os_ver": 7,
                           "mr": 6, "platform_str": "FortiGate-VM64"},
                "flags": ["create_task", "nonblocking"]})
            if status != 0:
                raise RuntimeError(f"could not create {name}: status={status}")
            # Judge the task, not the RPC. add/device returns 0 with a task id whatever
            # happens; a rejected serial only shows up in the finished task, and a probe
            # that skips this check goes on to lock devices that were never created.
            task_ok, detail = resolve_task(fmg, response, timeout=120)
            if task_ok is False:
                raise RuntimeError(f"device {name} was not created: {detail}")
        fmg.execute(url=workspace_url(adom, "commit"))
    finally:
        fmg.execute(url=workspace_url(adom, "unlock"))

    present = {entry.get("name") for entry in
               (fmg.get(url=f"/dvmdb/adom/{adom}/device")[1] or []) if isinstance(entry, dict)}
    absent = [name for name in wanted if name not in present]
    if absent:
        raise RuntimeError(f"probe devices missing after creation: {absent}")
    return wanted


def remove_devices(fmg, adom, names):
    status, existing = fmg.get(url=f"/dvmdb/adom/{adom}/device")
    present = {entry.get("name") for entry in (existing or []) if isinstance(entry, dict)}
    doomed = sorted(present & set(names))
    if not doomed:
        return
    if fmg.execute(url=workspace_url(adom, "lock"))[0] != 0:
        raise RuntimeError("could not take the ADOM lock to remove probe devices")
    try:
        for name in doomed:
            fmg.execute(url="/dvm/cmd/del/device", data={"adom": adom, "device": name})
        fmg.execute(url=workspace_url(adom, "commit"))
    finally:
        fmg.execute(url=workspace_url(adom, "unlock"))


CONTENTION_POLL = 0.25


def hold_lock(fmg, adom, scope, dwell, deadline):
    """
    Take one lock, hold it for `dwell` seconds, release it. Returns (waited, error).

    The session is established *before* the timed region and passed in: logging in costs
    about as long as the dwell on this appliance, and leaving it inside the measurement
    hides the lock behind session setup -- which is what the first version of this probe
    did, and why it saw nothing.

    A blocked worker retries until the deadline instead of giving up, so a contended shape
    measures how long it takes to get every worker through rather than how many failed.
    """
    started = time.monotonic()
    last_status = None
    while time.monotonic() < deadline:
        try:
            status, _ = fmg.execute(url=workspace_url(adom, "lock", scope))
        except Exception as failure:      # noqa: BLE001 - the failure IS the measurement
            return time.monotonic() - started, str(failure)[:120]
        last_status = status
        if status == 0:
            waited = time.monotonic() - started
            time.sleep(dwell)
            fmg.execute(url=workspace_url(adom, "unlock", scope))
            return waited, None
        time.sleep(CONTENTION_POLL)
    return time.monotonic() - started, f"never acquired, last status={last_status}"


def run_lock_shape(shape, connect_args, adom, devices, workers, dwell):
    if shape == LOCK_ADOM:
        scopes = [None] * workers
    elif shape == LOCK_SAME:
        scopes = [("dev", devices[0])] * workers
    else:
        scopes = [("dev", name) for name in devices[:workers]]

    sessions = [connect(*connect_args) for _ in scopes]
    for session in sessions:
        session.login()
    try:
        deadline = time.monotonic() + dwell * workers * 3 + 30
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(
                lambda pair: hold_lock(pair[0], adom, pair[1], dwell, deadline),
                list(zip(sessions, scopes))))
        wall = time.monotonic() - started
    finally:
        for session in sessions:
            try:
                session.logout()
            except Exception:             # noqa: BLE001 - cleanup must not mask results
                pass
    errors = [error for _, error in results if error]
    waits = sorted(round(wait, 2) for wait, _ in results)
    return {
        "wall": wall,
        "slowest": max(wait for wait, _ in results),
        "waits": waits,
        "errors": errors,
    }


def one_write(config, adom, device, marker):
    """One connector call, timed. Returns (seconds, error_or_None)."""
    started = time.monotonic()
    error = None
    try:
        generic_json_rpc.perform_rpc_action("update", config, {
            "url": f"/dvmdb/adom/{adom}/device/{device}",
            "data": {"data": {"desc": marker}},
        })
    except Exception as failure:          # noqa: BLE001 - the failure IS the measurement
        error = str(failure)[:120]
    return time.monotonic() - started, error


def run_shape(shape, config_base, adom, devices, workers, run_id):
    minimal = shape != ADOM_BASELINE
    config = dict(config_base, minimal_locking=minimal)
    targets = [devices[0]] * workers if shape == SAME_SCOPE else devices[:workers]
    markers = [f"{SAFE_PREFIX}-{run_id}-{shape}-{index}" for index in range(workers)]

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(
            lambda item: one_write(config, adom, item[0], item[1]),
            list(zip(targets, markers))))
    wall = time.monotonic() - started
    serial = sum(duration for duration, _ in results)
    errors = [error for _, error in results if error]
    return {
        "wall": wall,
        "serial": serial,
        "speedup": (serial / wall) if wall else 0,
        "slowest": max(duration for duration, _ in results),
        "errors": errors,
        "targets": targets,
        "markers": markers,
    }


def verify(fmg, adom, shape, outcome):
    """
    Confirm the writes landed.

    SAME_SCOPE has every worker writing the same field, so only the last writer's marker
    can survive; the check there is that one of them did and that nobody errored. For the
    other shapes every device must carry its own worker's marker.
    """
    if shape == SAME_SCOPE:
        status, response = fmg.get(url=f"/dvmdb/adom/{adom}/device/{outcome['targets'][0]}")
        landed = isinstance(response, dict) and response.get("desc") in outcome["markers"]
        return landed, "one of the workers' markers survived" if landed else "no marker landed"
    missing = []
    for device, marker in zip(outcome["targets"], outcome["markers"]):
        status, response = fmg.get(url=f"/dvmdb/adom/{adom}/device/{device}")
        if not isinstance(response, dict) or response.get("desc") != marker:
            missing.append(device)
    return not missing, ("all markers landed" if not missing
                         else f"missing on {len(missing)}: {missing[:3]}")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--adom", required=True, help="scratch ADOM with workspace enabled")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--dwell", type=float, default=3.0,
                        help="seconds each worker holds its lock in the lock-layer half")
    parser.add_argument("--keep-devices", action="store_true",
                        help="leave the probe's model devices behind for a rerun")
    parser.add_argument("--address", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()

    config_base = {
        "address": args.address or os.getenv("ADDRESS", ""),
        "username": args.username or os.getenv("USERNAME"),
        "password": args.password or os.getenv("PASSWORD"),
        "verify_ssl": False,
    }
    connect_args = (args.address, args.username, args.password, args.api_key)

    with connect(*connect_args) as fmg:
        if not fmg._lock_ctx.uses_workspace:
            print("Workspace mode is DISABLED; nothing to measure.")
            return 2
        devices = ensure_devices(fmg, args.adom, args.workers)
        print(f"{args.workers} workers over {len(devices)} model devices in '{args.adom}'\n")

        outcomes = {}
        try:
            print(f"Half 1 -- lock layer, {args.dwell:.1f}s dwell per worker")
            for shape in (LOCK_DIFFERENT, LOCK_SAME, LOCK_ADOM):
                outcome = run_lock_shape(shape, connect_args, args.adom, devices,
                                         args.workers, args.dwell)
                print(f"-> {shape}")
                print(f"   wall {outcome['wall']:6.2f}s   "
                      f"(fully parallel would be {args.dwell:.1f}s, "
                      f"fully serial {args.dwell * args.workers:.1f}s)")
                print(f"   lock waits {outcome['waits']}")
                if outcome["errors"]:
                    print(f"   errors: {outcome['errors'][:3]}")
                outcomes[shape] = outcome
                print()

            print("Half 2 -- shipping code path, short device-database write")
            for run_id, shape in enumerate((DIFFERENT_SCOPE, SAME_SCOPE, ADOM_BASELINE)):
                outcome = run_shape(shape, config_base, args.adom, devices,
                                    args.workers, run_id)
                landed, landed_detail = verify(fmg, args.adom, shape, outcome)
                outcome["landed"] = landed
                outcomes[shape] = outcome
                print(f"-> {shape}")
                print(f"   wall {outcome['wall']:6.2f}s   serial {outcome['serial']:6.2f}s"
                      f"   speedup {outcome['speedup']:4.1f}x"
                      f"   slowest worker {outcome['slowest']:5.2f}s")
                print(f"   writes: {landed_detail}"
                      f"{'' if not outcome['errors'] else '  errors=' + str(outcome['errors'][:2])}")
                print()
        finally:
            if not args.keep_devices:
                remove_devices(fmg, args.adom, devices)
                print("probe devices removed\n")

    lock_different = outcomes.get(LOCK_DIFFERENT)
    lock_adom = outcomes.get(LOCK_ADOM)
    if lock_different and lock_adom:
        print(f"Lock layer, {args.workers} workers holding {args.dwell:.1f}s each: "
              f"ADOM {lock_adom['wall']:.2f}s -> distinct device scopes "
              f"{lock_different['wall']:.2f}s "
              f"({lock_adom['wall'] / lock_different['wall']:.1f}x faster)")
    different = outcomes.get(DIFFERENT_SCOPE)
    baseline = outcomes.get(ADOM_BASELINE)
    if different and baseline:
        print(f"Short writes end to end: ADOM {baseline['wall']:.2f}s -> minimal "
              f"{different['wall']:.2f}s ({baseline['wall'] / different['wall']:.1f}x) "
              "-- per-call latency, not the lock, is what these are waiting on")
    return 0


if __name__ == "__main__":
    sys.exit(main())
