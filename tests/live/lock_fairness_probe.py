"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
Is the connector's own lock retry fair, and what does its backoff cost?

Everything measured so far asked whether a lock is *needed* or whether distinct scopes
run in *parallel*. This asks the opposite question: when N workers genuinely want the
same lock, what happens to them? The retry loop is `MAX_RETRY_LIMIT = 1500` attempts of
`random.randint(1, 10)` seconds -- a ~2.3 hour budget with no queue, no fairness
guarantee, and no memory of how long a worker has already waited. Nothing stops one
worker from being passed over repeatedly while later arrivals win the race.

Two arms, because a slow or unfair result has two possible authors and they need
separating:

    CONNECTOR   workers acquire through generic_json_rpc.lock_adom -- the shipped
                randint(1, 10) backoff
    TIGHT       identical workers polling the same lock every 0.25s -- the control

TIGHT is what the *appliance* does when asked repeatedly: if it hands the lock out in
arrival order, waits there rise in a clean staircase and the lock server is fair. Any
extra spread in CONNECTOR on top of that is charged to our backoff, not to FMG.

Two numbers matter. **Overshoot**: a worker that is Kth to acquire could not have waited
less than K * dwell, so wait / (K * dwell) is time the backoff wasted sleeping past an
already-free lock. **Spread**: slowest wait over median wait, which is what starvation
looks like when it is real.

The workload is a bare lock/hold/unlock rather than a write, because the question is
about the acquisition path only; the parallel load probe already covers what happens
around it.

Usage
-----
    python lock_fairness_probe.py --adom <scratch-adom> --workers 6 --dwell 3
"""

import argparse
import importlib
import os
import statistics
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

from lock_matrix_probe import connect  # noqa: E402

generic_json_rpc = importlib.import_module("fortinet-fortimanager-json-rpc.generic_json_rpc")

CONNECTOR = "CONNECTOR"
TIGHT = "TIGHT"
TIGHT_POLL = 0.25


def workspace_url(adom, verb):
    return f"/dvmdb/adom/{adom}/workspace/{verb}"


def acquire_connector(fmg, adom):
    """The shipped path. Returns True once the lock is held."""
    return generic_json_rpc.lock_adom(fmg, adom, workspace_url(adom, "lock"), None)


def acquire_tight(fmg, adom, deadline):
    """The control: same lock, same contention, no backoff."""
    while time.monotonic() < deadline:
        if fmg.execute(url=workspace_url(adom, "lock"))[0] == 0:
            return True
        time.sleep(TIGHT_POLL)
    return False


def worker(arm, fmg, adom, dwell, origin, deadline):
    """
    Take the contended lock, hold it for `dwell`, release it.

    Returns the wait, the moment the lock was granted (relative to the shared start, so
    acquisition *order* can be recovered), and any error. Sessions are established before
    the timed region by the caller -- login costs about as much as a dwell here, and
    inside the measurement it would hide the thing being measured.
    """
    started = time.monotonic()
    try:
        if arm == CONNECTOR:
            acquired = acquire_connector(fmg, adom)
        else:
            acquired = acquire_tight(fmg, adom, deadline)
    except Exception as failure:          # noqa: BLE001 - the failure IS the measurement
        return {"wait": time.monotonic() - started, "granted": None,
                "error": str(failure)[:120]}
    waited = time.monotonic() - started
    if not acquired:
        return {"wait": waited, "granted": None, "error": "never acquired"}
    granted = time.monotonic() - origin
    time.sleep(dwell)
    fmg.execute(url=workspace_url(adom, "unlock"))
    return {"wait": waited, "granted": granted, "error": None}


def run_arm(arm, connect_args, adom, workers, dwell):
    sessions = [connect(*connect_args) for _ in range(workers)]
    for session in sessions:
        session.login()
    try:
        origin = time.monotonic()
        deadline = origin + dwell * workers * 6 + 60
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(
                lambda session: worker(arm, session, adom, dwell, origin, deadline),
                sessions))
        wall = time.monotonic() - origin
    finally:
        for session in sessions:
            try:
                session.logout()
            except Exception:             # noqa: BLE001 - cleanup must not mask results
                pass
    return summarise(results, wall, workers, dwell)


def summarise(results, wall, workers, dwell):
    """
    Turn raw waits into the two numbers that answer the question.

    Overshoot needs acquisition *order*, not worker identity: the Kth worker to be granted
    the lock could not have started before K * dwell no matter how good the backoff was,
    so that is the floor its wait is measured against. Averaging the per-worker ratios
    keeps one unlucky worker from being hidden by the lucky ones.
    """
    ok = [entry for entry in results if entry["error"] is None]
    errors = [entry["error"] for entry in results if entry["error"]]
    if not ok:
        return {"wall": wall, "waits": [], "errors": errors, "spread": None,
                "overshoot": None, "order": []}

    ordered = sorted(ok, key=lambda entry: entry["granted"])
    overshoots = []
    for position, entry in enumerate(ordered):
        floor = position * dwell
        if floor > 0:
            overshoots.append(entry["wait"] / floor)

    waits = sorted(entry["wait"] for entry in ok)
    median = statistics.median(waits)
    return {
        "wall": wall,
        "waits": [round(value, 2) for value in waits],
        "median": median,
        "slowest": waits[-1],
        "spread": (waits[-1] / median) if median else None,
        "overshoot": (statistics.mean(overshoots) if overshoots else None),
        "worst_overshoot": (max(overshoots) if overshoots else None),
        "order": [round(entry["granted"], 2) for entry in ordered],
        "errors": errors,
    }


def report(arm, outcome, workers, dwell):
    ideal = dwell * workers
    print(f"-> {arm}")
    print(f"   wall {outcome['wall']:6.2f}s   (a perfectly fair queue would be "
          f"{ideal:.1f}s for {workers} workers x {dwell:.1f}s)")
    print(f"   waits          {outcome['waits']}")
    print(f"   granted at     {outcome['order']}")
    if outcome["spread"] is not None:
        print(f"   spread         {outcome['spread']:.2f}x  (slowest {outcome['slowest']:.2f}s "
              f"vs median {outcome['median']:.2f}s)")
    if outcome["overshoot"] is not None:
        print(f"   overshoot      {outcome['overshoot']:.2f}x mean, "
              f"{outcome['worst_overshoot']:.2f}x worst  "
              f"(1.00x = acquired the instant the lock came free)")
    if outcome["errors"]:
        print(f"   errors: {outcome['errors'][:3]}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--adom", required=True, help="scratch ADOM with workspace enabled")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--dwell", type=float, default=3.0,
                        help="seconds each worker holds the lock once it has it")
    parser.add_argument("--address", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()

    connect_args = (args.address, args.username, args.password, args.api_key)

    with connect(*connect_args) as fmg:
        if not fmg._lock_ctx.uses_workspace:
            print("Workspace mode is DISABLED; nothing to measure.")
            return 2
        # A lock left behind by an earlier run would make every worker in the first arm
        # wait on a holder that is not part of the measurement.
        status, held = fmg.get(url=workspace_url(args.adom, "lockinfo"))
        if isinstance(held, dict) and held.get("lock_user"):
            print(f"ADOM '{args.adom}' is already locked by {held.get('lock_user')!r}; "
                  f"release it before measuring.")
            return 2

    print(f"{args.workers} workers contending for the ADOM lock on '{args.adom}', "
          f"{args.dwell:.1f}s dwell each\n")

    outcomes = {}
    for arm in (TIGHT, CONNECTOR):
        outcomes[arm] = run_arm(arm, connect_args, args.adom, args.workers, args.dwell)
        report(arm, outcomes[arm], args.workers, args.dwell)

    tight, connector = outcomes[TIGHT], outcomes[CONNECTOR]
    if tight["overshoot"] and connector["overshoot"]:
        print(f"Backoff cost: {connector['wall'] / tight['wall']:.2f}x the wall clock of "
              f"the same contention polled tightly.")
        if connector["spread"] and tight["spread"]:
            print(f"Fairness: spread {connector['spread']:.2f}x vs {tight['spread']:.2f}x "
                  f"tight -- the appliance's own ordering is the {tight['spread']:.2f}x.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
