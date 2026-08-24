"""Sweep `execute` URLs that only read, looking for more over-locking.

`needs_lock` in the connector exempts the `get` action, not read-only work. An
`execute` URL whose payload carries an `adom` therefore resolves a lockable ADOM and
takes its lock to run a read -- which is not merely wasteful: measured on `/um/image/
list/ext`, the lock was the *only* reason the read could fail, because the call itself
succeeds fine while another session holds the ADOM.

This probe hunts for further instances of that class. For each candidate URL it runs
three arms:

    REACHABLE   called unlocked, with an adom in the payload. Does the URL exist and
                does it answer? -6/-9/-10 means untestable, not cleared.
    FREE        called unlocked while nothing holds the ADOM lock.
    CONTENDED   called unlocked while a *second session* holds the ADOM lock.

A URL belongs in NO_LOCK_URLS when CONTENDED still returns real data: the appliance is
telling us the read needs no lock, so the connector taking one can only ever subtract
availability.

Only read-shaped URLs are listed below. Anything that installs, aborts, cancels, or
upgrades is deliberately absent -- `/um/image/upgrade/path` in particular reads like a
planner but starts a real upgrade.

Usage:
    python readonly_exec_sweep_probe.py --address <fmg> --username <u> --password <p> \
        --adom <scratch-adom>
"""
import argparse
import os
import sys

current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_directory)

from lock_matrix_probe import connect  # noqa: E402

# (url, payload) -- payload always carries `adom`, which is what makes
# parse_adom_from_input resolve a lockable ADOM and is therefore the trigger condition.
CANDIDATES = [
    ("/securityconsole/package/status", {"adom": None, "pkg": None}),
    ("/securityconsole/package/status", {"adom": None}),
    ("/securityconsole/preview/result", {"adom": None, "device": None}),
    ("/um/image/list", {"adom": None}),
    ("/um/image/upgrade/status", {"adom": None}),
    ("/um/device/list", {"adom": None}),
    ("/um/image/version/list/ext", {"adom": None}),
]

# Statuses that mean "this URL/payload shape is not testable", as opposed to a real
# refusal. -6 invalid URL, -9 invalid command, -10 data invalid for URL, -11 no permission.
UNTESTABLE = {-6, -9, -10, -11}


def looks_like_data(resp):
    """A response carrying more than a bare status echo."""
    if isinstance(resp, list):
        return len(resp) > 0
    if isinstance(resp, dict):
        return any(k not in ("status", "url") for k in resp)
    return resp is not None


def run_arm(fmg, url, payload):
    try:
        status, resp = fmg.execute(url, **payload)
    except Exception as e:  # noqa: BLE001 - probe reports, never raises
        return None, f"EXC {type(e).__name__}: {e}"
    return status, resp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--address")
    ap.add_argument("--username")
    ap.add_argument("--password")
    ap.add_argument("--adom", required=True, help="scratch ADOM with workspace enabled")
    args = ap.parse_args()

    worker = connect(args.address, args.username, args.password)
    worker.login()
    holder = connect(args.address, args.username, args.password)
    holder.login()

    # Refuse to measure against a dirty starting state.
    status, info = worker.get(f"/dvmdb/adom/{args.adom}/workspace/lockinfo")
    if status == 0 and isinstance(info, list) and info and info[0].get("lock_sid"):
        sys.exit(f"ADOM {args.adom} is already locked ({info[0]}); rerun when it is free")

    results = []
    for url, shape in CANDIDATES:
        payload = {k: (args.adom if k == "adom" else v) for k, v in shape.items()}
        payload = {k: v for k, v in payload.items() if v is not None}
        label = f"{url} {sorted(payload)}"

        st_free, resp_free = run_arm(worker, url, payload)
        if st_free in UNTESTABLE:
            results.append((label, st_free, "UNTESTABLE", "URL/payload rejected; not cleared"))
            print(f"[skip] {label}: status={st_free}")
            continue

        st_lock, _ = holder.execute(f"/dvmdb/adom/{args.adom}/workspace/lock")
        if st_lock != 0:
            sys.exit(f"could not take the ADOM lock for the contended arm: {st_lock}")
        try:
            st_cont, resp_cont = run_arm(worker, url, payload)
        finally:
            holder.execute(f"/dvmdb/adom/{args.adom}/workspace/unlock")

        if st_cont == 0 and looks_like_data(resp_cont):
            verdict, note = "NO_LOCK_NEEDED", "reads fine while ADOM is held -- belongs in NO_LOCK_URLS"
        elif st_cont == 0:
            verdict, note = "OK_BUT_EMPTY", "status 0 but no payload; inconclusive"
        else:
            verdict, note = "NEEDS_LOCK_OR_FAILS", f"contended status={st_cont}"
        results.append((label, st_free, verdict, note))
        print(f"[{verdict}] {label}: free={st_free} contended={st_cont}")

    print("\n=== summary ===")
    for label, st_free, verdict, note in results:
        print(f"{verdict:20} free={str(st_free):5} {label}\n{'':21}{note}")

    worker.logout()
    holder.logout()


if __name__ == "__main__":
    main()
