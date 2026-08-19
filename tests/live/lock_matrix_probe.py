"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
Empirical workspace-lock necessity probe for a live FortiManager.

The connector currently decides whether to take a workspace lock from a hand-maintained
guess (`NO_LOCK_URLS` plus "anything that isn't a get"). This probe replaces the guess
with evidence: for every candidate operation it runs a two-arm experiment against a live
appliance and classifies the result.

    Arm A  perform the operation with NO workspace lock held
    Arm B  perform the same operation WITH the appropriate lock held

    A ok   / B ok    -> NOT_NEEDED   locking is pure overhead; candidate for NO_LOCK_URLS
    A fail / B ok    -> REQUIRED     the lock is what makes it work; must stay locked
    A ok   / B fail  -> LOCK_HARMFUL holding a lock breaks it; MUST be in NO_LOCK_URLS
    A fail / B fail  -> INCONCLUSIVE operation or environment problem, not a lock question

Only the LOCK_HARMFUL and NOT_NEEDED rows justify adding a URL to NO_LOCK_URLS, and only
REQUIRED rows justify paying for a lock.

Safety
------
Every write goes to throwaway objects prefixed with SAFE_PREFIX and is deleted afterwards.
Operations that push configuration to real managed FortiGates (install/device,
install/package, and script execution against a live device) are gated behind
--allow-device-push and are skipped by default, because those change real firewalls.

Note that these interact: a device-database script edits the device copy held in FMG,
and the install/device probe then pushes that copy to the actual FortiGate. The
device-database script therefore rewrites the device's existing hostname rather than
setting one of its own, so the push is a no-op.

Usage
-----
    python lock_matrix_probe.py --list                 # show the probe plan, touch nothing
    python lock_matrix_probe.py --adom root            # run read-safe + ADOM-DB write probes
    python lock_matrix_probe.py --adom root --allow-device-push   # include device-facing probes
"""

import argparse
import json
import re
import os
import sys
import time
import warnings

from dotenv import load_dotenv

warnings.filterwarnings("ignore")

current_directory = os.path.dirname(os.path.abspath(__file__))
tests_directory = os.path.abspath(os.path.join(current_directory, os.pardir))
repo_root = os.path.abspath(os.path.join(tests_directory, os.pardir))
sys.path.insert(0, repo_root)
load_dotenv(dotenv_path=os.path.join(tests_directory, ".env"))

from pyFMG.fortimgr import FortiManager  # noqa: E402

SAFE_PREFIX = "zz_lockprobe"

# Numeric enums for /dvmdb/adom/{adom}/script, read from the appliance's own syntax.
# FMG rejects the string labels here with -6, but only once you hold a lock: without
# one it fails on permission first and never validates the payload, which makes a bad
# payload look like a locking result. Keep these numeric.
SCRIPT_TYPE_CLI = 1
TARGET_DEVICE_DATABASE = 0
TARGET_REMOTE_DEVICE = 1
TARGET_ADOM_DATABASE = 2

# FMG status codes that mean "you did not hold the lock you needed".
# -10147 is what a workspace-protected write actually returns; confirmed on 7.6.
LOCK_DENIED_CODES = {-10147, -11, -3}
LOCK_DENIED_HINTS = ("no permission", "locked", "workspace", "read-only", "no write")

NOT_NEEDED = "NOT_NEEDED"
REQUIRED = "REQUIRED"
LOCK_HARMFUL = "LOCK_HARMFUL"
INCONCLUSIVE = "INCONCLUSIVE"
LOCK_IRRELEVANT = "LOCK_IRRELEVANT"


def connect(address=None, username=None, password=None, api_key=None):
    """Connect to the appliance, letting CLI flags override anything in .env."""
    address = address or os.getenv("ADDRESS") or ""
    address = address.replace("https://", "").replace("http://", "").strip("/")
    port = os.getenv("PORT")
    if port and port not in ("443", 443) and ":" not in address:
        address = f"{address}:{port}"
    verify_ssl = (os.getenv("VERIFY_SSL", "False").lower() in ("true", "1", "t"))
    if not (username or password):
        api_key = api_key or os.getenv("API_KEY")
    if api_key and not (username or password):
        return FortiManager(address, apikey=api_key, verify_ssl=verify_ssl,
                            disable_request_warnings=True)
    return FortiManager(
        address,
        username or os.getenv("USERNAME"),
        password or os.getenv("PASSWORD"),
        verify_ssl=verify_ssl,
        disable_request_warnings=True,
    )


# FMG task states. A task that reaches 5 has failed even though the RPC that
# created it returned 0.
TASK_STATE_DONE = 4
TASK_STATE_ERROR = 5


def resolve_task(fmg, response, timeout=60):
    """
    Follow an exec response to its task outcome.

    An exec call that queues a task returns status 0 as soon as the task is accepted,
    long before anything has actually happened. Verified on 7.6: running a CLI script
    without the workspace lock returns status 0 with a task id, and only the finished
    task reports num_err=1. Classifying on the RPC status alone therefore reports a
    lock as unnecessary when it is in fact required, so any queued work is followed
    to completion here.

    Returns (ok, detail) or (None, "") when the response carries no task.
    """
    if not isinstance(response, dict):
        return None, ""
    taskid = response.get("task") or response.get("taskid")
    if not taskid:
        return None, ""

    deadline = time.time() + timeout
    task = None
    while time.time() < deadline:
        status, task = fmg.get(url=f"/task/task/{taskid}")
        if status != 0 or not isinstance(task, dict):
            return None, f"task {taskid} unreadable"
        if task.get("percent") == 100 or task.get("state") in (TASK_STATE_DONE, TASK_STATE_ERROR):
            break
        time.sleep(2)

    if not isinstance(task, dict):
        return None, f"task {taskid} unreadable"
    num_err = task.get("num_err") or 0
    ok = task.get("state") != TASK_STATE_ERROR and not num_err
    lines = task.get("line") or []
    detail = lines[0].get("detail", "")[:80] if lines else ""
    return ok, f"state={task.get('state')} num_err={num_err} {detail}".strip()


def looks_like_lock_denial(status, response):
    """Distinguish 'you needed a lock' from any other failure."""
    if status == 0:
        return False
    text = json.dumps(response).lower() if response is not None else ""
    if status in LOCK_DENIED_CODES:
        return True
    return any(hint in text for hint in LOCK_DENIED_HINTS)


class Probe:
    """One candidate operation, described well enough to run it twice and clean up after."""

    def __init__(self, name, url, action, data=None, lock_scope=None,
                 cleanup=None, setup=None, device_push=False, notes=""):
        self.name = name
        self.url = url
        self.action = action
        self.data = data or {}
        # (scope_type, scope_id) for a minimal lock, or None to lock the whole ADOM.
        self.lock_scope = lock_scope
        self.setup = setup
        self.cleanup = cleanup
        self.device_push = device_push
        self.notes = notes


def acquire(fmg, adom, lock_scope):
    if lock_scope is None:
        return fmg.execute(url=f"/dvmdb/adom/{adom}/workspace/lock")
    scope_type, scope_id = lock_scope
    return fmg.execute(url=f"/dvmdb/adom/{adom}/workspace/lock/{scope_type}/{scope_id}")


def release(fmg, adom, lock_scope, commit=True):
    if lock_scope is None:
        base = f"/dvmdb/adom/{adom}/workspace"
    else:
        scope_type, scope_id = lock_scope
        base = f"/dvmdb/adom/{adom}/workspace/{{verb}}/{scope_type}/{scope_id}"
    if lock_scope is None:
        if commit:
            fmg.execute(url=f"{base}/commit")
        fmg.execute(url=f"{base}/unlock")
    else:
        if commit:
            fmg.execute(url=base.format(verb="commit"))
        fmg.execute(url=base.format(verb="unlock"))


def run_setup(fmg, probe, adom):
    """
    Run a probe's setup with a lock held, outside the measured operation.

    Setup exists to put a prerequisite in place (for example the script that a
    script/execute probe runs). Creating it is itself a locked write, so doing it
    inside the no-lock arm would fail and the probe would measure "prerequisite
    missing" instead of "lock needed". Always set up under a lock, release, then
    measure.
    """
    if not probe.setup:
        return
    lock_status, _ = acquire(fmg, adom, None)
    try:
        probe.setup(fmg)
    finally:
        if lock_status == 0:
            release(fmg, adom, None)


def run_arm(fmg, probe, adom, with_lock):
    """Run one arm of the experiment and return (status, response, note)."""
    if with_lock:
        lock_status, lock_response = acquire(fmg, adom, probe.lock_scope)
        if lock_status != 0:
            return lock_status, lock_response, "could not acquire lock for arm B"
    try:
        action_func = getattr(fmg, probe.action)
        status, response = action_func(url=probe.url, **probe.data)
        task_ok, task_detail = resolve_task(fmg, response)
        if task_ok is False:
            # The RPC succeeded but the work it queued did not.
            return -1, response, task_detail
        return status, response, task_detail
    finally:
        if with_lock:
            release(fmg, adom, probe.lock_scope)


def run_cleanup(fmg, probe, adom):
    """Remove whatever the probe created, under a lock since cleanup is a write too."""
    if not probe.cleanup:
        return
    lock_status, _ = acquire(fmg, adom, None)
    try:
        probe.cleanup(fmg)
    except Exception as cleanup_error:
        print(f"    ! cleanup failed for {probe.name}: {cleanup_error}")
    finally:
        if lock_status == 0:
            release(fmg, adom, None)


def classify(arm_a, arm_b):
    a_ok = arm_a[0] == 0
    b_ok = arm_b[0] == 0
    if a_ok and b_ok:
        return NOT_NEEDED
    if not a_ok and not b_ok and arm_a[2] and arm_a[2] == arm_b[2]:
        # Both arms failed the same way, so the lock changed nothing and whatever went
        # wrong is environmental -- an install preview with no pending changes, say.
        # That is a real answer about locking, unlike a pair of unrelated failures.
        return LOCK_IRRELEVANT
    if not a_ok and b_ok:
        # arm_a[0] == -1 marks "RPC accepted it but the task failed", which in the
        # presence of a working locked arm is exactly what a missing lock looks like.
        if arm_a[0] == -1 or looks_like_lock_denial(*arm_a[:2]):
            return REQUIRED
        return INCONCLUSIVE
    if a_ok and not b_ok:
        return LOCK_HARMFUL
    return INCONCLUSIVE


def parse_fmg_version(fmg):
    """Return the appliance version as a (major, minor, patch) tuple, or None."""
    status, sysinfo = fmg.get(url="/sys/status")
    if status != 0 or not isinstance(sysinfo, dict):
        return None
    match = re.search(r"v?(\d+)\.(\d+)\.(\d+)", sysinfo.get("Version", ""))
    return tuple(int(part) for part in match.groups()) if match else None


def script_endpoint(adom, version):
    """
    CLI scripts moved out of dvmdb in FMG 7.6.5 / 8.0.0.

    Up to 7.6.4 they live at /dvmdb/adom/{adom}/script. From 7.6.5 and 8.0.0 they are
    ordinary ADOM object-database objects at /pm/config/adom/{adom}/obj/fmg/script;
    the old path still answers reads but rejects every write with -6. Defaulting to
    the new endpoint when the version cannot be read matches how the ZTP flow
    branches, and fails forward on newer appliances.
    """
    # Every 8.x release sorts above 7.6.5, so one comparison covers both cut-offs.
    if version is not None and version < (7, 6, 5):
        return f"/dvmdb/adom/{adom}/script"
    return f"/pm/config/adom/{adom}/obj/fmg/script"


def build_probes(adom, device, package, version=None):
    """The candidate set, aimed at the paths that actually get automated."""
    address_url = f"/pm/config/adom/{adom}/obj/firewall/address"
    address_name = f"{SAFE_PREFIX}_addr"
    script_url = script_endpoint(adom, version)
    script_name = f"{SAFE_PREFIX}_script"

    def delete_address(fmg):
        fmg.delete(url=f"{address_url}/{address_name}")

    def delete_script(fmg):
        fmg.delete(url=f"{script_url}/{script_name}")

    def delete_script_and_output(fmg):
        """An adom_database script writes a real object; remove it along with the script."""
        fmg.delete(url=f"{script_url}/{script_name}")
        fmg.delete(url=f"{address_url}/{SAFE_PREFIX}_scripted")

    # Script content has to match the target, or the task fails for reasons that have
    # nothing to do with locking and look exactly like a missing lock:
    #   remote_device  runs on the FortiGate, so any command works
    #   device_database edits the device copy, so it takes device-level config
    #   adom_database   runs against a policy package, so it takes ADOM-object config
    #                   and rejects device-level commands such as "config system global"
    SCRIPT_CONTENT = {
        TARGET_REMOTE_DEVICE: "get system status",
        # Writes the device's own hostname straight back. This still exercises the
        # device-database write path and its lock, but changes nothing: a probe that
        # sets a made-up hostname gets pushed to the real FortiGate by the
        # install/device probe further down, renaming a live box.
        TARGET_DEVICE_DATABASE: None,   # resolved per-run by device_db_content()
        TARGET_ADOM_DATABASE: (
            "config firewall address\n"
            f'edit "{SAFE_PREFIX}_scripted"\n'
            "set subnet 10.255.255.253 255.255.255.255\n"
            "next\n"
            "end"),
    }

    def device_db_content(fmg):
        """A device-DB script body that rewrites the device's existing hostname."""
        status, current = fmg.get(
            url=f"/pm/config/device/{device}/global/system/global", fields=["hostname"])
        hostname = current.get("hostname") if isinstance(current, dict) else None
        if status != 0 or not hostname:
            return None
        return f"config system global\nset hostname {hostname}\nend"

    def make_script(url, name, target):
        """Build a setup hook that (re)creates the probe script with a given target."""
        content = SCRIPT_CONTENT[target]

        def setup(fmg):
            body = content if content is not None else device_db_content(fmg)
            if body is None:
                print(f"    ! could not build script body for target={target}")
                return
            fmg.delete(url=f"{url}/{name}")
            status, response = fmg.add(url=url, data={
                "name": name, "type": SCRIPT_TYPE_CLI, "target": target,
                "content": body,
                "desc": "workspace lock probe, safe to delete"})
            if status != 0:
                print(f"    ! could not create probe script (target={target}): "
                      f"status={status} {json.dumps(response)}")
        return setup

    probes = [
        # -- baseline reads: expected NOT_NEEDED, they anchor the matrix ------------
        Probe("read: sys status", "/sys/status", "get",
              notes="pure read, must never need a lock"),
        Probe("read: adom object database", address_url, "get",
              notes="pure read of the ADOM object DB"),
        Probe("read: policy package list", f"/pm/pkg/adom/{adom}", "get",
              notes="pure read of package metadata"),

        # -- ADOM object database writes: expected REQUIRED ------------------------
        Probe("write: create firewall address", address_url, "add",
              data={"data": {"name": address_name, "subnet": ["10.255.255.254", "255.255.255.255"],
                             "type": "ipmask", "comment": "workspace lock probe, safe to delete"}},
              cleanup=delete_address,
              notes="canonical ADOM DB write, the case locking exists for"),

        # -- remote CLI script objects and execution -------------------------------
        # The script object itself always lives in the ADOM database. What differs is
        # its target: adom_database edits the ADOM, device_database edits the device
        # copy held in FMG, and remote_device pushes straight to the FortiGate without
        # touching any FMG database at all. Whether a lock is needed should follow the
        # target, not the fact that this is an exec call.
        Probe("write: create CLI script object", script_url, "add",
              data={"data": {"name": script_name, "type": SCRIPT_TYPE_CLI,
                             "target": TARGET_DEVICE_DATABASE,
                             "content": "get system status",
                             "desc": "workspace lock probe, safe to delete"}},
              cleanup=delete_script,
              notes="script objects live in the ADOM DB, so a lock is plausible"),
        # An adomdb script runs against a policy package, and the package is named by a
        # "package" key rather than the "scope" list that device-targeted scripts use.
        # Passing scope here returns -8 Invalid parameter with no further detail.
        Probe("exec: run CLI script against adom_database",
              f"/dvmdb/adom/{adom}/script/execute", "execute",
              data={"data": {"adom": adom, "package": package, "script": script_name}},
              setup=make_script(script_url, script_name, TARGET_ADOM_DATABASE),
              cleanup=delete_script_and_output,
              notes="edits the ADOM DB via a policy package; needs the ADOM lock"),
        Probe("exec: run CLI script against device_database",
              f"/dvmdb/adom/{adom}/script/execute", "execute",
              data={"data": {"adom": adom, "script": script_name,
                             "scope": [{"name": device, "vdom": "root"}]}},
              setup=make_script(script_url, script_name, TARGET_DEVICE_DATABASE),
              cleanup=delete_script,
              notes="edits the device DB inside FMG; ADOM lock or dev lock?"),
        Probe("exec: run CLI script directly on device",
              f"/dvmdb/adom/{adom}/script/execute", "execute",
              data={"data": {"adom": adom, "script": script_name,
                             "scope": [{"name": device, "vdom": "root"}]}},
              setup=make_script(script_url, script_name, TARGET_REMOTE_DEVICE),
              cleanup=delete_script, device_push=True,
              notes="bypasses the FMG databases entirely, so a lock should be unnecessary"),

        # -- proxy API: goes straight to the managed device ------------------------
        Probe("exec: proxy REST read to device", "/sys/proxy/json", "execute",
              data={"data": {"target": [f"adom/{adom}/device/{device}"],
                             "action": "get", "resource": "/api/v2/cmdb/firewall/address"}},
              device_push=True,
              notes="proxied to the FortiGate, never touches the ADOM DB"),

        # -- install paths: currently in NO_LOCK_URLS, verify that is right --------
        Probe("exec: install preview", "/securityconsole/install/preview", "execute",
              data={"data": {"adom": adom, "pkg": package,
                             "scope": [{"name": device, "vdom": "root"}]}},
              device_push=True,
              notes="already in NO_LOCK_URLS; confirm a held lock does not break it"),
        Probe("exec: install device", "/securityconsole/install/device", "execute",
              data={"data": {"adom": adom, "scope": [{"name": device, "vdom": "root"}]}},
              device_push=True,
              notes="already in NO_LOCK_URLS; installs device-level settings"),
        Probe("exec: install package", "/securityconsole/install/package", "execute",
              data={"data": {"adom": adom, "pkg": package,
                             "scope": [{"name": device, "vdom": "root"}]}},
              device_push=True,
              notes="already in NO_LOCK_URLS; the LOCK_HARMFUL case this list exists for"),
    ]
    return probes


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--adom", default="root")
    parser.add_argument("--device", default=os.getenv("LIVE_FGT_DEVICE_NAME", ""))
    parser.add_argument("--package", default=os.getenv("FGT_ASSIGNED_POL_PKG", "default"))
    parser.add_argument("--allow-device-push", action="store_true",
                        help="include probes that reach real managed FortiGates")
    parser.add_argument("--list", action="store_true",
                        help="print the probe plan and exit without connecting")
    parser.add_argument("--only", default="", help="substring filter on probe name")
    parser.add_argument("--address", default="", help="override the appliance address from .env")
    parser.add_argument("--username", default="", help="override the username from .env")
    parser.add_argument("--password", default="", help="override the password from .env")
    parser.add_argument("--api-key", default="", help="authenticate with an API key instead")
    args = parser.parse_args()

    probes = build_probes(args.adom, args.device, args.package)
    if args.only:
        probes = [p for p in probes if args.only.lower() in p.name.lower()]

    if args.list:
        print(f"Probe plan for ADOM '{args.adom}' (device={args.device or '<unset>'}, "
              f"package={args.package}):\n")
        for probe in probes:
            gate = "  [device-push, needs --allow-device-push]" if probe.device_push else ""
            print(f"  {probe.action:8} {probe.url}{gate}")
            print(f"           {probe.name} - {probe.notes}")
        return 0

    skipped = [p for p in probes if p.device_push and not args.allow_device_push]
    active = [p for p in probes if not (p.device_push and not args.allow_device_push)]

    results = []
    with connect(args.address, args.username, args.password, args.api_key) as fmg:
        if not fmg._lock_ctx.uses_workspace:
            print("Workspace mode is DISABLED on this appliance. The probe cannot tell a "
                  "needed lock from an unneeded one; enable workspace mode and rerun.")
            return 2
        version = parse_fmg_version(fmg)
        print(f"Connected to FMG {version}. Workspace mode enabled. "
              f"Probing ADOM '{args.adom}'.")
        print(f"CLI script endpoint for this version: {script_endpoint(args.adom, version)}\n")
        rebuilt = build_probes(args.adom, args.device, args.package, version)
        if args.only:
            rebuilt = [p for p in rebuilt if args.only.lower() in p.name.lower()]
        by_name = {p.name: p for p in rebuilt}
        active = [by_name.get(p.name, p) for p in active]

        for probe in active:
            print(f"-> {probe.name}")
            run_setup(fmg, probe, args.adom)
            arm_a = run_arm(fmg, probe, args.adom, with_lock=False)
            run_cleanup(fmg, probe, args.adom)
            time.sleep(1)
            run_setup(fmg, probe, args.adom)
            arm_b = run_arm(fmg, probe, args.adom, with_lock=True)
            run_cleanup(fmg, probe, args.adom)
            verdict = classify(arm_a, arm_b)
            results.append((probe, arm_a, arm_b, verdict))
            print(f"   no-lock: status={arm_a[0]} {arm_a[2]}")
            print(f"   with-lock: status={arm_b[0]} {arm_b[2]}")
            print(f"   => {verdict}")

    print("\n" + "=" * 100)
    print(f"{'VERDICT':<14} {'ACTION':<8} {'URL':<50} NO-LOCK / WITH-LOCK")
    print("=" * 100)
    for probe, arm_a, arm_b, verdict in results:
        print(f"{verdict:<14} {probe.action:<8} {probe.url:<50} {arm_a[0]} / {arm_b[0]}")

    if skipped:
        print(f"\nSkipped {len(skipped)} device-facing probe(s); rerun with --allow-device-push "
              f"to include them:")
        for probe in skipped:
            print(f"  - {probe.name}")

    candidates = [p.url for p, _, _, v in results
                  if v in (NOT_NEEDED, LOCK_HARMFUL, LOCK_IRRELEVANT) and p.action != "get"]
    if candidates:
        print("\nURLs the evidence says do not need a lock (NO_LOCK_URLS candidates):")
        for url in sorted(set(candidates)):
            print(f"  {url}")

    inconclusive = [(p.name, a, b) for p, a, b, v in results if v == INCONCLUSIVE]
    if inconclusive:
        print("\nInconclusive rows, these need a human look:")
        for name, arm_a, arm_b in inconclusive:
            print(f"  {name}: no-lock={arm_a[0]} {arm_a[1]}")
            print(f"  {' ' * len(name)}  with-lock={arm_b[0]} {arm_b[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
