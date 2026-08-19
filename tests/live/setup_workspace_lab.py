"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
Prepare a lab FortiManager for workspace-locking tests.

The lock-necessity probe can only tell a needed lock from an unneeded one when
workspace mode is actually on. This script puts the appliance into per-ADOM
workspace mode and enables workspace on a single scratch ADOM, so locking is
exercised without turning it on for every ADOM on a shared lab box.

Intended for lab appliances only. It changes global system configuration.

    python setup_workspace_lab.py --address fortimanager.example.com --status
    python setup_workspace_lab.py --address fortimanager.example.com --enable
    python setup_workspace_lab.py --address fortimanager.example.com --disable
"""

import argparse
import json
import os
import sys
import warnings

from dotenv import load_dotenv

warnings.filterwarnings("ignore")

current_directory = os.path.dirname(os.path.abspath(__file__))
tests_directory = os.path.abspath(os.path.join(current_directory, os.pardir))
load_dotenv(dotenv_path=os.path.join(tests_directory, ".env"))

from pyFMG.fortimgr import FortiManager  # noqa: E402

GLOBAL_URL = "/cli/global/system/global"
SCRATCH_ADOM = "zz_locktest"

# FMG reports workspace-mode as an int and accepts either the int or its label.
WORKSPACE_MODES = {0: "disabled", 1: "normal", 2: "workflow", 3: "per-adom"}


def connect(args):
    address = (args.address or os.getenv("ADDRESS") or "")
    address = address.replace("https://", "").replace("http://", "").strip("/")
    return FortiManager(
        address,
        args.username or os.getenv("USERNAME"),
        args.password or os.getenv("PASSWORD"),
        verify_ssl=False,
        disable_request_warnings=True,
    )


def show_status(fmg):
    status, settings = fmg.get(url=GLOBAL_URL, fields=["workspace-mode", "adom-status"])
    mode = settings.get("workspace-mode") if isinstance(settings, dict) else None
    print(f"global workspace-mode : {mode} ({WORKSPACE_MODES.get(mode, 'unknown')})")

    status, adoms = fmg.get(url="/dvmdb/adom", fields=["name", "workspace_mode"])
    enabled = [a for a in (adoms or []) if a.get("workspace_mode")]
    print(f"ADOMs with workspace on: {[a['name'] for a in enabled] or 'none'}")
    return mode


def set_global_mode(fmg, desired):
    """Set workspace-mode, trying the label first and the numeric value as a fallback."""
    label = WORKSPACE_MODES[desired]
    for value in (label, desired):
        status, response = fmg.update(url=GLOBAL_URL, data={"workspace-mode": value})
        print(f"  set workspace-mode={value!r} -> status={status}")
        if status == 0:
            return True
        print(f"    {json.dumps(response)}")
    return False


def ensure_scratch_adom(fmg, adom):
    status, existing = fmg.get(url=f"/dvmdb/adom/{adom}", fields=["name"])
    if status == 0:
        print(f"  scratch ADOM '{adom}' already exists")
        return True
    status, response = fmg.add(url="/dvmdb/adom", data={
        "name": adom,
        "desc": "workspace lock probe scratch ADOM, safe to delete",
        "restricted_prds": "fos",
        "os_ver": 7,
        "mr": 6,
    })
    print(f"  create ADOM '{adom}' -> status={status}")
    if status != 0:
        print(f"    {json.dumps(response)}")
    return status == 0


def set_adom_workspace(fmg, adom, on):
    status, response = fmg.update(url=f"/dvmdb/adom/{adom}",
                                  data={"workspace_mode": 1 if on else 0})
    print(f"  set '{adom}' workspace_mode={1 if on else 0} -> status={status}")
    if status != 0:
        print(f"    {json.dumps(response)}")
    return status == 0


def seed_packages(fmg, adom):
    """
    Create the policy packages the probe needs, including one nested in a folder.

    The nested package is the case that broke minimal locking: only its full path
    ("probe_folder/probe_nested") is addressable, so it is the target that proves
    the lock URL is built correctly.
    """
    # The ADOM has workspace on, so seeding it needs the workspace lock first.
    status, _ = fmg.execute(url=f"/dvmdb/adom/{adom}/workspace/lock")
    if status != 0:
        print(f"  could not lock '{adom}' to seed packages (status={status})")
        return False
    try:
        for payload in (
            {"name": "probe_pkg", "type": "pkg"},
            {"name": "probe_folder", "type": "folder",
             "subobj": [{"name": "probe_nested", "type": "pkg"}]},
        ):
            status, response = fmg.add(url=f"/pm/pkg/adom/{adom}", data=payload)
            print(f"  create package {payload['name']!r} -> status={status}"
                  + ("" if status == 0 else f" {json.dumps(response)}"))
    finally:
        fmg.execute(url=f"/dvmdb/adom/{adom}/workspace/commit")
        fmg.execute(url=f"/dvmdb/adom/{adom}/workspace/unlock")

    status, packages = fmg.get(url=f"/pm/pkg/adom/{adom}")
    print(f"  packages now: {[p.get('name') for p in (packages or [])]}")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--address", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--adom", default=SCRATCH_ADOM)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--status", action="store_true", help="report current state only")
    action.add_argument("--enable", action="store_true",
                        help="per-ADOM workspace mode + workspace on the scratch ADOM")
    action.add_argument("--disable", action="store_true",
                        help="turn workspace back off for the scratch ADOM and globally")
    action.add_argument("--seed", action="store_true",
                        help="create the probe policy packages in the scratch ADOM")
    args = parser.parse_args()

    with connect(args) as fmg:
        if args.status:
            show_status(fmg)
            return 0

        if args.seed:
            print(f"Seeding packages in '{args.adom}':")
            seed_packages(fmg, args.adom)
            return 0

        if args.enable:
            print("Enabling per-ADOM workspace mode:")
            if not set_global_mode(fmg, 3):
                print("Could not set per-ADOM mode; leaving the appliance unchanged.")
                return 1
            if not ensure_scratch_adom(fmg, args.adom):
                return 1
            set_adom_workspace(fmg, args.adom, on=True)
        else:
            print("Disabling workspace mode:")
            set_adom_workspace(fmg, args.adom, on=False)
            set_global_mode(fmg, 0)

        print()
        show_status(fmg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
