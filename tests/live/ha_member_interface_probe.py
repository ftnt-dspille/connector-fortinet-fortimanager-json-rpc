"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
Get interface state for BOTH members of an HA cluster, using FortiManager only.

The goal: "which ports are up on the primary, and which on the secondary". The obstacle:
FortiManager manages a cluster as ONE device object, and `/sys/proxy/json` reaches
whichever unit is currently primary. There is no second device to target, and
`/sys/proxy/cli` and `/sys/proxy/xml` both answer `-11` on this appliance, so a
`execute ha manage` style hop is not available either. Everything therefore has to come
from either FMG's own database or from a FortiOS endpoint that reports per-member data in
one call.

The probe walks four mechanisms and reports what each one actually yields, so the
coverage gap is visible rather than assumed:

    ROSTER      FMG-native `/dvmdb/adom/<adom>/device/<dev>/ha_slave` -- the member list
                with role and status, without touching the box at all
    PER_MEMBER  proxy `ha-checksums` / `ha-statistics` / `ha-peer` -- FortiOS endpoints
                that natively return one entry PER MEMBER from a single call
    PRIMARY_IF  proxy `available-interfaces` -- admin `status` and physical `link` per
                interface, but only for the unit that answered
    SECONDARY_IF whether the secondary's interface state is reachable at all: the
                `?serial=<member>` form, and `ha-hw-interface`

Two things make the results trustworthy:

**Every proxy response carries `response.serial`.** That is the ground truth of WHICH unit
answered, and it is the only way to tell a genuine per-member answer from the primary
answering twice. The probe reports it for every call rather than trusting the request.

**`?serial=` is not validated.** Measured on a standalone unit: `?serial=FGVMBOGUS0000000`
returns `status: success` with the primary's own data and its own serial. A silently
ignored parameter looks identical to a working one unless you check the serial that came
back, so on a cluster a typo'd member serial would quietly yield the primary's ports
labelled as the secondary's. Whether the parameter is honoured when HA is actually
active is the open question this probe exists to answer.

Everything here is read-only.

Usage
-----
    python ha_member_interface_probe.py --adom root --device <cluster> \
        --address <fmg> --username <user> --password <pw>
"""

import argparse
import json
import os
import sys
import warnings

warnings.filterwarnings("ignore")

current_directory = os.path.dirname(os.path.abspath(__file__))
tests_directory = os.path.abspath(os.path.join(current_directory, os.pardir))
repo_root = os.path.abspath(os.path.join(tests_directory, os.pardir))
sys.path.insert(0, current_directory)
sys.path.insert(0, repo_root)

from lock_matrix_probe import connect  # noqa: E402


def proxy(fmg, adom, device, resource):
    """
    One proxied FortiOS read. Returns (code, results, serial).

    `serial` is the unit that actually answered -- see the module docstring; it is the
    only defence against a silently ignored member selector.
    """
    status, response = fmg.execute(url="/sys/proxy/json", data={
        "action": "get", "resource": resource,
        "target": [f"adom/{adom}/device/{device}"]})
    entry = response[0] if isinstance(response, list) and response else {}
    body = entry.get("response") or {}
    return (entry.get("status") or {}).get("code"), body.get("results"), body.get("serial")


def roster(fmg, adom, device):
    """FMG's own record of the cluster. No traffic to the device."""
    status, record = fmg.get(url=f"/dvmdb/adom/{adom}/device/{device}",
                             fields=["name", "sn", "ha_mode", "ha_group_name", "conn_status"])
    status, members = fmg.get(url=f"/dvmdb/adom/{adom}/device/{device}/ha_slave")
    return record if isinstance(record, dict) else {}, members if isinstance(members, list) else []


def interface_state(results):
    """
    Reduce available-interfaces to the admin-vs-link answer.

    Only `type: physical` entries are ports; the endpoint also returns VLANs, aggregates,
    tunnels and a synthetic `any`. Admin state (`status`) and physical state (`link`) are
    kept apart because "admin down" and "cable down" are different findings.
    """
    if not isinstance(results, list):
        return []
    return sorted(
        (entry.get("name"), entry.get("status"), entry.get("link"), entry.get("type"))
        for entry in results
        if isinstance(entry, dict) and entry.get("type") == "physical")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--adom", default="root")
    parser.add_argument("--device", required=True, help="the cluster's device name in FMG")
    parser.add_argument("--address", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()

    fmg = connect(args.address, args.username, args.password, args.api_key)
    fmg.login()
    try:
        print("=" * 72)
        print("ROSTER -- FortiManager's own database, no traffic to the device")
        print("=" * 72)
        record, members = roster(fmg, args.adom, args.device)
        primary_serial = record.get("sn")
        print(f"  device        {record.get('name')}  sn={primary_serial}")
        print(f"  ha_mode       {record.get('ha_mode')}   ha_group_name="
              f"{record.get('ha_group_name')!r}   conn_status={record.get('conn_status')}")
        if not members:
            print("  ha_slave      EMPTY -- FMG does not consider this device a cluster.")
        for member in members:
            print(f"  member        name={member.get('name')} sn={member.get('sn')} "
                  f"role={member.get('role')} status={member.get('status')} "
                  f"prio={member.get('prio')}")
        member_serials = [m.get("sn") for m in members if m.get("sn")]

        print()
        print("=" * 72)
        print("PER_MEMBER -- FortiOS endpoints that report every member in one call")
        print("=" * 72)
        for resource in ("/api/v2/monitor/system/ha-peer",
                         "/api/v2/monitor/system/ha-statistics",
                         "/api/v2/monitor/system/ha-checksums"):
            code, results, serial = proxy(fmg, args.adom, args.device, resource)
            count = len(results) if isinstance(results, (list, dict)) else 0
            note = "" if count else "   <- empty: normal on a standalone unit"
            print(f"  {resource.split('/')[-1]:16} code={code} answered_by={serial} "
                  f"entries={count}{note}")
            if count:
                print(f"      {json.dumps(results, default=str)[:400]}")

        print()
        print("=" * 72)
        print("PRIMARY_IF -- interface state of whichever unit answered")
        print("=" * 72)
        code, results, serial = proxy(
            fmg, args.adom, args.device, "/api/v2/monitor/system/available-interfaces")
        print(f"  answered_by   {serial}")
        for name, admin, link, _kind in interface_state(results):
            flag = "" if (admin == "up" and link == "up") else "   <-"
            print(f"  {name:12} admin={admin:5} link={link}{flag}")

        print()
        print("=" * 72)
        print("SECONDARY_IF -- can the other member's interfaces be reached at all?")
        print("=" * 72)
        # Arm 1: does ?serial= redirect, or is it ignored? A bogus serial is the control:
        # if it answers happily as the primary, the parameter proves nothing.
        code, _results, serial = proxy(
            fmg, args.adom, args.device,
            "/api/v2/monitor/system/available-interfaces?serial=FGVMBOGUS0000000")
        print(f"  bogus serial      code={code} answered_by={serial}")
        ignored = (code == 0 and serial == primary_serial)
        print(f"  -> ?serial= is {'IGNORED (answers as the primary)' if ignored else 'validated'}")

        for member_serial in member_serials:
            if member_serial == primary_serial:
                continue
            resource = ("/api/v2/monitor/system/available-interfaces"
                        f"?serial={member_serial}")
            code, results, serial = proxy(fmg, args.adom, args.device, resource)
            redirected = serial == member_serial
            print(f"  serial={member_serial} code={code} answered_by={serial} "
                  f"-> {'REDIRECTED, usable' if redirected else 'NOT redirected'}")
            if redirected:
                for name, admin, link, _kind in interface_state(results):
                    print(f"      {name:12} admin={admin:5} link={link}")

        # Arm 2: the hardware/hyperscale endpoint, the other candidate for per-member ports.
        code, results, serial = proxy(
            fmg, args.adom, args.device, "/api/v2/monitor/system/ha-hw-interface")
        print(f"  ha-hw-interface   code={code} answered_by={serial} "
              f"entries={len(results) if isinstance(results,(list,dict)) else 0}")
        if not member_serials:
            print("\n  No secondary in the roster, so the redirect question is UNANSWERED here.")
    finally:
        fmg.logout()
    return 0


if __name__ == "__main__":
    sys.exit(main())
