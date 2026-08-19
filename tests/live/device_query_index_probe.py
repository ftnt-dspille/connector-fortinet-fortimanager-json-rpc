"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
Verifies every row of docs/DEVICE_QUERY_API_INDEX.md against a live appliance.

The index maps each device-local CLI check a playbook wants to two API calls: a FortiOS
REST read proxied through `/sys/proxy/json`, and FortiManager's own copy under
`/dvmdb` or `/pm/config/device`. This probe calls all of them and reports, per row,
whether each side answers.

Everything here is read-only.

Verdicts:

    OK       the call answered and carried data
    EMPTY    the call answered with an empty result -- a real endpoint with nothing to
             report on this device (a standalone unit's HA peers, a VM's sensors). NOT a
             failure, and the distinction matters: a playbook that treats empty as broken
             will misread every standalone device.
    ERROR    the device rejected it (FortiOS `status: error`) -- wrong endpoint, wrong
             method, or unsupported on this platform
    FAIL     the RPC itself failed, or the proxy reported a per-device error

Note the proxy hides per-device failures: `/sys/proxy/json` returns RPC status 0 whatever
happens, and a failed device shows up as an entry in the returned array carrying its own
`status.code`. That is checked here rather than trusted.

Usage
-----
    python device_query_index_probe.py --adom root --device <device> --vdom root
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

OK, EMPTY, ERROR, FAIL = "OK", "EMPTY", "ERROR", "FAIL"


def proxy_get(fmg, adom, device, resource, action="get", payload=None):
    data = {"action": action, "resource": resource,
            "target": [f"adom/{adom}/device/{device}"]}
    if payload is not None:
        data["payload"] = payload
    status, response = fmg.execute(url="/sys/proxy/json", data=data)
    if status != 0:
        return FAIL, f"rpc status={status}"
    if not isinstance(response, list) or not response:
        return FAIL, f"unexpected envelope: {json.dumps(response)[:80]}"
    entry = response[0]
    # A per-device failure lives here, not in the RPC status.
    entry_status = entry.get("status")
    if isinstance(entry_status, dict) and entry_status.get("code", 0) != 0:
        return FAIL, f"device error: {entry_status.get('message', '')[:60]}"
    inner = entry.get("response")
    if not isinstance(inner, dict):
        return FAIL, f"no response body: {json.dumps(entry)[:80]}"
    if inner.get("status") == "error" or inner.get("error"):
        return ERROR, f"{inner.get('error') or 'error'} (http {inner.get('http_status', '?')})"
    results = inner.get("results")
    if results in (None, [], {}):
        return EMPTY, "answered, no rows"
    size = len(results) if isinstance(results, (list, dict)) else 1
    return OK, f"{size} item(s)"


def fmg_get(fmg, url, keys=()):
    status, response = fmg.get(url=url)
    if status != 0:
        message = response.get("status", {}).get("message") if isinstance(response, dict) else ""
        return FAIL, f"status={status} {message}"
    if isinstance(response, list):
        if not response:
            return EMPTY, "answered, no rows"
        return OK, f"{len(response)} row(s)"
    if isinstance(response, dict):
        shown = {key: response.get(key) for key in keys if key in response}
        if not response:
            return EMPTY, "answered, empty object"
        return OK, json.dumps(shown)[:70] if shown else f"{len(response)} field(s)"
    return OK, str(response)[:60]


def build_rows(adom, device, vdom):
    """(label, proxy resource or None, FMG url or None, interesting FMG keys)"""
    dev = f"/pm/config/device/{device}"
    return [
        ("get system status",
         "/api/v2/monitor/system/status",
         f"/dvmdb/adom/{adom}/device/{device}",
         ("name", "os_ver", "mr", "patch", "build", "conn_status")),
        ("running firmware",
         "/api/v2/monitor/system/firmware",
         f"/dvmdb/adom/{adom}/device/{device}", ("os_ver", "mr", "patch", "build")),
        ("config system ha",
         "/api/v2/cmdb/system/ha",
         f"{dev}/global/system/ha", ("mode", "group-name")),
        ("get system ha status",
         "/api/v2/monitor/system/ha-statistics",
         f"/dvmdb/adom/{adom}/device/{device}/ha_slave", ()),
        ("get system ha status (peers)",
         "/api/v2/monitor/system/ha-peer", None, ()),
        ("diagnose sys ha checksum cluster",
         "/api/v2/monitor/system/ha-checksums", None, ()),
        ("diag sys ha history read",
         "/api/v2/monitor/system/ha-history", None, ()),
        ("get system interface physical",
         "/api/v2/monitor/system/interface?scope=global", None, ()),
        ("config system interface",
         f"/api/v2/cmdb/system/interface?vdom={vdom}",
         f"{dev}/global/system/interface", ()),
        ("execute sensor list",
         "/api/v2/monitor/system/sensor-info", None, ()),
        ("system resource usage",
         "/api/v2/monitor/system/resource/usage", None, ()),
        ("system performance status",
         "/api/v2/monitor/system/performance/status", None, ()),
        ("config router static",
         f"/api/v2/cmdb/router/static?vdom={vdom}",
         f"{dev}/vdom/{vdom}/router/static", ()),
        ("config router bgp",
         f"/api/v2/cmdb/router/bgp?vdom={vdom}",
         f"{dev}/vdom/{vdom}/router/bgp", ("as", "router-id")),
        ("get router info bgp summary",
         "/api/v2/monitor/router/bgp/neighbors", None, ()),
        ("bgp paths statistics",
         "/api/v2/monitor/router/bgp/paths-statistics", None, ()),
        ("routing table",
         "/api/v2/monitor/router/ipv4", None, ()),
        ("firewall policy as the device has it",
         f"/api/v2/cmdb/firewall/policy?vdom={vdom}", None, ()),
        ("get webfilter status (fortiguard server)",
         "/api/v2/monitor/system/fortiguard/server-info", None, ()),
        ("get webfilter status (licence/entitlement)",
         "/api/v2/monitor/license/status", None, ()),
        ("get webfilter status (category quota)",
         "/api/v2/monitor/webfilter/category-quota", None, ()),

        ("webfilter profiles (FMG copy)",
         None, f"{dev}/vdom/{vdom}/webfilter/profile", ()),
        ("device VDOM list",
         None, f"/dvmdb/adom/{adom}/device/{device}/vdom", ()),
    ]


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--adom", default="root")
    parser.add_argument("--device", required=True, help="a real, connected device")
    parser.add_argument("--vdom", default="root")
    parser.add_argument("--address", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()

    rows = build_rows(args.adom, args.device, args.vdom)
    tally = {}
    with connect(args.address, args.username, args.password, args.api_key) as fmg:
        print(f"{'check':46} {'proxy':<8} {'fmg':<8}")
        print("-" * 90)
        for label, resource, fmg_url, keys in rows:
            proxy_verdict, proxy_detail = (
                proxy_get(fmg, args.adom, args.device, resource) if resource else ("-", ""))
            fmg_verdict, fmg_detail = fmg_get(fmg, fmg_url, keys) if fmg_url else ("-", "")
            for verdict in (proxy_verdict, fmg_verdict):
                if verdict != "-":
                    tally[verdict] = tally.get(verdict, 0) + 1
            print(f"{label:46} {proxy_verdict:<8} {fmg_verdict:<8}")
            if proxy_detail:
                print(f"{'':46}   proxy: {proxy_detail}")
            if fmg_detail:
                print(f"{'':46}   fmg:   {fmg_detail}")

        # The one POST in the index, and the only verified write shape: `action: "post"`
        # with a `payload` object. GET on the same resource is rejected.
        verdict, detail = proxy_get(fmg, args.adom, args.device,
                                    "/api/v2/monitor/utm/rating-lookup",
                                    action="post", payload={"url": ["www.fortinet.com"]})
        print(f"\n{'utm/rating-lookup (POST + payload)':46} {verdict:<8}\n{'':46}   proxy: {detail}")

        # The multi-target contract, which has three outcomes rather than two and only
        # one of them is visible as an error.
        print("\nmulti-target contract")
        for label, targets in (
                ("good + unknown name", [f"adom/{args.adom}/device/{args.device}",
                                         f"adom/{args.adom}/device/zz-no-such-device"]),
                ("only an unknown name", [f"adom/{args.adom}/device/zz-no-such-device"])):
            status, response = fmg.execute(url="/sys/proxy/json", data={
                "action": "get", "resource": "/api/v2/monitor/system/status",
                "target": targets})
            entries = len(response) if isinstance(response, list) else "-"
            codes = ([(e.get("target"), (e.get("status") or {}).get("code"))
                      for e in response] if isinstance(response, list) else response)
            print(f"   {label:22} rpc={status:<4} entries={entries} {json.dumps(codes)[:90]}")

    print("\ntally:", ", ".join(f"{k}={v}" for k, v in sorted(tally.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
