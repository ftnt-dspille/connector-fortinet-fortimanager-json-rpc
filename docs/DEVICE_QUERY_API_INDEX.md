# Device query API index -- CLI command → API call

For each device-local check a playbook wants, this lists two ways to get it:

- **FortiOS REST**, proxied through FortiManager with `/sys/proxy/json`. Reads the live
  device. Takes **no workspace lock** (the URL is in the connector's `NO_LOCK_URLS`), so
  it never serialises behind other workers -- and equally, it can read a device in the
  middle of an install.
- **FortiManager-native**, reading FMG's own copy. No device round trip, so it works even
  when the device is unreachable, and it is what FMG will push on the next install -- but
  it is FMG's *intent*, which is not necessarily what the device is running right now.

Pick the proxy when the question is "what is the device actually doing"; pick FMG-native
when the question is "what is FMG configured to give it", or when the device is down.

## Call shapes

FortiOS REST through the proxy -- connector operation **execute**, `url = /sys/proxy/json`:

```json
{
  "action":   "get",
  "resource": "/api/v2/monitor/system/status",
  "target":   ["adom/<adom>/device/<device>"]
}
```

- Query strings live inside `resource` (`?vdom=<vdom>`, `?scope=global`). There is no
  separate params field.
- `"target": ["device/<device>"]` (no adom prefix) also works.
- Writes use `"action": "post"` / `"put"` with a `payload` object alongside `resource`.
  Verified with `utm/rating-lookup`:
  `{"action": "post", "resource": "/api/v2/monitor/utm/rating-lookup", "target": [...],
  "payload": {"url": ["www.fortinet.com"]}}` answers `status: success`, while `GET` on the
  same resource is rejected `-6 Invalid url`.

### The multi-target contract has three outcomes, and only one of them looks like an error

`target` accepts several devices in one call, and the RPC status tells you nothing about
any of them. Measured:

| Case | RPC status | What you get |
|---|---|---|
| device reachable | 0 | entry with `status.code: 0` and a `response` body |
| device known but unreachable | 0 | entry with `status.code: -1`, e.g. `"<device>(393) error: No tunnel 80."` |
| device name unknown, alongside a good one | 0 | **the unknown device is silently dropped** -- 2 targets in, 1 entry out, no error anywhere |
| every device name unknown | **-11** | `No permission for the resource` |

The third row is the trap: a typo'd device name does not fail, it disappears. Match
returned entries back to the targets you asked for by their `target` field and count them,
rather than iterating whatever came back.

FMG-native -- connector operation **get**, with the URL in the table. Device-DB config
lives under `/pm/config/device/<device>/global/...` (global settings) or
`/pm/config/device/<device>/vdom/<vdom>/...` (per-VDOM settings); device metadata lives
under `/dvmdb/adom/<adom>/device/<device>`.

## The index

| Wanted (CLI) | FortiOS REST via `/sys/proxy/json` | FortiManager-native | Verified |
|---|---|---|---|
| `get system status` | `/api/v2/monitor/system/status` | `/dvmdb/adom/<adom>/device/<device>` → `os_ver`, `mr`, `patch`, `build`, `platform_str`, `conn_status` | both |
| running firmware | `/api/v2/monitor/system/firmware` | same device record (`os_ver`/`mr`/`patch`/`build`) | both |
| `config system ha` | `/api/v2/cmdb/system/ha` → `mode`, `group-name`, `group-id` | `/pm/config/device/<device>/global/system/ha` | both |
| `get system ha status` | `/api/v2/monitor/system/ha-statistics`, `/api/v2/monitor/system/ha-peer` | `/dvmdb/adom/<adom>/device/<device>` → `ha_mode`, `ha_group_name`; cluster members at `/dvmdb/adom/<adom>/device/<device>/ha_slave` | both |
| `diagnose sys ha checksum cluster` | `/api/v2/monitor/system/ha-checksums` | -- (live-only state) | proxy |
| `diag sys ha history read` | `/api/v2/monitor/system/ha-history` | -- | proxy |
| `get system interface physical` | `/api/v2/monitor/system/interface?scope=global` → link, speed, IP, counters | -- (live-only state) | proxy |
| `config system interface` | `/api/v2/cmdb/system/interface?vdom=<vdom>` → `status` (`up`/`down`) | `/pm/config/device/<device>/global/system/interface` | both |
| `execute sensor list` | `/api/v2/monitor/system/sensor-info` | -- | **not available** on a VM (`-6 Invalid url`, as are `system/sensors` and `system/hardware-status`); unverified on hardware |
| device health / load (the VM-safe substitute) | `/api/v2/monitor/system/resource/usage`, `/api/v2/monitor/system/performance/status` | -- | proxy |
| `config router static` (per VDOM) | `/api/v2/cmdb/router/static?vdom=<vdom>` | `/pm/config/device/<device>/vdom/<vdom>/router/static` | both |
| `config router bgp` (per VDOM) | `/api/v2/cmdb/router/bgp?vdom=<vdom>` | `/pm/config/device/<device>/vdom/<vdom>/router/bgp` | both |
| `get router info bgp summary` (per VDOM) | `/api/v2/monitor/router/bgp/neighbors`, `/api/v2/monitor/router/bgp/paths-statistics` | -- (live-only state) | proxy |
| routing table | `/api/v2/monitor/router/ipv4` | -- | proxy |
| policies as the device has them | `/api/v2/cmdb/firewall/policy?vdom=<vdom>` | policy package under `/pm/config/adom/<adom>/pkg/<pkg>/firewall/policy` | both |
| `get webfilter status` (per VDOM) | no single equivalent -- see below | `/pm/config/device/<device>/vdom/<vdom>/webfilter/profile` | partial |
| FortiGuard URL rating (POST) | `/api/v2/monitor/utm/rating-lookup` with `payload: {"url": [...]}` | -- | proxy |
| licence / FortiGuard contract state | `/api/v2/monitor/license/status`, `/api/v2/monitor/system/fortiguard/server-info` | -- | proxy |

`sudo <vdom> <command>` in the CLI list is just per-VDOM scoping: add `?vdom=<vdom>` to
the proxied resource, or address `/pm/config/device/<device>/vdom/<vdom>/...` on the FMG
side. List a device's VDOMs with `/dvmdb/adom/<adom>/device/<device>/vdom`.

## Verification

Every row was called against a live 7.6.7 FortiManager and a connected FortiGate by
`tests/live/device_query_index_probe.py`, which is read-only and rerunnable:

    python device_query_index_probe.py --adom <adom> --device <device> --vdom <vdom>

Latest run: **21 OK, 8 EMPTY, 1 FAIL** (the FAIL being `sensor-info` on a VM). The probe
separates EMPTY from FAIL deliberately -- see the caution below.

## Gaps and cautions

- **`get webfilter status` has no direct endpoint.** The CLI command reports FortiGuard
  web-filter rating service reachability. The closest proxied reads are
  `/api/v2/monitor/system/fortiguard/server-info` and `/api/v2/monitor/license/status`
  (which carries FortiGuard entitlement); `/api/v2/monitor/webfilter/category-quota`
  answers but describes quota, not service state. `/api/v2/monitor/utm/rating-lookup`
  exists but rejects `GET` -- it is a POST endpoint.
- **`execute sensor list` is not merely empty on a VM, it is rejected** (`-6 Invalid
  url`), and so are `system/sensors` and `system/hardware-status`. Whether that is the
  platform or the firmware is untested -- there is no hardware FortiGate on the bench to
  tell them apart. If a playbook needs a health signal that works everywhere,
  `system/resource/usage` and `system/performance/status` both answer on a VM.
- **Empty is not broken.** On a standalone unit `ha-statistics`, `ha-peer`,
  `ha-checksums`, `ha-history` and `ha_slave` all answer successfully with nothing in
  them, and `cmdb/system/ha` reports `mode: standalone`. Same for `bgp/neighbors` where no
  peers are configured, and `fortiguard/server-info` / `webfilter/category-quota`. Eight of
  the checks in the index come back empty on a healthy device. A playbook branch that
  reads "no rows" as a failure will misjudge every standalone device it touches -- check
  the call's own `status` field, not the length of `results`.
- **The two sources disagree by design.** FMG's device record is what FMG last retrieved
  or intends to push; the proxy reads the box. Firmware is the obvious case -- after an
  out-of-band upgrade the device record is stale until a retrieve.

## Where the specs live

- **FortiManager API reference (7.6.x, HTML):**
  `~/Library/CloudStorage/OneDrive-FortinetCorpMain/Cloud_Documents/Documentation/FMG/FMG_76X_API/html-internal`
- **FNDN spec downloader:** `~/PycharmProjects/fndn-fortiapi-specs/fndn_specs.py`.
  Its `downloads/` currently holds FortiSASE, FortiNDR and FortiFlex only -- **no FortiOS
  spec has been downloaded yet**, so every FortiOS row above was verified by calling it
  through a live appliance rather than read from a spec. Fetching the FortiOS spec would
  let the remaining gaps (webfilter status, the POST shapes) be resolved from the source.

---

## Sample outputs

Captured from a live 7.6.7 FortiManager against a connected FortiGate VM by
`tests/live/device_query_index_probe.py`. Values are sanitised (addresses, serials,
MACs, UUIDs and account names replaced) and deep structures are elided -- these show the
*shape* of each answer, which is what a playbook has to parse, not one device's data.

For proxied calls only `response.results` is shown; the surrounding envelope is
`[{"response": {..., "status": "success"}, "status": {"code": 0}}]`.

### get system status -- proxy

`/api/v2/monitor/system/status`

```json
{
  "model_name": "FortiGate",
  "model_number": "VM64-KVM",
  "model": "FGVMK6",
  "hostname": "<device>",
  "log_disk_status": "not_available"
}
```

### get system status -- FMG

`/dvmdb/adom/root/device/<device>`

FMG's own record. `conn_status: 1` is up; the version fields are FMG's copy and go stale after an out-of-band upgrade.

```json
{
  "name": "<device>",
  "sn": "<serial>",
  "platform_str": "FortiGate-VM64-KVM",
  "os_ver": 7,
  "mr": 6,
  "patch": 7,
  "build": 3704,
  "conn_status": 1,
  "ha_mode": 0,
  "ha_group_name": "",
  "ip": "192.0.2.1",
  "mgmt_mode": 3,
  "dev_status": 1
}
```

### running firmware -- proxy

`/api/v2/monitor/system/firmware`

`current` is what the box runs; `available` lists every image FortiGuard offers it (~99 entries here).

```json
{
  "current": {
    "name": "FortiOS",
    "id": "current",
    "version": "v7.6.7",
    "major": 7,
    "minor": 6,
    "patch": 7,
    "...": "(+7 more keys)"
  },
  "available": [
    "...(object, elided)",
    "...(+98 more)"
  ]
}
```

### config system ha -- proxy

`/api/v2/cmdb/system/ha`

`mode: standalone` on a non-HA unit. The device answers in full even with no cluster.

```json
{
  "group-id": 0,
  "group-name": "",
  "mode": "standalone",
  "sync-packet-balance": "disable",
  "password": "<redacted>",
  "key": "<redacted>",
  "...": "(+74 more keys)"
}
```

### config system ha -- FMG

`/pm/config/device/<device>/global/system/ha`

Same setting from FMG's copy, but enum-encoded: `mode: 0` rather than the string `standalone`.

```json
{
  "mode": 0,
  "group-name": null,
  "group-id": 0,
  "priority": 128,
  "override": 0
}
```

### get system ha status -- proxy

`/api/v2/monitor/system/ha-statistics`

Empty on a standalone unit -- a successful call with nothing to report, not a failure.

```json
[]
```

### get system ha status (peers) -- proxy

`/api/v2/monitor/system/ha-peer`

```json
[]
```

### get system ha status -- FMG

`/dvmdb/adom/root/device/<device>/ha_slave`

`ha_slave` lists cluster members; empty for a standalone device.

```json
[]
```

### diagnose sys ha checksum cluster -- proxy

`/api/v2/monitor/system/ha-checksums`

Empty without a cluster. On an HA pair this carries the per-member checksums to compare.

```json
[]
```

### diag sys ha history read -- proxy

`/api/v2/monitor/system/ha-history`

```json
{}
```

### get system interface physical -- proxy

`/api/v2/monitor/system/interface?scope=global`

Keyed by interface name. `link`, `speed`, `ip` and the counters are the live values.

```json
{
  "port1": {
    "id": "port1",
    "name": "port1",
    "alias": "",
    "mac": "00:00:5e:00:53:00",
    "ip": "192.0.2.1",
    "mask": 24,
    "...": "(+9 more keys)"
  },
  "port2": {
    "id": "port2",
    "name": "port2",
    "alias": "",
    "mac": "00:00:5e:00:53:00",
    "ip": "192.0.2.1",
    "mask": 24,
    "...": "(+9 more keys)"
  }
}
```

### config system interface -- proxy

`/api/v2/cmdb/system/interface?vdom=root`

Configuration, not state -- `status: up/down` here is the admin setting. Use the monitor call above for the actual link.

```json
[
  {
    "name": "fortilink",
    "q_origin_key": "fortilink",
    "vdom": "root",
    "vrf": 0,
    "cli-conn-status": 0,
    "fortilink": "enable",
    "...": "(+214 more keys)"
  },
  "...(+6 more)"
]
```

### config system interface -- FMG

`/pm/config/device/<device>/global/system/interface`

```json
[
  {
    "aggregate-type": 0,
    "allowaccess": 16543,
    "ap-discover": 1,
    "arpforward": 1,
    "auto-auth-extension-device": 0,
    "bandwidth-measure-time": 0,
    "...": "(+141 more keys)"
  },
  "...(+6 more)"
]
```

### execute sensor list -- proxy

`/api/v2/monitor/system/sensor-info`

`null` results: rejected on a VM (`-6 Invalid url`). Hardware-only, untested here.

```json
null
```

### system resource usage -- proxy

`/api/v2/monitor/system/resource/usage`

CPU/memory/session with per-metric history. The VM-safe health signal when sensors are unavailable.

```json
{
  "cpu": [
    "...(object, elided)"
  ],
  "mem": [
    "...(object, elided)"
  ],
  "disk": [
    "...(object, elided)"
  ],
  "session": [
    "...(object, elided)"
  ],
  "session6": [
    "...(object, elided)"
  ],
  "setuprate": [
    "...(object, elided)"
  ],
  "...": "(+9 more keys)"
}
```

### system performance status -- proxy

`/api/v2/monitor/system/performance/status`

```json
{
  "cpu": {
    "cores": "...(list, elided)",
    "user": 0,
    "system": 0,
    "nice": 0,
    "idle": 100,
    "iowait": 0
  },
  "mem": {
    "total": 4071018496,
    "used": 1279447040,
    "free": 2347843584,
    "freeable": 443727872
  }
}
```

### config router static -- proxy

`/api/v2/cmdb/router/static?vdom=root`

```json
[
  {
    "seq-num": 1,
    "q_origin_key": 1,
    "status": "enable",
    "dst": "0.0.0.0 0.0.0.0",
    "src": "0.0.0.0 0.0.0.0",
    "gateway": "192.0.2.1",
    "...": "(+17 more keys)"
  },
  "...(+8 more)"
]
```

### config router static -- FMG

`/pm/config/device/<device>/vdom/root/router/static`

FMG's copy carries `oid` and list-wraps values (`dst` as a list) where FortiOS returns a string.

```json
[
  {
    "oid": 4346,
    "seq-num": 1,
    "dst": [
      "0.0.0.0",
      "...(+1 more)"
    ],
    "gateway": "192.0.2.1",
    "distance": 10,
    "priority": 1,
    "...": "(+16 more keys)"
  },
  "...(+8 more)"
]
```

### config router bgp -- proxy

`/api/v2/cmdb/router/bgp?vdom=root`

Answers with the full BGP object even when BGP is unconfigured -- `as: ""` is the tell, not an empty response.

```json
{
  "as": "",
  "router-id": "",
  "keepalive-timer": 60,
  "holdtime-timer": 180,
  "always-compare-med": "disable",
  "bestpath-as-path-ignore": "disable",
  "...": "(+60 more keys)"
}
```

### config router bgp -- FMG

`/pm/config/device/<device>/vdom/root/router/bgp`

```json
{
  "additional-path": 0,
  "additional-path-select-vpnv4": 2,
  "additional-path-select-vpnv6": 2,
  "additional-path-vpnv4": 0,
  "additional-path-vpnv6": 0,
  "additional-path6": 0,
  "...": "(+54 more keys)"
}
```

### get router info bgp summary -- proxy

`/api/v2/monitor/router/bgp/neighbors`

Empty when no peers are configured.

```json
[]
```

### bgp paths statistics -- proxy

`/api/v2/monitor/router/bgp/paths-statistics`

```json
{
  "total": 0,
  "ipv4": 0,
  "ipv6": 0
}
```

### routing table -- proxy

`/api/v2/monitor/router/ipv4`

```json
[
  {
    "ip_version": 4,
    "type": "static",
    "origin": "unspecified",
    "ip_mask": "0.0.0.0/0",
    "distance": 10,
    "metric": 0,
    "...": "(+5 more keys)"
  },
  "...(+10 more)"
]
```

### firewall policy -- proxy

`/api/v2/cmdb/firewall/policy?vdom=root`

Policies as the device holds them, which is what an install is supposed to have produced.

```json
[
  {
    "policyid": 1,
    "q_origin_key": 1,
    "status": "enable",
    "name": "Block All Traffic to Threat Feed",
    "uuid": "<uuid>",
    "uuid-idx": 16401,
    "...": "(+184 more keys)"
  },
  "...(+1 more)"
]
```

### fortiguard server info -- proxy

`/api/v2/monitor/system/fortiguard/server-info`

Empty object here. Use `license/status` below for a usable FortiGuard signal.

```json
{}
```

### licence / entitlement -- proxy

`/api/v2/monitor/license/status`

The closest thing to `get webfilter status`: FortiGuard reachability plus per-service entitlement.

```json
{
  "fortiguard": {
    "type": "cloud_service_status",
    "supported": true,
    "connected": true,
    "has_connected": true,
    "connection_issue": false,
    "last_connection_success": 1787147129,
    "...": "(+5 more keys)"
  },
  "forticare": {
    "type": "cloud_service_status",
    "status": "registered",
    "registration_status": "registered",
    "registration_supported": true,
    "account": "<account>",
    "support": "...(object, elided)",
    "...": "(+2 more keys)"
  },
  "forticloud": {
    "type": "cloud_service_status",
    "status": "cloud_na"
  },
  "security_rating": {
    "type": "functionality_enabling",
    "status": "licensed",
    "expires": 1807660800,
    "entitlement": "FGSA"
  },
  "antivirus": {
    "type": "downloaded_fds_object",
    "status": "licensed",
    "version": "1.00001",
    "expires": 1807660800,
    "entitlement": "AVDB",
    "last_update": 1775094480,
    "...": "(+2 more keys)"
  },
  "mobile_malware": {
    "type": "downloaded_fds_object",
    "status": "licensed",
    "version": "0.00000",
    "expires": 1807660800,
    "entitlement": "AVDB",
    "last_update": 978264000
  },
  "...": "(+44 more keys)"
}
```

### webfilter category quota -- proxy

`/api/v2/monitor/webfilter/category-quota`

Empty unless quotas are configured -- describes quota, not service health.

```json
[]
```

### webfilter profiles -- FMG

`/pm/config/device/<device>/vdom/root/webfilter/profile`

```json
[
  {
    "antiphish": null,
    "ftgd-wf": "...(object, elided)",
    "oid": 3802,
    "override": "...(object, elided)",
    "url-extraction": null,
    "web": "...(object, elided)",
    "...": "(+20 more keys)"
  },
  "...(+3 more)"
]
```

### device VDOM list -- FMG

`/dvmdb/adom/root/device/<device>/vdom`

One row per VDOM; feeds the `?vdom=` parameter of every per-VDOM call above.

```json
[
  {
    "comments": "",
    "devid": "<device>",
    "ext_flags": 5,
    "flags": 0,
    "name": "root",
    "node_flags": 0,
    "...": "(+7 more keys)"
  }
]
```

### FortiGuard URL rating (POST) -- proxy

`/api/v2/monitor/utm/rating-lookup`

The verified write shape: `action: post` plus a `payload` object.

```json
[
  {
    "url": "www.fortinet.com"
  }
]
```
