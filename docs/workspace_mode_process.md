Yes. Here is a compact section you can add for **common payload and response examples**.

## Common JSON-RPC Payload and Response Examples

These examples follow the FortiManager JSON-RPC format shown in the reference. The common workspace actions use `method: "exec"` for lock, commit, and unlock, and `method: "get"` for status checks like `lockinfo` and `dirty`. A successful response typically returns `status.code: 0` and `status.message: "OK"`. ADOM commit responses may also include a `taskid`. ([How To FortiManager API][1])

### 1. Lock an ADOM

**Request**

```json
{
  "id": 1,
  "method": "exec",
  "params": [
    {
      "url": "/dvmdb/adom/demo/workspace/lock"
    }
  ],
  "session": "{{session}}"
}
```

**Response**

```json
{
  "id": 1,
  "result": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "url": "/dvmdb/adom/demo/workspace/lock"
    }
  ]
}
```

This is the standard pattern for locking an ADOM workspace. ([How To FortiManager API][1])

### 2. Commit changes in an ADOM

**Request**

```json
{
  "id": 1,
  "method": "exec",
  "params": [
    {
      "url": "/dvmdb/adom/demo/workspace/commit"
    }
  ],
  "session": "{{session}}"
}
```

**Response**

```json
{
  "id": 1,
  "result": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "taskid": 3332,
      "url": "/dvmdb/adom/demo/workspace/commit"
    }
  ]
}
```

The reference notes that commit is required before unlocking if you want to preserve pending changes. ([How To FortiManager API][1])

### 3. Unlock an ADOM

**Request**

```json
{
  "id": 1,
  "method": "exec",
  "params": [
    {
      "url": "/dvmdb/adom/demo/workspace/unlock"
    }
  ],
  "session": "{{session}}"
}
```

**Response**

```json
{
  "id": 1,
  "result": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "url": "/dvmdb/adom/demo/workspace/unlock"
    }
  ]
}
```

Unlocking without a prior commit discards unsaved changes. ([How To FortiManager API][1])

### 4. Check whether an ADOM has unsaved changes

**Request**

```json
{
  "id": 4,
  "method": "get",
  "params": [
    {
      "url": "/dvmdb/adom/demo/workspace/dirty"
    }
  ],
  "session": "{{session}}"
}
```

**Example response**

```json
{
  "id": 4,
  "result": [
    {
      "data": {
        "dirty": 1
      },
      "status": {
        "code": 0,
        "message": "OK"
      },
      "url": "/dvmdb/adom/demo/workspace/dirty"
    }
  ]
}
```

FortiManager maintains a `dirty` flag where `0` means no unsaved changes and `1` means a save or commit is required before unlock. The example response above is a concise normalized form for documentation; the source confirms the flag semantics and workflow. ([How To FortiManager API][1])

### 5. Check ADOM lock ownership

**Request**

```json
{
  "id": 3,
  "method": "get",
  "params": [
    {
      "url": "/dvmdb/adom/demo/workspace/lockinfo"
    }
  ],
  "session": "{{session}}",
  "verbose": 1
}
```

**Response**

```json
{
  "id": 3,
  "result": [
    {
      "data": [
        {
          "adom_dirty": 0,
          "db_mode": 1,
          "dev_oid": 399,
          "dirty": 0,
          "flags": 0,
          "lock_sid": 37154,
          "lock_time": 1714077048,
          "lock_user": "devops",
          "obj_cat": 0,
          "obj_oid": 0,
          "obj_url": "",
          "type": 1,
          "wfsid": 0
        }
      ],
      "status": {
        "code": 0,
        "message": "OK"
      },
      "url": "/dvmdb/adom/demo/workspace/lockinfo"
    }
  ]
}
```

When the ADOM is locked, `lockinfo` returns lock metadata such as `lock_user`, `lock_time`, and dirty state. When it is not locked, nothing special is returned. ([How To FortiManager API][1])

### 6. Lock a policy package

**Request**

```json
{
  "id": 3,
  "method": "exec",
  "params": [
    {
      "url": "/dvmdb/adom/demo/workspace/lock/pkg/ppkg_001"
    }
  ],
  "session": "{{session}}"
}
```

**Response**

```json
{
  "id": 3,
  "result": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "url": "/dvmdb/adom/demo/workspace/lock/pkg/ppkg_001"
    }
  ]
}
```

Package locking uses the same JSON-RPC shape as ADOM locking; only the URL changes. ([How To FortiManager API][1])

### 7. Lock a firewall policy inside a package

**Request**

```json
{
  "id": 3,
  "method": "exec",
  "params": [
    {
      "url": "/dvmdb/adom/demo/workspace/lock/pkg/ppkg_001/firewall/policy/1"
    }
  ],
  "session": "{{session}}"
}
```

**Response**

```json
{
  "id": 3,
  "result": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "url": "/dvmdb/adom/demo/workspace/lock/pkg/ppkg_001/firewall/policy/1"
    }
  ]
}
```

This is the more granular package-scoped lock used before object-level work in some cases. ([How To FortiManager API][1])

### 8. Lock a device

**Request**

```json
{
  "id": 1,
  "method": "exec",
  "params": [
    {
      "url": "/dvmdb/adom/demo/workspace/lock/dev/dev_001"
    }
  ],
  "session": "{{session}}"
}
```

**Response**

```json
{
  "id": 1,
  "result": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "url": "/dvmdb/adom/demo/workspace/lock/dev/dev_001"
    }
  ]
}
```

Device lock support is documented in the reference and follows the same request pattern. ([How To FortiManager API][1])

### 9. Commit a device lock

**Request**

```json
{
  "id": 1,
  "method": "exec",
  "params": [
    {
      "url": "/dvmdb/adom/demo/workspace/commit/dev/dev_001"
    }
  ],
  "session": "{{session}}"
}
```

**Example response**

```json
{
  "id": 1,
  "result": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "url": "/dvmdb/adom/demo/workspace/commit/dev/dev_001"
    }
  ]
}
```

The device commit endpoint is explicitly shown in the reference. The response above is a concise normalized example based on the same successful `exec` response pattern used throughout the workspace operations. ([How To FortiManager API][1])

### 10. Unlock a device

**Request**

```json
{
  "id": 1,
  "method": "exec",
  "params": [
    {
      "url": "/dvmdb/adom/demo/workspace/unlock/dev/dev_001"
    }
  ],
  "session": "{{session}}"
}
```

**Example response**

```json
{
  "id": 1,
  "result": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "url": "/dvmdb/adom/demo/workspace/unlock/dev/dev_001"
    }
  ]
}
```

The source documents the device unlock endpoint immediately after ADOM unlock; the response shape remains the same. ([How To FortiManager API][1])

### 11. Lock an object after taking the higher-level lock

Before locking an object, you must first lock the containing policy package or firewall policy. The documented object endpoint is based on the normal object path. ([How To FortiManager API][1])

**Request**

```json
{
  "id": 5,
  "method": "exec",
  "params": [
    {
      "url": "/dvmdb/adom/demo/workspace/obj/firewall/address/host_001"
    }
  ],
  "session": "{{session}}"
}
```

**Example response**

```json
{
  "id": 5,
  "result": [
    {
      "status": {
        "code": 0,
        "message": "OK"
      },
      "url": "/dvmdb/adom/demo/workspace/obj/firewall/address/host_001"
    }
  ]
}
```

The reference lists the object-lock path format and example object paths such as `/firewall/address/host_001` and `/firewall/addrgrp/grp_001`. ([How To FortiManager API][1])

## Minimal task sequence examples

### Common ADOM sequence

```json
// 1. lock
{"method":"exec","params":[{"url":"/dvmdb/adom/demo/workspace/lock"}],"session":"{{session}}","id":1}

// 2. make config changes with normal add/set/update calls

// 3. check dirty
{"method":"get","params":[{"url":"/dvmdb/adom/demo/workspace/dirty"}],"session":"{{session}}","id":2}

// 4. commit if dirty=1
{"method":"exec","params":[{"url":"/dvmdb/adom/demo/workspace/commit"}],"session":"{{session}}","id":3}

// 5. unlock
{"method":"exec","params":[{"url":"/dvmdb/adom/demo/workspace/unlock"}],"session":"{{session}}","id":4}
```

This sequence is directly aligned with the documented workspace behavior for ADOM locking, dirty checking, commit, and unlock. ([How To FortiManager API][1])

### Common package sequence

```json
// 1. lock package
{"method":"exec","params":[{"url":"/dvmdb/adom/demo/workspace/lock/pkg/ppkg_001"}],"session":"{{session}}","id":1}

// 2. make package changes

// 3. commit package
{"method":"exec","params":[{"url":"/dvmdb/adom/demo/workspace/commit/pkg/ppkg_001"}],"session":"{{session}}","id":2}

// 4. unlock package
{"method":"exec","params":[{"url":"/dvmdb/adom/demo/workspace/unlock/pkg/ppkg_001"}],"session":"{{session}}","id":3}
```

The package flow is the same as ADOM flow, with only the scoped URL changing. ([How To FortiManager API][1])

If you want, I can rewrite the full knowledge document and insert these examples directly under each workflow section.

[1]: https://how-to-fortimanager-api.readthedocs.io/en/latest/013_adom_management.html "14. ADOM management — How to FortiManager API - Mon Mar 30 13:19:58 2026"
