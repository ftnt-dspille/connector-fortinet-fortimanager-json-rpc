## Testing the JSON RPC Connector

### Setup

1. `cd` into the `tests` directory.
   ```bash
   cd fortimanager-json-rpc/tests
   ```

2. Copy the example env file and fill in your values.
   ```bash
   cp .env.example .env
   ```

3. Edit `.env` with the credentials for your FortiManager instance.

   | Variable              | Required | Description                                                                                                                  |
   |-----------------------|----------|------------------------------------------------------------------------------------------------------------------------------|
   | `ADDRESS`             | Yes      | IP or hostname of the FortiManager (e.g. `https://192.168.1.1`)                                                              |
   | `PORT`                | Yes      | API port (default `443`)                                                                                                     |
   | `USERNAME`            | Yes      | FMG user with read-write JSON API access                                                                                     |
   | `PASSWORD`            | Yes      | Password for the above user                                                                                                  |
   | `API_KEY`             | Yes      | REST API key — the key's trusted host list must include the machine running the tests                                        |
   | `VERIFY_SSL`          | No       | `True` / `False` (default `False`)                                                                                           |
   | `DEBUG_CONNECTION`    | No       | `True` / `False` — enables pyFMG debug output (default `False`)                                                              |
   | `VERBOSE_JSON`        | No       | `True` / `False` — adds `verbose` flag to requests so FMG returns string labels instead of integers (default `True`)         |
   | `MANAGED_DEVICE_NAME` | No       | Name of a managed FortiGate device — required only for device-scope locking tests (see below)                                |
   | `SECOND_PKG_NAME`     | No       | Name of a second policy package in the `root` ADOM — required only for the no-contention concurrent-package test (see below) |

4. Create a virtual environment and install dependencies.
   ```bash
   uv venv
   uv pip install -r requirements.txt
   ```

---

### Running the full test suite

```bash
uv run python run_tests.py
```

`run_tests.py` automatically toggles workspace mode on the FMG and runs all tests twice — once with workspace mode **enabled** and once **disabled** — so every code path is exercised. Each test is also run with both Username/Password and API Key authentication. The script restores the original workspace mode when it finishes.

> **Note:** The script requires the `USERNAME`/`PASSWORD` credentials to be able to set `/cli/global/system/global` on the FMG.

Sample output (abbreviated):

```
Current workspace mode: 1
sequential/test_sequential_fortimanager_rpc.py .............   [100%]  13 passed in 47.34s
concurrent/test_concurrent_fortimanager_rpc.py ....           [100%]   4 passed in 18.74s
All tests passed
Setting workspace mode to 0
sequential/test_sequential_fortimanager_rpc.py .............   [100%]  13 passed in 31.37s
concurrent/test_concurrent_fortimanager_rpc.py ....           [100%]   4 passed in  3.76s
All tests passed
Setting workspace mode to 1
```

---

### Running individual test suites

All commands below should be run from inside the `tests/` directory.

#### Unit tests — no live FMG required

Unit tests cover pure-Python logic (URL parsing, lock scope detection, helper functions) and run entirely with mocks. They are fast and safe to run anywhere.

```bash
uv run pytest unit/ -v
```

#### Sequential integration tests

Sequential tests run one at a time and verify end-to-end behaviour against a live FMG.

```bash
# All sequential tests
uv run pytest sequential/ -v

# Only the locking tests
uv run pytest sequential/test_locking_fortimanager_rpc.py -v

# Only the general connector tests
uv run pytest sequential/test_sequential_fortimanager_rpc.py -v
```

#### Concurrent integration tests

Concurrent tests fire multiple operations in parallel to verify the lock retry logic under real contention.

```bash
uv run pytest concurrent/ -n 4 -v
```

---

### Test structure

```
tests/
├── unit/
│   └── test_unit_generic_json_rpc.py   # Pure-logic tests — no FMG needed
├── sequential/
│   ├── test_sequential_fortimanager_rpc.py   # General connector tests
│   └── test_locking_fortimanager_rpc.py      # Workspace locking tests (see below)
├── concurrent/
│   └── test_concurrent_fortimanager_rpc.py   # Parallel add/delete stress tests
└── scripts/
    └── fmg_multi_session_apikey_connector.py  # Standalone parallel stress script
```

---

### Workspace locking tests

`test_locking_fortimanager_rpc.py` contains tests that specifically exercise the workspace locking feature. All tests skip automatically when workspace mode is disabled on the FMG, so they are safe to include in the full suite regardless of your FMG configuration.

#### TestAdomLockRelease
Verifies that ADOM-level workspace locks are fully released and changes committed after each write operation.

- `test_adom_lockinfo_clean_after_write` — performs a write and checks that `lockinfo` returns no active locks immediately after.
- `test_dirty_flag_cleared_after_write` — checks that the ADOM `dirty` flag is `0` after the operation, confirming the commit succeeded.

#### TestMinimalLockRelease
Verifies the **Minimal Locking (Beta)** feature acquires and releases the right scope.

- `test_pkg_lockinfo_clean_after_minimal_write` — writes to a policy package URL; confirms the pkg-scoped lock is released.
- `test_obj_url_falls_back_to_adom_lock` — writes to an ADOM object-database URL (no `/pkg/` component); confirms the fallback to ADOM-level locking succeeds and releases cleanly.
- `test_dev_lockinfo_clean_after_minimal_dev_write` — writes using a device-scoped URL; requires `MANAGED_DEVICE_NAME` to be set, otherwise skips.

#### TestNoLockUrlsBypass
Verifies that URLs in `NO_LOCK_URLS` skip workspace lock acquisition entirely.

- `test_no_lock_url_completes_while_adom_locked` — pre-locks the ADOM from a second FMG session, then calls `/securityconsole/install/preview`. The call must complete in under 5 seconds, proving it did not wait on the lock. If it had tried to acquire the lock it would have slept 1-10 seconds per retry attempt.
- `test_all_no_lock_urls_defined_are_reachable` — smoke-test confirming the `NO_LOCK_URLS` set contains exactly the expected entries.

The following URLs currently bypass workspace locking:

| URL | Reason |
|---|---|
| `/securityconsole/install/device` | Installs already-committed config to a device — does not modify the ADOM |
| `/securityconsole/install/package` | Same as above, package scope |
| `/securityconsole/install/preview` | Read-only preview of pending install diff |

#### TestLockContention
Verifies that the retry loop resolves correctly when a lock is held by a competing session.

- `test_write_retries_and_succeeds_after_external_lock_released` — a second FMG session holds the ADOM lock for 3 seconds; the write operation retries in a background thread and succeeds after the competing lock is released. The elapsed time is asserted to be ≥ 3 seconds to confirm contention actually occurred.
- `test_pkg_write_retries_and_succeeds_after_external_pkg_lock_released` — same scenario but for a pkg-scoped minimal lock.

#### TestConcurrentWrites
Verifies that two simultaneous writes to the same locking scope both eventually succeed.

- `test_concurrent_adom_writes_both_succeed` — two threads write to the same ADOM object database; ADOM-level locking serialises them.
- `test_concurrent_pkg_writes_same_pkg_both_succeed` — two threads write to the same policy package with `minimal_locking=True`; pkg-level locking serialises them.
- `test_concurrent_pkg_writes_different_pkgs_no_contention` — two threads write to **different** packages with `minimal_locking=True`; they should hold separate pkg locks and not block each other. Requires `SECOND_PKG_NAME` to be set, otherwise skips.

---

### Minimal Locking (Beta) — connector configuration

The **Minimal Locking** feature is an opt-in checkbox in the connector configuration. When enabled, the connector locks at the most granular scope the URL supports instead of always locking the full ADOM. This reduces contention when multiple automation workers are writing to different parts of the ADOM simultaneously.

| URL pattern | Lock scope |
|---|---|
| `/pm/config/adom/{adom}/pkg/{pkg}/...` | Policy package (`pkg`) |
| `/dvmdb/.../dev/{dev}/...` or `.../device/{dev}/...` | Device (`dev`) |
| Everything else | ADOM (fallback) |

> **Important:** The "default" policy package must exist in the `root` ADOM for the pkg-scope locking tests to pass. If your environment uses a different package name, update the `PKG = "default"` constant in `test_locking_fortimanager_rpc.py`.
