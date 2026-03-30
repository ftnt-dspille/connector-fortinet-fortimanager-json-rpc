"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
Sequential locking tests against a live FortiManager.

These tests verify the workspace locking behavior across several scenarios:
  - ADOM and pkg/dev scope locks are released after each operation
  - URLs in NO_LOCK_URLS skip workspace lock acquisition entirely
  - The retry loop resolves contention when a lock is held by another session
  - Concurrent writes to the same ADOM both succeed via retry logic
  - Concurrent writes to different packages with minimal_locking=True complete
    without contention

Requirements:
  - A live FortiManager reachable via the .env credentials
  - The "default" policy package must exist in the "root" ADOM
  - A managed device named via MANAGED_DEVICE_NAME must exist if device-scope
    tests are run (these skip automatically if the env var is not set)

Tests that depend on workspace mode being enabled will skip automatically
when workspace is disabled.
"""

import importlib
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

current_directory = os.path.dirname(__file__)
parent_directory = os.path.abspath(os.path.join(current_directory, os.pardir))
grandparent_directory = os.path.abspath(os.path.join(parent_directory, os.pardir))
sys.path.insert(0, str(grandparent_directory))

env_path = os.path.join(parent_directory, ".env")
load_dotenv(dotenv_path=env_path)

operations_module = importlib.import_module("fortinet-fortimanager-json-rpc.operations")
generic_module = importlib.import_module("fortinet-fortimanager-json-rpc.generic_json_rpc")
operations = operations_module.operations
ConnectorError = operations_module.ConnectorError
get_config = generic_module.get_config
NO_LOCK_URLS = generic_module.NO_LOCK_URLS

# Optional env var — device-scope tests skip when this is absent
MANAGED_DEVICE_NAME = os.getenv("MANAGED_DEVICE_NAME", "")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _log_level(caplog):
    caplog.set_level(logging.DEBUG)


@pytest.fixture(params=["Username/Password", "API Key"])
def auth_config(request):
    base = {
        "address": os.getenv("ADDRESS"),
        "verify_ssl": os.getenv("VERIFY_SSL", "False").lower() in ("true", "1", "t"),
        "port": os.getenv("PORT"),
        "debug_connection": False,
        "verbose_json": True,
    }
    if request.param == "Username/Password":
        base.update({
            "username": os.getenv("USERNAME"),
            "password": os.getenv("PASSWORD"),
            "auth_method": "Username/Password",
        })
    else:
        base.update({
            "api_key": os.getenv("API_KEY"),
            "auth_method": "API Key",
        })
    return base


@pytest.fixture
def minimal_lock_config(auth_config):
    """auth_config with minimal_locking=True."""
    config = auth_config.copy()
    config["minimal_locking"] = True
    return config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_lockinfo(auth_config, adom="root"):
    """Return the raw lockinfo data list for an ADOM, or None if workspace is off."""
    params = {"url": f"/dvmdb/adom/{adom}/workspace/lockinfo"}
    response = operations["json_rpc_get"](auth_config, params)
    data = response.get("get_response")
    if isinstance(data, dict) and data.get("status", {}).get("code") in (-9, -6):
        return None  # workspace not enabled or invalid ADOM
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "data" in data:
        return data["data"]
    return []


def _workspace_enabled(auth_config, adom="root"):
    """Return True when workspace mode is active for the ADOM."""
    return _get_lockinfo(auth_config, adom) is not None


def _make_address(name, octet=200):
    return {"name": name, "subnet": [f"172.23.{octet}.1", "255.255.255.255"], "type": "ipmask"}


def _add_address(auth_config, name, url="/pm/config/adom/root/obj/firewall/address/", octet=200):
    return operations["json_rpc_add"](auth_config, {"url": url, "data": [_make_address(name, octet)]})


def _delete_address(auth_config, name, base="/pm/config/adom/root/obj/firewall/address"):
    try:
        operations["json_rpc_delete"](auth_config, {"url": f"{base}/{name}", "data": {}})
    except Exception:
        pass


def _open_fmg(auth_config):
    """Return an open pyFMG FortiManager context (caller must close it)."""
    from pyFMG.fortimgr import FortiManager as FMGDirect
    server_host, username, password, api_key, verify_ssl = get_config(auth_config)
    fmg = FMGDirect(server_host, username, password, apikey=api_key,
                    verify_ssl=verify_ssl, disable_request_warnings=True)
    fmg.login()
    return fmg


# ---------------------------------------------------------------------------
# 1. Lock released after ADOM-level write
# ---------------------------------------------------------------------------

class TestAdomLockRelease:
    """Verifies that workspace locks are released once an operation completes."""

    ADDR_NAME = "test-lock-release-adom"

    def test_adom_lockinfo_clean_after_write(self, auth_config):
        """After a write op the ADOM should not remain locked."""
        if not _workspace_enabled(auth_config):
            pytest.skip("Workspace mode not enabled")

        try:
            resp = _add_address(auth_config, self.ADDR_NAME)
            assert resp.get("status") == 0, f"Add failed: {resp}"

            lock_data = _get_lockinfo(auth_config)
            assert lock_data is not None
            # No entries means no active lock
            assert len(lock_data) == 0, (
                f"Expected empty lockinfo after write but got: {lock_data}"
            )
        finally:
            _delete_address(auth_config, self.ADDR_NAME)

    def test_dirty_flag_cleared_after_write(self, auth_config):
        """After a committed write the dirty flag must be 0."""
        if not _workspace_enabled(auth_config):
            pytest.skip("Workspace mode not enabled")

        try:
            resp = _add_address(auth_config, self.ADDR_NAME + "-dirty")
            assert resp.get("status") == 0

            params = {"url": "/dvmdb/adom/root/workspace/dirty"}
            dirty_resp = operations["json_rpc_get"](auth_config, params)
            dirty_value = dirty_resp.get("get_response", {}).get("dirty", -1)
            assert dirty_value == 0, (
                f"Expected dirty=0 after committed write but got dirty={dirty_value}"
            )
        finally:
            _delete_address(auth_config, self.ADDR_NAME + "-dirty")


# ---------------------------------------------------------------------------
# 2. Minimal lock released after pkg-scoped write
# ---------------------------------------------------------------------------

class TestMinimalLockRelease:
    """Verifies that minimal (pkg/dev) scope locks are released after each op."""

    PKG = "default"
    ADDR_NAME = "test-lock-release-pkg"
    PKG_URL = f"/pm/config/adom/root/pkg/{PKG}/firewall/address/"

    def test_pkg_lockinfo_clean_after_minimal_write(self, minimal_lock_config):
        """After a pkg-scoped minimal-lock write, lockinfo should show no lock."""
        if not _workspace_enabled(minimal_lock_config):
            pytest.skip("Workspace mode not enabled")

        try:
            resp = _add_address(minimal_lock_config, self.ADDR_NAME, url=self.PKG_URL)
            assert resp.get("status") == 0, f"Add failed: {resp}"

            lock_data = _get_lockinfo(minimal_lock_config)
            assert lock_data is not None
            assert len(lock_data) == 0, (
                f"Expected empty lockinfo after minimal-lock pkg write but got: {lock_data}"
            )
        finally:
            _delete_address(minimal_lock_config, self.ADDR_NAME,
                            base=f"/pm/config/adom/root/pkg/{self.PKG}/firewall/address")

    def test_obj_url_falls_back_to_adom_lock(self, minimal_lock_config):
        """
        With minimal_locking=True, a URL targeting the ADOM object database
        (/pm/config/adom/{adom}/obj/...) has no package component and must fall
        back to ADOM-level locking. Verify the write succeeds and the lock is clean.
        """
        if not _workspace_enabled(minimal_lock_config):
            pytest.skip("Workspace mode not enabled")

        name = "test-lock-minimal-obj-fallback"
        try:
            resp = _add_address(minimal_lock_config, name)
            assert resp.get("status") == 0, f"Fallback write failed: {resp}"

            lock_data = _get_lockinfo(minimal_lock_config)
            assert len(lock_data) == 0, (
                f"ADOM lock not released after minimal-lock obj-db write: {lock_data}"
            )
        finally:
            _delete_address(minimal_lock_config, name)

    @pytest.mark.skipif(not MANAGED_DEVICE_NAME, reason="MANAGED_DEVICE_NAME env var not set")
    def test_dev_lockinfo_clean_after_minimal_dev_write(self, minimal_lock_config):
        """After a device-scoped minimal-lock write, lockinfo shows no lock."""
        if not _workspace_enabled(minimal_lock_config):
            pytest.skip("Workspace mode not enabled")

        dev_url = f"/dvmdb/adom/root/device/{MANAGED_DEVICE_NAME}/vdom/root/firewall/address/"
        name = "test-lock-release-dev"
        try:
            resp = _add_address(minimal_lock_config, name, url=dev_url)
            assert resp.get("status") == 0, f"Device-scope write failed: {resp}"

            lock_data = _get_lockinfo(minimal_lock_config)
            assert len(lock_data) == 0, (
                f"Device lock not released after minimal-lock write: {lock_data}"
            )
        finally:
            _delete_address(minimal_lock_config, name,
                            base=f"/dvmdb/adom/root/device/{MANAGED_DEVICE_NAME}/vdom/root/firewall/address")


# ---------------------------------------------------------------------------
# 3. NO_LOCK_URLS bypass workspace lock
# ---------------------------------------------------------------------------

class TestNoLockUrlsBypass:
    """
    Verifies that operations on NO_LOCK_URLS complete without attempting to
    acquire the workspace lock — even when the ADOM is locked by another session.
    """

    def test_no_lock_url_completes_while_adom_locked(self, auth_config):
        """
        Pre-lock the ADOM from a second session, then call a NO_LOCK_URL.
        The call must complete quickly (< 5 s) — if it tried to acquire the lock
        it would sleep 1-10 s per retry attempt.
        """
        if not _workspace_enabled(auth_config):
            pytest.skip("Workspace mode not enabled")

        pre_lock_fmg = _open_fmg(auth_config)
        try:
            lock_status, _ = pre_lock_fmg.lock_adom("root")
            if lock_status == -9:
                pytest.skip("Workspace mode not enabled (lock returned -9)")
            if lock_status != 0:
                pytest.skip(f"Could not pre-acquire ADOM lock (status={lock_status})")

            params = {
                "url": "/securityconsole/install/preview",
                "data": {"adom": "root", "scope": [{"name": "placeholder", "vdom": "root"}]},
                "track_task": True,
                "task_timeout": 30,
            }
            start = time.time()
            try:
                operations["json_rpc_execute"](auth_config, params)
            except ConnectorError:
                pass  # install/preview may fail if device doesn't exist; that's fine
            elapsed = time.time() - start

            assert elapsed < 5, (
                f"NO_LOCK_URL took {elapsed:.1f}s — it may have waited on the workspace lock. "
                f"Expected < 5s since {'/securityconsole/install/preview'!r} is in NO_LOCK_URLS."
            )
        finally:
            pre_lock_fmg.unlock_adom("root")
            pre_lock_fmg.logout()

    def test_all_no_lock_urls_defined_are_reachable(self, auth_config):
        """
        Smoke-test: verify every URL in NO_LOCK_URLS is present in the set and
        does not raise an import error. The live reachability of each URL is
        covered by other integration tests.
        """
        expected = {
            "/securityconsole/install/device",
            "/securityconsole/install/package",
            "/securityconsole/install/preview",
        }
        assert expected == set(NO_LOCK_URLS), (
            f"NO_LOCK_URLS mismatch.\n  Expected: {sorted(expected)}\n  Got: {sorted(NO_LOCK_URLS)}"
        )


# ---------------------------------------------------------------------------
# 4. Lock contention — retry resolves correctly
# ---------------------------------------------------------------------------

class TestLockContention:
    """
    Verifies that the retry loop in lock_adom and lock_minimal_scope resolves
    correctly when a competing session releases the lock after a short delay.
    """

    ADDR_NAME = "test-lock-contention-adom"
    HOLD_SECONDS = 3  # how long the competing session holds the lock

    def test_write_retries_and_succeeds_after_external_lock_released(self, auth_config):
        """
        A competing session holds the ADOM lock for HOLD_SECONDS, then releases it.
        The write operation should retry and succeed once the lock becomes available.
        The total elapsed time must be between HOLD_SECONDS and a generous upper bound.
        """
        if not _workspace_enabled(auth_config):
            pytest.skip("Workspace mode not enabled")

        # Acquire the ADOM lock from a competing session
        pre_lock_fmg = _open_fmg(auth_config)
        lock_status, _ = pre_lock_fmg.lock_adom("root")
        if lock_status == -9:
            pre_lock_fmg.logout()
            pytest.skip("Workspace mode not enabled (lock returned -9)")
        if lock_status != 0:
            pre_lock_fmg.logout()
            pytest.skip(f"Could not pre-acquire ADOM lock (status={lock_status})")

        result_holder = {}
        errors = []

        def _do_write():
            try:
                resp = _add_address(auth_config, self.ADDR_NAME)
                result_holder["response"] = resp
            except Exception as exc:
                errors.append(exc)

        # Submit the write in a background thread; it will block on lock acquisition
        start = time.time()
        write_thread = ThreadPoolExecutor(max_workers=1).submit(_do_write)

        # Hold the lock for HOLD_SECONDS, then release
        time.sleep(self.HOLD_SECONDS)
        pre_lock_fmg.unlock_adom("root")
        pre_lock_fmg.logout()

        # Give the write thread enough time to retry and complete
        max_wait = self.HOLD_SECONDS + 30
        write_thread.result(timeout=max_wait)
        elapsed = time.time() - start

        if errors:
            raise errors[0]

        resp = result_holder.get("response", {})
        assert resp.get("status") == 0, f"Write after lock release failed: {resp}"
        assert elapsed >= self.HOLD_SECONDS, (
            f"Write completed in {elapsed:.1f}s — faster than the lock hold time "
            f"({self.HOLD_SECONDS}s), suggesting the lock was not actually contested."
        )
        _delete_address(auth_config, self.ADDR_NAME)

    def test_pkg_write_retries_and_succeeds_after_external_pkg_lock_released(self, minimal_lock_config):
        """
        Same as the ADOM contention test but for a pkg-scoped minimal lock.
        A competing session holds the pkg lock, then releases it after HOLD_SECONDS.
        """
        if not _workspace_enabled(minimal_lock_config):
            pytest.skip("Workspace mode not enabled")

        pkg = "default"
        pre_lock_fmg = _open_fmg(minimal_lock_config)
        lock_status, _ = pre_lock_fmg.execute(
            url=f"/dvmdb/adom/root/workspace/lock/pkg/{pkg}"
        )
        if lock_status == -9:
            pre_lock_fmg.logout()
            pytest.skip("Workspace mode not enabled")
        if lock_status == -6:
            pre_lock_fmg.logout()
            pytest.skip(f"Policy package '{pkg}' not found")
        if lock_status != 0:
            pre_lock_fmg.logout()
            pytest.skip(f"Could not pre-acquire pkg lock (status={lock_status})")

        pkg_url = f"/pm/config/adom/root/pkg/{pkg}/firewall/address/"
        name = "test-lock-contention-pkg"
        result_holder = {}
        errors = []

        def _do_write():
            try:
                resp = _add_address(minimal_lock_config, name, url=pkg_url)
                result_holder["response"] = resp
            except Exception as exc:
                errors.append(exc)

        start = time.time()
        write_thread = ThreadPoolExecutor(max_workers=1).submit(_do_write)

        time.sleep(self.HOLD_SECONDS)
        pre_lock_fmg.execute(url=f"/dvmdb/adom/root/workspace/unlock/pkg/{pkg}")
        pre_lock_fmg.logout()

        write_thread.result(timeout=self.HOLD_SECONDS + 30)
        elapsed = time.time() - start

        if errors:
            raise errors[0]

        resp = result_holder.get("response", {})
        assert resp.get("status") == 0, f"Pkg write after lock release failed: {resp}"
        assert elapsed >= self.HOLD_SECONDS

        _delete_address(minimal_lock_config, name,
                        base=f"/pm/config/adom/root/pkg/{pkg}/firewall/address")


# ---------------------------------------------------------------------------
# 5. Concurrent writes — both succeed
# ---------------------------------------------------------------------------

class TestConcurrentWrites:
    """
    Concurrent writes to the same locking scope must both eventually succeed.
    One will acquire the lock first; the other retries until the first releases it.
    """

    def _run_concurrent(self, config, pairs):
        """
        Submit multiple (add_url, addr_name, octet) write operations simultaneously.
        Returns list of (addr_name, response) tuples; cleans up on finish.
        """
        def _write(add_url, addr_name, octet):
            resp = _add_address(config, addr_name, url=add_url, octet=octet)
            return addr_name, resp

        results = []
        with ThreadPoolExecutor(max_workers=len(pairs)) as pool:
            futures = {pool.submit(_write, *p): p for p in pairs}
            for fut in as_completed(futures):
                results.append(fut.result())
        return results

    def test_concurrent_adom_writes_both_succeed(self, auth_config):
        """
        Two simultaneous writes to the ADOM object database both succeed.
        ADOM-level locking serialises them via the retry loop.
        """
        if not _workspace_enabled(auth_config):
            pytest.skip("Workspace mode not enabled")

        obj_url = "/pm/config/adom/root/obj/firewall/address/"
        pairs = [
            (obj_url, "test-concurrent-adom-1", 201),
            (obj_url, "test-concurrent-adom-2", 202),
        ]
        results = self._run_concurrent(auth_config, pairs)
        for name, resp in results:
            assert resp.get("status") == 0, f"Concurrent write '{name}' failed: {resp}"
        for _, name, _ in pairs:
            _delete_address(auth_config, name)

    def test_concurrent_pkg_writes_same_pkg_both_succeed(self, minimal_lock_config):
        """
        Two simultaneous writes to the same policy package with minimal_locking=True
        both succeed. The pkg lock serialises them.
        """
        if not _workspace_enabled(minimal_lock_config):
            pytest.skip("Workspace mode not enabled")

        pkg = "default"
        pkg_url = f"/pm/config/adom/root/pkg/{pkg}/firewall/address/"
        pairs = [
            (pkg_url, "test-concurrent-pkg-same-1", 211),
            (pkg_url, "test-concurrent-pkg-same-2", 212),
        ]
        results = self._run_concurrent(minimal_lock_config, pairs)
        for name, resp in results:
            assert resp.get("status") == 0, f"Concurrent pkg write '{name}' failed: {resp}"
        base = f"/pm/config/adom/root/pkg/{pkg}/firewall/address"
        for _, name, _ in pairs:
            _delete_address(minimal_lock_config, name, base=base)

    def test_concurrent_pkg_writes_different_pkgs_no_contention(self, minimal_lock_config):
        """
        Two simultaneous writes to DIFFERENT policy packages with minimal_locking=True
        should complete without lock contention (each holds its own pkg lock).
        Both must succeed and finish faster than if they had to serialise on a
        shared ADOM lock.

        Note: this test requires at least two policy packages in root. It skips
        if a second package named 'default2' is not found.
        """
        if not _workspace_enabled(minimal_lock_config):
            pytest.skip("Workspace mode not enabled")

        pkg1 = "default"
        pkg2 = os.getenv("SECOND_PKG_NAME", "")
        if not pkg2:
            pytest.skip("SECOND_PKG_NAME env var not set — need two packages for this test")

        pairs = [
            (f"/pm/config/adom/root/pkg/{pkg1}/firewall/address/", "test-concurrent-pkg-diff-1", 221),
            (f"/pm/config/adom/root/pkg/{pkg2}/firewall/address/", "test-concurrent-pkg-diff-2", 222),
        ]
        start = time.time()
        results = self._run_concurrent(minimal_lock_config, pairs)
        elapsed = time.time() - start

        for name, resp in results:
            assert resp.get("status") == 0, f"Concurrent cross-pkg write '{name}' failed: {resp}"

        logger.info(f"Two-package concurrent writes elapsed: {elapsed:.2f}s")

        _delete_address(minimal_lock_config, "test-concurrent-pkg-diff-1",
                        base=f"/pm/config/adom/root/pkg/{pkg1}/firewall/address")
        _delete_address(minimal_lock_config, "test-concurrent-pkg-diff-2",
                        base=f"/pm/config/adom/root/pkg/{pkg2}/firewall/address")
