"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import importlib
import sys
import os
from unittest.mock import MagicMock, patch, call

import pytest

# Add the repo root to the path so the connector package is importable without
# a real FortiSOAR environment.
current_directory = os.path.dirname(__file__)
repo_root = os.path.abspath(os.path.join(current_directory, os.pardir, os.pardir))
sys.path.insert(0, repo_root)

generic_json_rpc = importlib.import_module("fortinet-fortimanager-json-rpc.generic_json_rpc")

parse_minimal_lock_scope = generic_json_rpc.parse_minimal_lock_scope
lock_minimal_scope = generic_json_rpc.lock_minimal_scope
commit_minimal_scope = generic_json_rpc.commit_minimal_scope
unlock_minimal_scope = generic_json_rpc.unlock_minimal_scope
NO_LOCK_URLS = generic_json_rpc.NO_LOCK_URLS


# ---------------------------------------------------------------------------
# parse_minimal_lock_scope
# ---------------------------------------------------------------------------

class TestParseMinimalLockScope:
    def test_package_url_returns_pkg_scope(self):
        url = "/pm/config/adom/root/pkg/My_Policy/firewall/policy"
        scope_type, scope_id = parse_minimal_lock_scope(url)
        assert scope_type == "pkg"
        assert scope_id == "My_Policy"

    def test_package_url_with_hyphens(self):
        url = "/pm/config/adom/root/pkg/corp-edge-policy/firewall/address"
        scope_type, scope_id = parse_minimal_lock_scope(url)
        assert scope_type == "pkg"
        assert scope_id == "corp-edge-policy"

    def test_package_url_non_root_adom(self):
        url = "/pm/config/adom/prod_adom/pkg/ppkg_001/firewall/policy/1"
        scope_type, scope_id = parse_minimal_lock_scope(url)
        assert scope_type == "pkg"
        assert scope_id == "ppkg_001"

    def test_device_url_dev_prefix(self):
        url = "/dvmdb/adom/root/dev/dev_001/vdom/root"
        scope_type, scope_id = parse_minimal_lock_scope(url)
        assert scope_type == "dev"
        assert scope_id == "dev_001"

    def test_device_url_device_prefix(self):
        url = "/dvmdb/device/FGT60F0123456789"
        scope_type, scope_id = parse_minimal_lock_scope(url)
        assert scope_type == "dev"
        assert scope_id == "FGT60F0123456789"

    def test_package_takes_priority_over_device(self):
        # Some pkg paths may also contain /device/ further down; pkg must win.
        url = "/pm/config/adom/root/pkg/my_pkg/device/FGT1"
        scope_type, scope_id = parse_minimal_lock_scope(url)
        assert scope_type == "pkg"
        assert scope_id == "my_pkg"

    def test_no_match_returns_none(self):
        url = "/sys/status"
        scope_type, scope_id = parse_minimal_lock_scope(url)
        assert scope_type is None
        assert scope_id is None

    def test_securityconsole_url_returns_none(self):
        url = "/securityconsole/install/package"
        scope_type, scope_id = parse_minimal_lock_scope(url)
        assert scope_type is None
        assert scope_id is None

    def test_dvmdb_adom_url_without_pkg_or_dev_returns_none(self):
        url = "/dvmdb/adom/root/workspace/lockinfo"
        scope_type, scope_id = parse_minimal_lock_scope(url)
        assert scope_type is None
        assert scope_id is None

    def test_object_database_url_returns_none(self):
        # ADOM object database paths don't contain /pkg/ or /device/
        url = "/pm/config/adom/root/obj/firewall/address/host_001"
        scope_type, scope_id = parse_minimal_lock_scope(url)
        assert scope_type is None
        assert scope_id is None


# ---------------------------------------------------------------------------
# NO_LOCK_URLS
# ---------------------------------------------------------------------------

class TestNoLockUrls:
    def test_install_device_excluded(self):
        assert "/securityconsole/install/device" in NO_LOCK_URLS

    def test_install_package_excluded(self):
        assert "/securityconsole/install/package" in NO_LOCK_URLS

    def test_install_preview_excluded(self):
        assert "/securityconsole/install/preview" in NO_LOCK_URLS

    def test_non_excluded_url_not_in_set(self):
        assert "/pm/config/adom/root/pkg/mypkg/firewall/policy" not in NO_LOCK_URLS

    def test_is_frozenset(self):
        assert isinstance(NO_LOCK_URLS, frozenset)


# ---------------------------------------------------------------------------
# lock_minimal_scope
# ---------------------------------------------------------------------------

class TestLockMinimalScope:
    def _make_fmg(self, status_sequence):
        """Return a mock fmg whose execute() returns successive (status, {}) pairs."""
        fmg = MagicMock()
        fmg.execute.side_effect = [(s, {}) for s in status_sequence]
        return fmg

    def test_success_on_first_attempt(self):
        fmg = self._make_fmg([0])
        result = lock_minimal_scope(fmg, "root", "pkg", "my_pkg", "/some/url", {})
        assert result is True
        fmg.execute.assert_called_once_with(url="/dvmdb/adom/root/workspace/lock/pkg/my_pkg")

    def test_workspace_not_enabled_returns_true(self):
        # status -9 means workspace is disabled — no lock needed, should succeed
        fmg = self._make_fmg([-9])
        result = lock_minimal_scope(fmg, "root", "pkg", "my_pkg", "/some/url", {})
        assert result is True

    def test_invalid_url_returns_false(self):
        # status -6 means the adom/pkg/device doesn't exist
        fmg = self._make_fmg([-6])
        result = lock_minimal_scope(fmg, "root", "pkg", "nonexistent_pkg", "/some/url", {})
        assert result is False

    def test_success_after_retry(self):
        # Fail twice, then succeed
        fmg = self._make_fmg([-10, -10, 0])
        with patch.object(generic_json_rpc.time, "sleep"):
            with patch.object(generic_json_rpc.random, "randint", return_value=1):
                result = lock_minimal_scope(fmg, "root", "dev", "dev_001", "/some/url", {})
        assert result is True
        assert fmg.execute.call_count == 3

    def test_correct_lock_url_for_dev_scope(self):
        fmg = self._make_fmg([0])
        lock_minimal_scope(fmg, "prod", "dev", "FGT_HQ", "/some/url", {})
        fmg.execute.assert_called_once_with(url="/dvmdb/adom/prod/workspace/lock/dev/FGT_HQ")

    def test_max_retry_returns_false(self):
        # All attempts return a retriable error; only run a small number to keep tests fast.
        with patch.object(generic_json_rpc, "MAX_RETRY_LIMIT", 3):
            fmg = self._make_fmg([-10, -10, -10])
            with patch.object(generic_json_rpc.time, "sleep"):
                with patch.object(generic_json_rpc.random, "randint", return_value=1):
                    result = lock_minimal_scope(fmg, "root", "pkg", "my_pkg", "/some/url", {})
        assert result is False


# ---------------------------------------------------------------------------
# commit_minimal_scope
# ---------------------------------------------------------------------------

class TestCommitMinimalScope:
    def test_calls_execute_with_correct_pkg_url(self):
        fmg = MagicMock()
        commit_minimal_scope(fmg, "root", "pkg", "my_pkg")
        fmg.execute.assert_called_once_with(url="/dvmdb/adom/root/workspace/commit/pkg/my_pkg")

    def test_calls_execute_with_correct_dev_url(self):
        fmg = MagicMock()
        commit_minimal_scope(fmg, "prod", "dev", "FGT_HQ")
        fmg.execute.assert_called_once_with(url="/dvmdb/adom/prod/workspace/commit/dev/FGT_HQ")


# ---------------------------------------------------------------------------
# unlock_minimal_scope
# ---------------------------------------------------------------------------

class TestUnlockMinimalScope:
    def test_calls_execute_with_correct_pkg_url(self):
        fmg = MagicMock()
        unlock_minimal_scope(fmg, "root", "pkg", "my_pkg")
        fmg.execute.assert_called_once_with(url="/dvmdb/adom/root/workspace/unlock/pkg/my_pkg")

    def test_calls_execute_with_correct_dev_url(self):
        fmg = MagicMock()
        unlock_minimal_scope(fmg, "prod", "dev", "FGT_HQ")
        fmg.execute.assert_called_once_with(url="/dvmdb/adom/prod/workspace/unlock/dev/FGT_HQ")
