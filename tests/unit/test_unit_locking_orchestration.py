"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

# End-to-end tests for the lock/commit/unlock sequence perform_rpc_action drives.
# The helper-level tests in test_unit_generic_json_rpc.py cover URL parsing and the
# individual workspace calls; these pin the *orchestration* -- which lock is taken,
# in what order the commit and unlock fire, and that the legacy ADOM-locking path is
# untouched when minimal_locking is off (the default for every existing user).

import importlib
import os
import sys
from unittest.mock import patch

import pytest

current_directory = os.path.dirname(__file__)
repo_root = os.path.abspath(os.path.join(current_directory, os.pardir, os.pardir))
sys.path.insert(0, repo_root)

generic_json_rpc = importlib.import_module("fortinet-fortimanager-json-rpc.generic_json_rpc")

BASE_CONFIG = {
    "address": "fortimanager.example.com",
    "username": "user",
    "password": "<password>",
    "auth_method": "Credentials",
}
MINIMAL = dict(BASE_CONFIG, minimal_locking=True)

PKG_URL = "/pm/config/adom/root/pkg/Pkg1/firewall/policy"
OBJ_URL = "/pm/config/adom/root/obj/firewall/address"


class _LockCtx:
    def __init__(self, uses_workspace):
        self.uses_workspace = uses_workspace


class FakeFMG:
    """Stands in for pyFMG, recording every call so the exact sequence can be asserted."""

    # Mirrors the package tree on a real appliance: flat packages alongside a
    # package nested in a folder, which is only addressable by its full path.
    DEFAULT_PACKAGES = [
        {"name": "Pkg1", "type": "pkg"},
        {"name": "PkgA", "type": "pkg"},
        {"name": "PkgB", "type": "pkg"},
        {"name": "folder1", "type": "folder",
         "subobj": [{"name": "package1", "type": "pkg"}]},
        {"name": "empty_folder", "type": "folder", "subobj": None},
    ]

    def __init__(self, uses_workspace=True, exec_result=(0, {"task": 42}), action_error=None,
                 packages=None, package_lookup_status=0):
        self._lock_ctx = _LockCtx(uses_workspace)
        self.calls = []
        self.exec_result = exec_result
        self.action_error = action_error
        self.packages = self.DEFAULT_PACKAGES if packages is None else packages
        self.package_lookup_status = package_lookup_status

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def lock_adom(self, adom):
        self.calls.append(("lock_adom", adom))
        return 0, {}

    def unlock_adom(self, adom):
        self.calls.append(("unlock_adom", adom))
        return 0, {}

    def commit_changes(self, adom):
        self.calls.append(("commit_changes", adom))
        return 0, {}

    def execute(self, url=None, **kwargs):
        self.calls.append(("execute", url))
        if "/workspace/" in (url or ""):
            return 0, {}
        if self.action_error:
            raise self.action_error
        return self.exec_result

    def get(self, url=None, **kwargs):
        self.calls.append(("get", url))
        if (url or "").startswith("/pm/pkg/adom/"):
            return self.package_lookup_status, self.packages
        return 0, {"result": []}

    def set(self, url=None, **kwargs):
        self.calls.append(("set", url))
        if self.action_error:
            raise self.action_error
        return 0, {"status": "OK"}

    def add(self, url=None, **kwargs):
        self.calls.append(("add", url))
        if self.action_error:
            raise self.action_error
        return 0, {"status": "OK"}

    def free_form(self, method, **kwargs):
        self.calls.append(("free_form", method))
        return 0, {}

    def track_task(self, task, **kwargs):
        self.calls.append(("track_task", task))
        return 0, {"state": "done"}


def run_action(fmg, action, params, config):
    """Drive perform_rpc_action against the fake, with retry sleeps disabled."""
    with patch.object(generic_json_rpc, "FortiManager", return_value=fmg), \
            patch.object(generic_json_rpc.time, "sleep"):
        return generic_json_rpc.perform_rpc_action(action, config, params)


def workspace_calls(fmg):
    return [url for name, url in fmg.calls if name == "execute" and "/workspace/" in (url or "")]


def lock_sequence(fmg):
    """Recorded calls minus the package-tree lookup, which is scope-resolution plumbing."""
    return [(name, url) for name, url in fmg.calls
            if not (name == "get" and (url or "").startswith("/pm/pkg/adom/"))]


# ---------------------------------------------------------------------------
# Legacy behaviour: minimal_locking off must stay exactly as it was
# ---------------------------------------------------------------------------

class TestLegacyAdomLocking:
    def test_set_locks_whole_adom_and_commits(self):
        fmg = FakeFMG()
        run_action(fmg, "set", {"url": PKG_URL, "data": {}}, BASE_CONFIG)
        assert fmg.calls == [
            ("lock_adom", "root"),
            ("set", PKG_URL),
            ("commit_changes", "root"),
        ]

    def test_execute_with_track_task_commits_twice_then_unlocks(self):
        fmg = FakeFMG()
        run_action(fmg, "execute", {"url": PKG_URL, "data": {}, "track_task": True}, BASE_CONFIG)
        assert fmg.calls == [
            ("lock_adom", "root"),
            ("execute", PKG_URL),
            ("commit_changes", "root"),
            ("track_task", 42),
            ("commit_changes", "root"),
            ("unlock_adom", "root"),
        ]

    def test_no_workspace_lock_calls_are_ever_issued(self):
        fmg = FakeFMG()
        run_action(fmg, "set", {"url": PKG_URL, "data": {}}, BASE_CONFIG)
        assert workspace_calls(fmg) == []


# ---------------------------------------------------------------------------
# Cases where no lock is required at all
# ---------------------------------------------------------------------------

class TestNoLockRequired:
    def test_get_never_locks(self):
        fmg = FakeFMG()
        run_action(fmg, "get", {"url": PKG_URL, "data": {}}, MINIMAL)
        assert fmg.calls == [("get", PKG_URL)]

    def test_workspace_mode_disabled_never_locks(self):
        fmg = FakeFMG(uses_workspace=False)
        run_action(fmg, "set", {"url": PKG_URL, "data": {}}, MINIMAL)
        assert fmg.calls == [("set", PKG_URL)]

    @pytest.mark.parametrize("url", sorted(generic_json_rpc.NO_LOCK_URLS))
    def test_install_urls_are_not_locked(self, url):
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {"url": url, "data": {"adom": "root"}}, MINIMAL)
        assert fmg.calls == [("execute", url)]

    @pytest.mark.parametrize("url", sorted(generic_json_rpc.NO_LOCK_URLS))
    def test_install_urls_are_not_locked_with_minimal_locking_off(self, url):
        # The NO_LOCK_URLS optimisation is unconditional, so pin it for legacy users too.
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {"url": url, "data": {"adom": "root"}}, BASE_CONFIG)
        assert fmg.calls == [("execute", url)]


# ---------------------------------------------------------------------------
# Minimal locking: happy paths
# ---------------------------------------------------------------------------

class TestMinimalLocking:
    def test_package_url_locks_only_the_package(self):
        fmg = FakeFMG()
        run_action(fmg, "set", {"url": PKG_URL, "data": {}}, MINIMAL)
        assert lock_sequence(fmg) == [
            ("execute", "/dvmdb/adom/root/workspace/lock/pkg/Pkg1"),
            ("set", PKG_URL),
            ("execute", "/dvmdb/adom/root/workspace/commit/pkg/Pkg1"),
            ("execute", "/dvmdb/adom/root/workspace/unlock/pkg/Pkg1"),
        ]

    def test_package_url_never_locks_the_adom(self):
        fmg = FakeFMG()
        run_action(fmg, "set", {"url": PKG_URL, "data": {}}, MINIMAL)
        assert not any(name in ("lock_adom", "commit_changes") for name, _ in fmg.calls)

    def test_device_url_locks_only_the_device(self):
        fmg = FakeFMG()
        url = "/dvmdb/adom/root/dev/FGT-A"
        run_action(fmg, "set", {"url": url, "data": {}}, MINIMAL)
        assert workspace_calls(fmg) == [
            "/dvmdb/adom/root/workspace/lock/dev/FGT-A",
            "/dvmdb/adom/root/workspace/commit/dev/FGT-A",
            "/dvmdb/adom/root/workspace/unlock/dev/FGT-A",
        ]

    def test_track_task_commits_and_unlocks_exactly_once(self):
        # A second commit/unlock pair would fire against a lock this session no
        # longer holds, and could hit a lock another worker has since taken.
        fmg = FakeFMG()
        run_action(fmg, "execute", {"url": PKG_URL, "data": {}, "track_task": True}, MINIMAL)
        assert workspace_calls(fmg) == [
            "/dvmdb/adom/root/workspace/lock/pkg/Pkg1",
            "/dvmdb/adom/root/workspace/commit/pkg/Pkg1",
            "/dvmdb/adom/root/workspace/unlock/pkg/Pkg1",
        ]

    def test_unlock_happens_after_the_task_is_tracked(self):
        fmg = FakeFMG()
        run_action(fmg, "execute", {"url": PKG_URL, "data": {}, "track_task": True}, MINIMAL)
        names = [name if name != "execute" else url for name, url in fmg.calls]
        assert names.index("track_task") < names.index("/dvmdb/adom/root/workspace/unlock/pkg/Pkg1")


# ---------------------------------------------------------------------------
# Minimal locking: fallbacks to ADOM-level locking
# ---------------------------------------------------------------------------

class TestMinimalLockingFallback:
    def test_object_database_url_falls_back_to_adom_lock(self):
        fmg = FakeFMG()
        run_action(fmg, "set", {"url": OBJ_URL, "data": {}}, MINIMAL)
        assert fmg.calls == [
            ("lock_adom", "root"),
            ("set", OBJ_URL),
            ("commit_changes", "root"),
        ]

    def test_global_adom_takes_no_lock_at_all(self):
        # "global" is not lockable on 7.6.7 -- both documented global lock URLs are
        # rejected -- so the request proceeds unlocked. It used to reach the same place
        # by calling lock_adom("global") and misreading the resulting -9 as "this
        # appliance has no workspace mode"; now it is an explicit decision.
        fmg = FakeFMG()
        url = "/pm/config/adom/global/pkg/Pkg1/firewall/policy"
        run_action(fmg, "set", {"url": url, "data": {}}, MINIMAL)
        assert fmg.calls == [("set", url)]
        assert workspace_calls(fmg) == []

    def test_free_form_spanning_two_packages_falls_back_to_adom_lock(self):
        # Locking only the first package would leave the writes to the second
        # package unlocked, and FMG rejects those with a permission error.
        fmg = FakeFMG()
        params = {
            "method": "set",
            "data": {"data": [
                {"url": "/pm/config/adom/root/pkg/PkgA/firewall/policy"},
                {"url": "/pm/config/adom/root/pkg/PkgB/firewall/policy"},
            ]},
        }
        run_action(fmg, "free_form", params, MINIMAL)
        assert lock_sequence(fmg) == [
            ("lock_adom", "root"),
            ("free_form", "set"),
            ("commit_changes", "root"),
        ]

    def test_free_form_within_one_package_still_uses_minimal_lock(self):
        fmg = FakeFMG()
        params = {
            "method": "set",
            "data": {"data": [
                {"url": "/pm/config/adom/root/pkg/PkgA/firewall/policy"},
                {"url": "/pm/config/adom/root/pkg/PkgA/firewall/address"},
            ]},
        }
        run_action(fmg, "free_form", params, MINIMAL)
        assert workspace_calls(fmg) == [
            "/dvmdb/adom/root/workspace/lock/pkg/PkgA",
            "/dvmdb/adom/root/workspace/commit/pkg/PkgA",
            "/dvmdb/adom/root/workspace/unlock/pkg/PkgA",
        ]


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------

class TestLockRelease:
    def test_minimal_lock_is_released_when_the_action_fails(self):
        # pyFMG's __exit__ only auto-unlocks ADOMs registered via lock_adom(), so a
        # leaked pkg/dev lock would block every other worker on that object.
        fmg = FakeFMG(action_error=RuntimeError("boom"))
        with pytest.raises(generic_json_rpc.ConnectorError):
            run_action(fmg, "set", {"url": PKG_URL, "data": {}}, MINIMAL)
        assert "/dvmdb/adom/root/workspace/unlock/pkg/Pkg1" in workspace_calls(fmg)

    def test_failed_action_does_not_commit(self):
        fmg = FakeFMG(action_error=RuntimeError("boom"))
        with pytest.raises(generic_json_rpc.ConnectorError):
            run_action(fmg, "set", {"url": PKG_URL, "data": {}}, MINIMAL)
        assert not any("/commit/" in url for url in workspace_calls(fmg))

    def test_failure_to_acquire_minimal_lock_raises(self):
        fmg = FakeFMG()
        with patch.object(generic_json_rpc, "lock_minimal_scope", return_value=False), \
                patch.object(generic_json_rpc, "FortiManager", return_value=fmg):
            with pytest.raises(generic_json_rpc.ConnectorError):
                generic_json_rpc.perform_rpc_action("set", MINIMAL, {"url": PKG_URL, "data": {}})
        # Nothing was locked, so nothing may be unlocked.
        assert workspace_calls(fmg) == []


# ---------------------------------------------------------------------------
# Packages nested in package folders
# ---------------------------------------------------------------------------

class TestNestedPackageScope:
    """
    Verified against a live FortiManager 8.0/7.6: a package inside a folder is only
    addressable by its full path. /pm/config/adom/root/pkg/folder1/package1/... is
    valid while /pm/config/adom/root/pkg/folder1/... returns -6 Invalid url, so
    locking the folder name alone fails every write in that package.
    """

    NESTED_URL = "/pm/config/adom/root/pkg/folder1/package1/firewall/policy"

    def test_nested_package_locks_the_full_path(self):
        fmg = FakeFMG()
        run_action(fmg, "set", {"url": self.NESTED_URL, "data": {}}, MINIMAL)
        assert workspace_calls(fmg) == [
            "/dvmdb/adom/root/workspace/lock/pkg/folder1/package1",
            "/dvmdb/adom/root/workspace/commit/pkg/folder1/package1",
            "/dvmdb/adom/root/workspace/unlock/pkg/folder1/package1",
        ]

    def test_nested_package_never_locks_only_the_folder(self):
        fmg = FakeFMG()
        run_action(fmg, "set", {"url": self.NESTED_URL, "data": {}}, MINIMAL)
        assert not any(url.endswith("/pkg/folder1") for url in workspace_calls(fmg))

    def test_flat_package_is_unaffected_by_the_lookup(self):
        fmg = FakeFMG()
        run_action(fmg, "set", {"url": PKG_URL, "data": {}}, MINIMAL)
        assert workspace_calls(fmg)[0] == "/dvmdb/adom/root/workspace/lock/pkg/Pkg1"

    def test_package_lookup_failure_falls_back_to_url_parsing(self):
        # A failed lookup must not break the operation; the single-segment guess is
        # still right for any package that is not inside a folder.
        fmg = FakeFMG(package_lookup_status=-11)
        run_action(fmg, "set", {"url": PKG_URL, "data": {}}, MINIMAL)
        assert workspace_calls(fmg)[0] == "/dvmdb/adom/root/workspace/lock/pkg/Pkg1"

    def test_package_lookup_is_skipped_for_device_urls(self):
        # No /pkg/ in the URL means no reason to pay for the package listing.
        fmg = FakeFMG()
        run_action(fmg, "set", {"url": "/dvmdb/adom/root/dev/FGT-A", "data": {}}, MINIMAL)
        assert not any(name == "get" and (url or "").startswith("/pm/pkg/adom/")
                       for name, url in fmg.calls)

    def test_package_lookup_is_skipped_when_minimal_locking_is_off(self):
        fmg = FakeFMG()
        run_action(fmg, "set", {"url": self.NESTED_URL, "data": {}}, BASE_CONFIG)
        assert not any(name == "get" and (url or "").startswith("/pm/pkg/adom/")
                       for name, url in fmg.calls)

    def test_free_form_within_one_nested_package_uses_that_scope(self):
        fmg = FakeFMG()
        params = {"method": "set", "data": {"data": [
            {"url": self.NESTED_URL},
            {"url": "/pm/config/adom/root/pkg/folder1/package1/firewall/address"},
        ]}}
        run_action(fmg, "free_form", params, MINIMAL)
        assert workspace_calls(fmg)[0] == "/dvmdb/adom/root/workspace/lock/pkg/folder1/package1"

    def test_free_form_across_folder_siblings_falls_back(self):
        fmg = FakeFMG(packages=[
            {"name": "folder1", "type": "folder", "subobj": [
                {"name": "package1", "type": "pkg"},
                {"name": "package2", "type": "pkg"},
            ]},
        ])
        params = {"method": "set", "data": {"data": [
            {"url": "/pm/config/adom/root/pkg/folder1/package1/firewall/policy"},
            {"url": "/pm/config/adom/root/pkg/folder1/package2/firewall/policy"},
        ]}}
        run_action(fmg, "free_form", params, MINIMAL)
        assert workspace_calls(fmg) == []
        assert ("lock_adom", "root") in fmg.calls


class TestListAdomPackages:
    def test_flattens_folders_into_full_paths(self):
        fmg = FakeFMG()
        assert set(generic_json_rpc.list_adom_packages(fmg, "root")) == {
            "Pkg1", "PkgA", "PkgB", "folder1/package1",
        }

    def test_empty_folder_contributes_nothing(self):
        fmg = FakeFMG(packages=[{"name": "empty_folder", "type": "folder", "subobj": None}])
        assert generic_json_rpc.list_adom_packages(fmg, "root") == []

    def test_lookup_failure_returns_empty_list(self):
        fmg = FakeFMG(package_lookup_status=-11)
        assert generic_json_rpc.list_adom_packages(fmg, "root") == []


# ---------------------------------------------------------------------------
# NO_LOCK_URLS membership, as measured against a live appliance
# ---------------------------------------------------------------------------

class TestMeasuredLockRequirements:
    """
    Each expectation here corresponds to a two-arm experiment run against a live
    FortiManager in workspace mode: the operation was performed with and without the
    workspace lock, and the queued task was followed to completion. The RPC status is
    0 in both arms for all of these, so only the task outcome distinguishes them.
    """

    def test_install_package_takes_a_lock(self):
        # Unlocked, the install task fails with "no write permission" while the RPC
        # still reports success. Putting this URL in NO_LOCK_URLS silently breaks
        # every install.
        assert "/securityconsole/install/package" not in generic_json_rpc.NO_LOCK_URLS
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute",
                   {"url": "/securityconsole/install/package",
                    "data": {"adom": "root", "pkg": "Pkg1"}}, BASE_CONFIG)
        assert ("lock_adom", "root") in fmg.calls

    def test_install_device_takes_a_lock(self):
        # Two-arm with a real pending device-DB change, 2/2 reproducible: unlocked the
        # task copies and then fails the save, a dev lock held across the task succeeds.
        assert "/securityconsole/install/device" not in generic_json_rpc.NO_LOCK_URLS
        fmg = FakeFMG(exec_result=(0, {"task": 42}))
        run_action(fmg, "execute",
                   {"url": "/securityconsole/install/device",
                    "data": {"adom": "root", "scope": [{"name": "fgt", "vdom": "root"}]}},
                   BASE_CONFIG)
        assert ("lock_adom", "root") in fmg.calls

    def test_install_device_takes_only_a_device_lock_under_minimal_locking(self):
        # A dev lock is sufficient, which is what makes this entry cheap to remove.
        fmg = FakeFMG(exec_result=(0, {"task": 42}))
        run_action(fmg, "execute",
                   {"url": "/securityconsole/install/device",
                    "data": {"adom": "root", "scope": [{"name": "fgt", "vdom": "root"}]}},
                   MINIMAL)
        assert not any(name == "lock_adom" for name, _ in fmg.calls)
        assert workspace_calls(fmg) == [
            "/dvmdb/adom/root/workspace/lock/dev/fgt",
            "/dvmdb/adom/root/workspace/commit/dev/fgt",
            "/dvmdb/adom/root/workspace/unlock/dev/fgt",
        ]

    def test_install_preview_skips_the_lock(self):
        assert "/securityconsole/install/preview" in generic_json_rpc.NO_LOCK_URLS

    def test_proxy_json_skips_the_lock(self):
        assert "/sys/proxy/json" in generic_json_rpc.NO_LOCK_URLS

    def test_proxy_json_no_longer_locks_the_global_adom(self):
        # /sys/proxy/json carries no ADOM in its URL or payload, so ADOM parsing falls
        # back to "global". Before this URL was excluded, every proxied device call
        # serialised all workers behind the global ADOM lock.
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {
            "url": "/sys/proxy/json",
            "data": {"target": ["adom/root/device/fgt"], "action": "get",
                     "resource": "/api/v2/monitor/system/status"},
        }, BASE_CONFIG)
        assert fmg.calls == [("execute", "/sys/proxy/json")]
        assert not any(name == "lock_adom" for name, _ in fmg.calls)

    def test_proxy_json_skips_the_lock_under_minimal_locking_too(self):
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {
            "url": "/sys/proxy/json",
            "data": {"target": ["adom/root/device/fgt"], "action": "get",
                     "resource": "/api/v2/monitor/system/status"},
        }, MINIMAL)
        assert fmg.calls == [("execute", "/sys/proxy/json")]

    def test_script_execute_takes_a_lock(self):
        # Running a CLI script without the lock produces a task with num_err=1,
        # for device_database and remote_device targets alike.
        assert "/dvmdb/adom/root/script/execute" not in generic_json_rpc.NO_LOCK_URLS
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {
            "url": "/dvmdb/adom/root/script/execute",
            "data": {"adom": "root", "script": "s1",
                     "scope": [{"name": "fgt", "vdom": "root"}]},
        }, BASE_CONFIG)
        assert ("lock_adom", "root") in fmg.calls

    def test_script_object_write_takes_a_lock(self):
        # CLI scripts moved to the ADOM object database in FMG 7.6.5 / 8.0.0, so the
        # write is an ordinary ADOM DB write and falls back to the ADOM lock.
        fmg = FakeFMG()
        run_action(fmg, "add",
                   {"url": "/pm/config/adom/root/obj/fmg/script", "data": {}}, MINIMAL)
        assert ("lock_adom", "root") in fmg.calls

    def test_adom_database_script_execute_takes_a_lock(self):
        # An adomdb-target script runs against a policy package and is addressed with a
        # "package" key, not the "scope" list device-targeted scripts use. Unlocked, its
        # task fails with num_err=1 while the RPC still returns 0.
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {
            "url": "/dvmdb/adom/root/script/execute",
            "data": {"adom": "root", "package": "Pkg1", "script": "s1"},
        }, BASE_CONFIG)
        assert ("lock_adom", "root") in fmg.calls


# ---------------------------------------------------------------------------
# Scope resolved from the request payload
# ---------------------------------------------------------------------------

class TestPayloadLockScope:
    """
    Several operations carry no scope in the URL but name one in the body. Each
    expectation below was verified end to end against a live FortiManager: the
    connector took the named lock and the resulting task completed with num_err=0.
    """

    EXEC_URL = "/dvmdb/adom/root/script/execute"

    def test_single_device_scope_locks_that_device(self):
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {"url": self.EXEC_URL, "data": {
            "adom": "root", "script": "s1",
            "scope": [{"name": "FGT-A", "vdom": "root"}]}}, MINIMAL)
        assert workspace_calls(fmg)[0] == "/dvmdb/adom/root/workspace/lock/dev/FGT-A"

    def test_package_key_locks_that_package(self):
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {"url": self.EXEC_URL, "data": {
            "adom": "root", "package": "PkgA", "script": "s1"}}, MINIMAL)
        assert workspace_calls(fmg)[0] == "/dvmdb/adom/root/workspace/lock/pkg/PkgA"

    def test_package_beats_device_when_both_are_present(self):
        # Verified live: installing a package while holding only the device lock fails
        # with "no write permission"; the package lock alone succeeds.
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {"url": "/securityconsole/install/package", "data": {
            "adom": "root", "pkg": "PkgA",
            "scope": [{"name": "FGT-A", "vdom": "root"}]}}, MINIMAL)
        assert workspace_calls(fmg)[0] == "/dvmdb/adom/root/workspace/lock/pkg/PkgA"

    def test_several_devices_fall_back_to_the_adom_lock(self):
        # One lock cannot cover two devices.
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {"url": self.EXEC_URL, "data": {
            "adom": "root", "script": "s1",
            "scope": [{"name": "FGT-A", "vdom": "root"},
                      {"name": "FGT-B", "vdom": "root"}]}}, MINIMAL)
        assert workspace_calls(fmg) == []
        assert ("lock_adom", "root") in fmg.calls

    def test_nested_package_named_by_leaf_resolves_to_full_path(self):
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {"url": self.EXEC_URL, "data": {
            "adom": "root", "package": "package1", "script": "s1"}}, MINIMAL)
        assert workspace_calls(fmg)[0] == \
            "/dvmdb/adom/root/workspace/lock/pkg/folder1/package1"

    def test_ambiguous_package_name_falls_back_to_the_adom_lock(self):
        # The same leaf name in two folders cannot be resolved, and locking the wrong
        # package would leave the real write unprotected.
        fmg = FakeFMG(exec_result=(0, {}), packages=[
            {"name": "folder1", "type": "folder",
             "subobj": [{"name": "shared", "type": "pkg"}]},
            {"name": "folder2", "type": "folder",
             "subobj": [{"name": "shared", "type": "pkg"}]},
        ])
        run_action(fmg, "execute", {"url": self.EXEC_URL, "data": {
            "adom": "root", "package": "shared", "script": "s1"}}, MINIMAL)
        assert workspace_calls(fmg) == []
        assert ("lock_adom", "root") in fmg.calls

    def test_payload_scope_is_ignored_when_minimal_locking_is_off(self):
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {"url": self.EXEC_URL, "data": {
            "adom": "root", "script": "s1",
            "scope": [{"name": "FGT-A", "vdom": "root"}]}}, BASE_CONFIG)
        assert workspace_calls(fmg) == []
        assert ("lock_adom", "root") in fmg.calls

    def test_url_scope_still_wins_over_payload_scope(self):
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {
            "url": "/pm/config/adom/root/pkg/Pkg1/firewall/policy",
            "data": {"scope": [{"name": "FGT-A", "vdom": "root"}]}}, MINIMAL)
        assert workspace_calls(fmg)[0] == "/dvmdb/adom/root/workspace/lock/pkg/Pkg1"

    def test_adom_key_alone_is_not_treated_as_a_scope(self):
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {
            "url": "/pm/config/adom/root/obj/firewall/address",
            "data": {"adom": "root", "name": "addr1"}}, MINIMAL)
        assert workspace_calls(fmg) == []
        assert ("lock_adom", "root") in fmg.calls

    def test_scope_entry_without_a_name_falls_back(self):
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {"url": self.EXEC_URL, "data": {
            "adom": "root", "script": "s1", "scope": [{"vdom": "root"}]}}, MINIMAL)
        assert ("lock_adom", "root") in fmg.calls

    def test_package_lookup_is_skipped_when_payload_has_no_package(self):
        fmg = FakeFMG(exec_result=(0, {}))
        run_action(fmg, "execute", {"url": self.EXEC_URL, "data": {
            "adom": "root", "script": "s1",
            "scope": [{"name": "FGT-A", "vdom": "root"}]}}, MINIMAL)
        assert not any(name == "get" and (url or "").startswith("/pm/pkg/adom/")
                       for name, url in fmg.calls)


# ---------------------------------------------------------------------------
# auto_lock_ws: FortiManager locks server-side, so the connector must not
# ---------------------------------------------------------------------------

INSTALL_PACKAGE_URL = "/securityconsole/install/package"


class TestAutoLockWorkspaceFlag:
    """
    Callers that send flags: ["auto_lock_ws"] ask FMG to take the workspace lock itself.
    Measured on a live 7.6.7 appliance: with the connector's package lock held, such an
    install produces a task that fails with "failed to lock adom" (FMG's auto-lock is
    ADOM-wide and a held pkg lock blocks the ADOM lock), while the same install with no
    connector lock completes. The connector must therefore stand aside.
    """

    AUTO_LOCK_PAYLOAD = {"data": {"adom": "root", "pkg": "Pkg1",
                                  "scope": [{"name": "dev1", "vdom": "root"}],
                                  "flags": ["auto_lock_ws"]}}

    @pytest.mark.parametrize("config", [BASE_CONFIG, MINIMAL])
    def test_no_lock_is_taken_when_the_payload_asks_fmg_to_lock(self, config):
        fmg = FakeFMG()
        run_action(fmg, "execute", dict(self.AUTO_LOCK_PAYLOAD, url=INSTALL_PACKAGE_URL), config)
        assert workspace_calls(fmg) == []
        assert ("lock_adom", "root") not in fmg.calls

    def test_install_still_runs_when_the_lock_is_skipped(self):
        fmg = FakeFMG()
        run_action(fmg, "execute", dict(self.AUTO_LOCK_PAYLOAD, url=INSTALL_PACKAGE_URL), MINIMAL)
        assert ("execute", INSTALL_PACKAGE_URL) in fmg.calls

    def test_the_same_install_without_the_flag_is_still_locked(self):
        # Guards against the flag check swallowing the ordinary path: install/package
        # with no flag is REQUIRED (measured), and must keep taking a lock.
        fmg = FakeFMG()
        params = {"url": INSTALL_PACKAGE_URL,
                  "data": {"adom": "root", "pkg": "Pkg1",
                           "scope": [{"name": "dev1", "vdom": "root"}]}}
        run_action(fmg, "execute", params, MINIMAL)
        assert any("/workspace/lock" in call for call in workspace_calls(fmg))

    def test_flag_is_found_inside_a_free_form_payload(self):
        fmg = FakeFMG()
        params = {"method": "exec",
                  "data": {"data": [{"url": INSTALL_PACKAGE_URL, "adom": "root",
                                     "pkg": "Pkg1", "flags": ["auto_lock_ws"]}]}}
        run_action(fmg, "free_form", params, MINIMAL)
        assert workspace_calls(fmg) == []

    @pytest.mark.parametrize("flags", [["adom_rev", "auto_lock_ws"], "auto_lock_ws"])
    def test_flag_forms_that_appear_in_real_traffic(self, flags):
        fmg = FakeFMG()
        params = {"url": INSTALL_PACKAGE_URL,
                  "data": {"adom": "root", "pkg": "Pkg1", "flags": flags}}
        run_action(fmg, "execute", params, MINIMAL)
        assert workspace_calls(fmg) == []

    def test_unrelated_flags_do_not_skip_the_lock(self):
        fmg = FakeFMG()
        params = {"url": INSTALL_PACKAGE_URL,
                  "data": {"adom": "root", "pkg": "Pkg1", "flags": ["preview"]}}
        run_action(fmg, "execute", params, MINIMAL)
        assert any("/workspace/lock" in call for call in workspace_calls(fmg))


# ---------------------------------------------------------------------------
# reinstall/package carries its packages in target[], not "pkg"
# ---------------------------------------------------------------------------

REINSTALL_URL = "/securityconsole/reinstall/package"


class TestReinstallTargetScope:
    """
    Measured on a live 7.6.7 appliance: a single-package reinstall is authorised by a
    package lock (device scope or device-group scope alike), a two-package reinstall is
    rejected outright (-1) with a lock on only one of them, and any reinstall with no
    lock is rejected. So one package -> pkg lock, several -> ADOM, same rule the
    multi-device case already follows.
    """

    @staticmethod
    def _params(targets, **extra):
        return {"url": REINSTALL_URL,
                "data": dict({"adom": "root", "flags": ["generate_rev"],
                              "target": targets}, **extra)}

    def test_single_target_takes_the_package_lock(self):
        fmg = FakeFMG()
        run_action(fmg, "execute", self._params(
            [{"pkg": "Pkg1", "scope": [{"name": "dev1", "vdom": "root"}]}]), MINIMAL)
        assert "/dvmdb/adom/root/workspace/lock/pkg/Pkg1" in workspace_calls(fmg)

    def test_device_group_scope_still_takes_the_package_lock(self):
        # A group target omits vdom and names the group, but the lock that authorises
        # the reinstall is still the package one.
        fmg = FakeFMG()
        run_action(fmg, "execute", self._params(
            [{"pkg": "Pkg1", "scope": [{"name": "grp_001"}]}]), MINIMAL)
        assert "/dvmdb/adom/root/workspace/lock/pkg/Pkg1" in workspace_calls(fmg)

    def test_nested_package_in_a_target_resolves_to_its_full_path(self):
        fmg = FakeFMG()
        run_action(fmg, "execute", self._params(
            [{"pkg": "package1", "scope": [{"name": "dev1", "vdom": "root"}]}]), MINIMAL)
        assert "/dvmdb/adom/root/workspace/lock/pkg/folder1/package1" in workspace_calls(fmg)

    def test_two_packages_fall_back_to_the_adom_lock(self):
        fmg = FakeFMG()
        run_action(fmg, "execute", self._params(
            [{"pkg": "PkgA", "scope": [{"name": "dev1", "vdom": "root"}]},
             {"pkg": "PkgB", "scope": [{"name": "dev2", "vdom": "root"}]}]), MINIMAL)
        assert ("lock_adom", "root") in fmg.calls
        assert not any("/workspace/lock/pkg/" in call for call in workspace_calls(fmg))

    def test_one_package_across_two_devices_falls_back_to_the_adom_lock(self):
        # Two targets means two installs in one task; the second device is exactly the
        # multi-device case that already falls back.
        fmg = FakeFMG()
        run_action(fmg, "execute", self._params(
            [{"pkg": "Pkg1", "scope": [{"name": "dev1", "vdom": "root"}]},
             {"pkg": "Pkg1", "scope": [{"name": "dev2", "vdom": "root"}]}]), MINIMAL)
        assert ("lock_adom", "root") in fmg.calls

    def test_reinstall_is_still_locked_with_minimal_locking_off(self):
        fmg = FakeFMG()
        run_action(fmg, "execute", self._params(
            [{"pkg": "Pkg1", "scope": [{"name": "dev1", "vdom": "root"}]}]), BASE_CONFIG)
        assert ("lock_adom", "root") in fmg.calls

    def test_malformed_targets_do_not_crash_scope_resolution(self):
        for targets in ([], [{}], "Pkg1", [{"scope": [{"name": "dev1"}]}]):
            fmg = FakeFMG()
            run_action(fmg, "execute", self._params(targets), MINIMAL)
            assert ("lock_adom", "root") in fmg.calls


class TestFirmwareUpgradeNeedsNoLock:
    """
    Live two-arm result on 7.6.7 against a licensed FortiGate: the upgrade succeeds with
    no lock and equally with dev/<device> held across it, so the lock is pure overhead.
    Left unlisted, an upgrade carrying a real ADOM would lock that ADOM for the whole
    upgrade once track_task is set.
    """

    UPGRADE_URL = "/um/image/upgrade/ext"

    def _params(self, adom):
        return {"url": self.UPGRADE_URL, "track_task": True,
                "data": {"adom": adom, "create_task": "enable", "flags": 900,
                         "devices": [{"name": "dev1", "image": "7.6.7"}]}}

    @pytest.mark.parametrize("adom", ["root", ""])
    @pytest.mark.parametrize("config", [BASE_CONFIG, MINIMAL])
    def test_no_lock_is_taken_for_a_firmware_upgrade(self, adom, config):
        fmg = FakeFMG()
        run_action(fmg, "execute", self._params(adom), config)
        assert workspace_calls(fmg) == []
        assert not any(name == "lock_adom" for name, _ in fmg.calls)

    def test_the_upgrade_still_runs(self):
        fmg = FakeFMG()
        run_action(fmg, "execute", self._params("root"), MINIMAL)
        assert ("execute", self.UPGRADE_URL) in fmg.calls


# ---------------------------------------------------------------------------
# Lock lifetime: the installs whose lock must outlive the RPC
# ---------------------------------------------------------------------------

class TestLockHeldUntilTaskCompletes:
    """
    Measured three-arm on a live appliance with a pending change staged first: for these
    three URLs the arm that releases the lock at RPC return fails inside the queued task
    (or, for reinstall, is rejected outright), while holding it across the task succeeds.
    So the connector must follow the task before releasing, whether or not the caller
    asked for tracking.
    """

    INSTALL_DEVICE = {"url": "/securityconsole/install/device",
                      "data": {"adom": "root", "scope": [{"name": "fgt", "vdom": "root"}]}}

    @pytest.mark.parametrize("url", sorted(generic_json_rpc.HOLD_LOCK_UNTIL_TASK_URLS))
    def test_membership_is_pinned(self, url):
        assert generic_json_rpc.holds_lock_until_task(url)

    def test_script_execute_is_not_in_the_set(self):
        # The lock authorises the run; releasing it at RPC return does not break the
        # queued script. Adding it here would hold locks for no measured benefit.
        assert not generic_json_rpc.holds_lock_until_task("/dvmdb/adom/root/script/execute")

    def test_task_is_tracked_before_the_minimal_lock_is_released(self):
        fmg = FakeFMG(exec_result=(0, {"task": 42}))
        run_action(fmg, "execute", self.INSTALL_DEVICE, MINIMAL)
        names = [name for name, _ in fmg.calls]
        unlock_index = [i for i, (name, url) in enumerate(fmg.calls)
                        if name == "execute" and "/workspace/unlock/" in (url or "")][0]
        assert names.index("track_task") < unlock_index

    def test_task_is_tracked_before_the_adom_lock_is_released(self):
        fmg = FakeFMG(exec_result=(0, {"task": 42}))
        run_action(fmg, "execute", self.INSTALL_DEVICE, BASE_CONFIG)
        assert lock_sequence(fmg) == [
            ("lock_adom", "root"),
            ("execute", "/securityconsole/install/device"),
            ("commit_changes", "root"),
            ("track_task", 42),
            ("commit_changes", "root"),
            ("unlock_adom", "root"),
        ]

    def test_task_outcome_is_returned_even_though_it_was_not_requested(self):
        # The task is how an install reports failure, so a caller who never set
        # track_task still gets it -- but the top-level status stays the RPC's own.
        fmg = FakeFMG(exec_result=(7, {"task": 42}))
        response = run_action(fmg, "execute", self.INSTALL_DEVICE, MINIMAL)
        assert response["task_response"] == {"state": "done"}
        assert response["status"] == 7

    def test_missing_task_id_is_not_an_error_when_tracking_was_not_requested(self):
        fmg = FakeFMG(exec_result=(0, {"status": "No devices"}))
        response = run_action(fmg, "execute", self.INSTALL_DEVICE, MINIMAL)
        assert "error" not in response
        assert "task_response" not in response
        assert not any(name == "track_task" for name, _ in fmg.calls)

    def test_missing_task_id_still_errors_when_tracking_was_requested(self):
        fmg = FakeFMG(exec_result=(0, {"status": "No devices"}))
        params = dict(self.INSTALL_DEVICE, track_task=True)
        response = run_action(fmg, "execute", params, MINIMAL)
        assert response["task_response"] is None
        assert "No devices" in response["error"]

    def test_unlocked_urls_do_not_gain_implicit_tracking(self):
        # The hold only exists to protect a lock. install/preview takes none.
        fmg = FakeFMG(exec_result=(0, {"task": 42}))
        run_action(fmg, "execute",
                   {"url": "/securityconsole/install/preview", "data": {"adom": "root"}},
                   MINIMAL)
        assert not any(name == "track_task" for name, _ in fmg.calls)

    def test_reinstall_package_holds_its_package_lock_across_the_task(self):
        fmg = FakeFMG(exec_result=(0, {"task": 42}))
        run_action(fmg, "execute", {
            "url": "/securityconsole/reinstall/package",
            "data": {"adom": "root",
                     "target": [{"pkg": "Pkg1", "scope": [{"name": "fgt", "vdom": "root"}]}]},
        }, MINIMAL)
        names = [name for name, _ in fmg.calls]
        unlock_index = [i for i, (name, url) in enumerate(fmg.calls)
                        if name == "execute" and "/workspace/unlock/" in (url or "")][0]
        assert names.index("track_task") < unlock_index
        assert workspace_calls(fmg)[0] == "/dvmdb/adom/root/workspace/lock/pkg/Pkg1"


# ---------------------------------------------------------------------------
# Unlockable ADOMs: "global" and "no ADOM at all"
# ---------------------------------------------------------------------------

class TestUnlockableAdom:
    def test_unresolved_adom_is_empty_not_global(self):
        assert generic_json_rpc.parse_adom_from_input("/sys/status", {}) == ""

    def test_adom_is_lockable(self):
        assert generic_json_rpc.adom_is_lockable("root")
        assert not generic_json_rpc.adom_is_lockable("global")
        assert not generic_json_rpc.adom_is_lockable("")
        assert not generic_json_rpc.adom_is_lockable(None)

    def test_no_adom_takes_no_lock_and_never_calls_lock_adom(self):
        fmg = FakeFMG()
        run_action(fmg, "set", {"url": "/cli/global/system/admin/user", "data": {}}, MINIMAL)
        assert fmg.calls == [("set", "/cli/global/system/admin/user")]

    def test_minus_nine_still_means_workspaces_off_for_a_real_adom(self):
        # pyFMG can report uses_workspace=True on an appliance where workspace mode is
        # off (it checks an int where verbose mode returns a string). That escape hatch
        # must survive, or those users' writes start failing.
        fmg = FakeFMG()
        fmg.lock_adom = lambda adom: (fmg.calls.append(("lock_adom", adom)), (-9, {}))[1]
        assert generic_json_rpc.lock_adom(fmg, "root", "/url", {}) is True

    def test_minus_nine_is_a_failure_for_an_unlockable_adom(self):
        # The old branch returned True here, which is what silently disabled locking for
        # every global-resolving payload on every URL.
        fmg = FakeFMG()
        fmg.lock_adom = lambda adom: (-9, {})
        assert generic_json_rpc.lock_adom(fmg, "global", "/url", {}) is False
        assert generic_json_rpc.lock_adom(fmg, "", "/url", {}) is False


# ---------------------------------------------------------------------------
# Device onboarding: ADOM-only by the appliance's design
# ---------------------------------------------------------------------------

class TestAdomOnlyUrls:
    """
    Measured three-arm on a live appliance for add/device, add/dev-list and del/device:
    unlocked they fail -11, the ADOM lock works, and no device scope is available --
    the lock URL for a device that does not exist yet is rejected -10, and a dev lock on
    an existing device is granted and still does not authorise deleting it.
    """

    def test_dvm_urls_require_the_adom_lock(self):
        assert generic_json_rpc.requires_adom_lock("/dvm/cmd/add/device")
        assert generic_json_rpc.requires_adom_lock("/dvm/cmd/add/dev-list")
        assert generic_json_rpc.requires_adom_lock("/dvm/cmd/del/device")
        assert not generic_json_rpc.requires_adom_lock("/securityconsole/install/package")

    def test_device_shaped_payload_does_not_earn_a_device_lock(self):
        # A dvm payload carrying scope[] would otherwise resolve to dev/<name> and take
        # a lock the appliance grants but does not honour for this URL.
        fmg = FakeFMG(exec_result=(0, {"taskid": 42}))
        run_action(fmg, "execute", {
            "url": "/dvm/cmd/del/device",
            "data": {"adom": "root", "device": "fgt",
                     "scope": [{"name": "fgt", "vdom": "root"}]},
        }, MINIMAL)
        assert ("lock_adom", "root") in fmg.calls
        assert workspace_calls(fmg) == []

    def test_ordinary_urls_still_resolve_a_minimal_scope(self):
        fmg = FakeFMG(exec_result=(0, {"task": 42}))
        run_action(fmg, "execute", {
            "url": "/dvmdb/adom/root/script/execute",
            "data": {"adom": "root", "script": "s1",
                     "scope": [{"name": "fgt", "vdom": "root"}]},
        }, MINIMAL)
        assert workspace_calls(fmg)[0] == "/dvmdb/adom/root/workspace/lock/dev/fgt"


# ---------------------------------------------------------------------------
# Invariants. These are not tests of a feature, they are guards on two
# properties every path through perform_rpc_action must have, whatever the
# URL, action, or config. They exist so a future scope rule cannot quietly
# reintroduce the deadlock or the leak.
# ---------------------------------------------------------------------------

class SessionFakeFMG(FakeFMG):
    """
    FakeFMG that also models what pyFMG does at session exit.

    The legacy ADOM path never calls `unlock_adom` explicitly unless it tracked a task:
    `perform_rpc_action` wraps every call in `with FortiManager(...)`, and pyFMG's
    `__exit__` -> `logout()` -> `FMGLockContext.run_unlock()` releases every ADOM
    registered through `lock_adom`. That is a real release -- section I.4 measured the
    appliance dropping the lock at session end too -- but it is invisible to a fake that
    does not model it, which would make the balance invariant below unprovable for the
    ADOM path.

    Kept as a subclass rather than folded into FakeFMG because the existing tests assert
    exact `fmg.calls` lists and must not grow implicit entries.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._locked_adoms = []

    def lock_adom(self, adom):
        self._locked_adoms.append(adom)
        return super().lock_adom(adom)

    def unlock_adom(self, adom):
        if adom in self._locked_adoms:
            self._locked_adoms.remove(adom)
        return super().unlock_adom(adom)

    def __exit__(self, *exc_info):
        for adom in list(self._locked_adoms):
            self.unlock_adom(adom)
        return False


def lock_events(fmg):
    """(+1 per lock acquired, -1 per lock released), in call order."""
    events = []
    for name, url in fmg.calls:
        if name == "lock_adom":
            events.append(1)
        elif name == "unlock_adom":
            events.append(-1)
        elif name == "execute" and "/workspace/lock" in (url or ""):
            events.append(1)
        elif name == "execute" and "/workspace/unlock" in (url or ""):
            events.append(-1)
    return events


# Every combination the connector routes differently: ADOM-scoped object writes,
# package-scoped policy writes, nested packages, device-database writes, the
# execute URLs that take no lock, an install that now holds its lock across the
# task, and an ADOM-only command.
INVARIANT_CASES = [
    ("set", {"url": OBJ_URL, "data": {}}),
    ("set", {"url": PKG_URL, "data": {}}),
    ("set", {"url": "/pm/config/adom/root/pkg/folder1/package1/firewall/policy", "data": {}}),
    ("set", {"url": "/dvmdb/adom/root/device/dev1", "data": {}}),
    ("add", {"url": OBJ_URL, "data": {}}),
    ("execute", {"url": "/sys/proxy/json", "data": {}}),
    ("execute", {"url": "/securityconsole/install/package",
                 "data": {"adom": "root", "pkg": "Pkg1"}}),
    ("execute", {"url": "/securityconsole/install/device",
                 "data": {"adom": "root", "scope": [{"name": "dev1"}]}}),
    ("execute", {"url": "/dvm/cmd/add/device", "data": {"adom": "root"}}),
    ("get", {"url": OBJ_URL}),
]

INVARIANT_IDS = [f"{action}:{params['url']}" for action, params in INVARIANT_CASES]


class TestLockingInvariants:
    @pytest.mark.parametrize("action,params", INVARIANT_CASES, ids=INVARIANT_IDS)
    @pytest.mark.parametrize("config", [BASE_CONFIG, MINIMAL], ids=["adom", "minimal"])
    def test_never_holds_more_than_one_lock(self, action, params, config):
        """
        The no-deadlock invariant.

        Two locks held at once is how a deadlock becomes possible: two workers taking the
        same pair in opposite orders wait on each other forever. The connector's defence
        is that it never holds more than one, and nothing enforces that today beyond the
        shape of the code. Checked as a running depth rather than a count, so a path that
        takes a second lock *while* holding the first fails even if both are released.
        """
        fmg = SessionFakeFMG()
        run_action(fmg, action, params, config)
        depth = 0
        for event in lock_events(fmg):
            depth += event
            assert depth <= 1, f"held {depth} locks at once: {fmg.calls}"

    @pytest.mark.parametrize("action,params", INVARIANT_CASES, ids=INVARIANT_IDS)
    @pytest.mark.parametrize("config", [BASE_CONFIG, MINIMAL], ids=["adom", "minimal"])
    def test_lock_is_never_held_across_calls(self, action, params, config):
        """
        Every lock this call takes, this call releases.

        A lock that outlives its `perform_rpc_action` is invisible here and catastrophic
        in production: section I.3 measured that an abandoned scope lock is not released
        when the session dies, another session's unlock returns 0 without clearing it,
        and it then wedges for the 8-hour API idle timeout. Two calls are driven through
        the same fake so a leak from the first shows up as unbalanced depth overall.
        """
        fmg = SessionFakeFMG()
        run_action(fmg, action, params, config)
        run_action(fmg, action, params, config)
        assert sum(lock_events(fmg)) == 0, f"lock left held: {fmg.calls}"


class TestReadOnlyExecUrlsTakeNoLock:
    """
    Read-only `execute` URLs must not lock, even when the caller passes an ADOM.

    These carry `adom` in the payload, which is enough for the connector to resolve a
    lockable ADOM, so the pre-fix behaviour was to lock the whole ADOM to run a read --
    and to block outright when another session held it, despite the same call succeeding
    unlocked while that lock was held.
    """

    @pytest.mark.parametrize("url", ["/um/image/list/ext", "/um/image/version/list"])
    @pytest.mark.parametrize("config", [BASE_CONFIG, MINIMAL], ids=["adom", "minimal"])
    def test_firmware_queries_take_no_lock(self, url, config):
        fmg = FakeFMG()
        run_action(fmg, "execute", {"url": url, "data": {"adom": "root"}}, config)
        assert workspace_calls(fmg) == []
        assert [name for name, _ in fmg.calls if name in ("lock_adom", "unlock_adom")] == []

    def test_firmware_upgrade_still_takes_no_lock(self):
        """The neighbouring upgrade URL must keep its existing exemption."""
        fmg = FakeFMG()
        run_action(fmg, "execute", {"url": "/um/image/upgrade/ext",
                                    "data": {"adom": "root"}}, MINIMAL)
        assert workspace_calls(fmg) == []
