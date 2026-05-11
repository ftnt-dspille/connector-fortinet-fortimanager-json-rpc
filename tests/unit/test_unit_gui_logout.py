"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import importlib
import sys
import os
from unittest.mock import MagicMock, patch

import pytest

current_directory = os.path.dirname(__file__)
repo_root = os.path.abspath(os.path.join(current_directory, os.pardir, os.pardir))
sys.path.insert(0, repo_root)

gui_json_rpc = importlib.import_module("fortinet-fortimanager-json-rpc.gui_json_rpc")
FortiManagerGUI = gui_json_rpc.FortiManagerGUI


def _make_gui():
    gui = FortiManagerGUI("https://10.0.0.1", "admin", "pw", verify_ssl=False)
    gui.session = MagicMock()
    gui.headers = {"HTTP_CSRF_TOKEN": "test-csrf-token"}
    return gui


class TestLogout:
    def test_logout_posts_to_logout_api_endpoint(self):
        gui = _make_gui()
        gui.logout()

        gui.session.post.assert_called_once()
        called_url = gui.session.post.call_args[0][0]
        assert called_url == "https://10.0.0.1/p/logout-api/"

    def test_logout_sends_required_headers(self):
        gui = _make_gui()
        gui.logout()

        headers = gui.session.post.call_args.kwargs["headers"]
        assert headers["Xsrf-Token"] == "test-csrf-token"
        assert headers["Referer"] == "https://10.0.0.1"
        assert headers["Content-Type"] == "application/json"

    def test_logout_does_not_use_get(self):
        gui = _make_gui()
        gui.logout()

        gui.session.get.assert_not_called()

    def test_logout_swallows_exceptions(self):
        gui = _make_gui()
        gui.session.post.side_effect = RuntimeError("network down")

        gui.logout()

    def test_context_manager_exit_triggers_logout(self):
        gui = _make_gui()
        with patch.object(gui, "login", return_value=True), \
             patch.object(gui, "logout") as mock_logout:
            with gui:
                pass
            mock_logout.assert_called_once()
