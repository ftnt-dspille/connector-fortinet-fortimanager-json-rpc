"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

"""
Integration tests for the FortiManagerGUI logout flow against a live FortiManager.

These tests verify that after calling logout():
  - The CURRENT_SESSION cookie no longer authenticates subsequent proxy calls
  - The server actually invalidates the session (not just a client-side discard)

Requirements:
  - A live FortiManager reachable via the .env credentials (ADDRESS, USERNAME,
    PASSWORD, optional PORT, VERIFY_SSL)
"""

import importlib
import os
import sys

import pytest
from dotenv import load_dotenv

current_directory = os.path.dirname(__file__)
parent_directory = os.path.abspath(os.path.join(current_directory, os.pardir))
grandparent_directory = os.path.abspath(os.path.join(parent_directory, os.pardir))
sys.path.insert(0, str(grandparent_directory))

env_path = os.path.join(parent_directory, ".env")
load_dotenv(dotenv_path=env_path)

gui_module = importlib.import_module("fortinet-fortimanager-json-rpc.gui_json_rpc")
FortiManagerGUI = gui_module.FortiManagerGUI
get_gui_config = gui_module.get_gui_config


@pytest.fixture
def gui_config():
    address = os.getenv("ADDRESS")
    username = os.getenv("USERNAME")
    password = os.getenv("PASSWORD")
    if not (address and username and password):
        pytest.skip("ADDRESS/USERNAME/PASSWORD not set in .env")
    return {
        "address": address,
        "username": username,
        "password": password,
        "port": os.getenv("PORT", 443),
        "verify_ssl": os.getenv("VERIFY_SSL", "False").lower() in ("true", "1", "t"),
    }


def _authenticated_probe(gui: FortiManagerGUI) -> bool:
    """Hit the flatui_proxy endpoint directly and decide whether the session
    is still authenticated based on the raw response.

    A valid session: server accepts the proxied call and returns a JSON body
    with a "result" key (even if the inner status is a 404 for a non-existent
    upstream URL).

    A revoked session: server rejects the call before proxying — typically a
    redirect to login (302), an auth error (401/403), or a body without the
    expected proxy "result" envelope.
    """
    proxy_url = f"{gui.base_url}/cgi-bin/module/flatui_proxy"
    try:
        response = gui.session.post(
            proxy_url,
            headers=gui.headers,
            json={"method": "get", "url": "/gui/adoms"},
            timeout=15,
            allow_redirects=False,
        )
    except Exception:
        return False

    if response.status_code in (301, 302, 303, 307, 308, 401, 403):
        return False
    if not response.ok:
        return False
    try:
        body = response.json()
    except ValueError:
        return False
    return "result" in body


class TestGUILogoutIntegration:
    def test_login_then_logout_revokes_session(self, gui_config):
        base_url, username, password, verify_ssl = get_gui_config(gui_config)
        gui = FortiManagerGUI(base_url, username, password, verify_ssl)

        assert gui.login() is True, "login should succeed against the live FMG"
        assert "CURRENT_SESSION" in gui.session.cookies, "expected session cookie after login"

        assert _authenticated_probe(gui) is True, (
            "authenticated proxy call should succeed before logout"
        )

        gui.logout()

        assert _authenticated_probe(gui) is False, (
            "authenticated proxy call should FAIL after logout — "
            "if it still succeeds, the server did not actually invalidate the session"
        )

    def test_context_manager_revokes_session_on_exit(self, gui_config):
        base_url, username, password, verify_ssl = get_gui_config(gui_config)

        with FortiManagerGUI(base_url, username, password, verify_ssl) as gui:
            assert _authenticated_probe(gui) is True
            leaked_session = gui.session  # keep the same session/cookies after exit

        probe_gui = FortiManagerGUI(base_url, username, password, verify_ssl)
        probe_gui.session = leaked_session
        probe_gui.headers = {
            "HTTP_CSRF_TOKEN": (leaked_session.cookies.get("HTTP_CSRF_TOKEN") or "").replace('"', '')
        }

        assert _authenticated_probe(probe_gui) is False, (
            "reusing cookies from a context-managed session after exit should fail"
        )
