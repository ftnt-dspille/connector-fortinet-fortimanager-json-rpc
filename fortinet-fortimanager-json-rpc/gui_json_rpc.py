"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import json
from typing import Union

import requests
import urllib3
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('fortinet-fortimanager-json-rpc')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FortiManagerGUI:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.headers = {}

    def __enter__(self):
        if self.login():
            return self
        else:
            raise ConnectorError("Failed to log in to FortiManager GUI")

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()

    def login(self) -> bool:
        auth_url = f"{self.base_url}/cgi-bin/module/flatui_auth"
        data = {
            'url': '/gui/userauth',
            'method': 'login',
            'params': {
                'username': self.username,
                'secretkey': self.password,
                'logintype': 0
            }
        }

        try:
            response = self.session.post(auth_url, json=data, timeout=30)
            if response.ok:
                csrf_token = self.session.cookies.get('HTTP_CSRF_TOKEN')
                if csrf_token:
                    self.headers = {'HTTP_CSRF_TOKEN': csrf_token.replace('"', '')}
                    logger.debug("GUI login successful")
                    return True
                else:
                    logger.error("CSRF token not found in response cookies")
                    return False
            else:
                logger.error(f"GUI authentication failed: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Exception during GUI login: {str(e)}")
            raise ConnectorError(f"GUI login failed: {str(e)}")

    def make_request(self, gui_method: str, url: str, params: Union[dict, None] = None) -> dict:
        session_url = f"{self.base_url}/cgi-bin/module/flatui_proxy"

        request_data = {
            "method": gui_method,
            "url": url
        }

        if params:
            request_data["params"] = params

        try:
            response = self.session.post(
                session_url,
                headers=self.headers,
                json=request_data,
                timeout=30
            )

            if response.ok:
                return response.json()
            else:
                error_msg = f"Request failed: {response.status_code} - {response.text}"
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except requests.exceptions.RequestException as e:
            logger.error(f"Request exception: {str(e)}")
            raise ConnectorError(f"Request failed: {str(e)}")

    def logout(self):
        try:
            logout_url = f"{self.base_url}/p/logout-api/"
            headers = {
                "Xsrf-Token": self.headers.get("HTTP_CSRF_TOKEN", ""),
                "Referer": self.base_url,
                "Content-Type": "application/json",
            }
            self.session.post(logout_url, headers=headers, timeout=10)
            logger.debug("GUI logout successful")
        except Exception as e:
            logger.warning(f"Logout exception: {str(e)}")


def get_gui_config(config: dict) -> tuple:
    address = config.get('address', '').strip('/')
    port = config.get('port', 443)

    if not address.startswith('http'):
        base_url = f"https://{address}"
    else:
        base_url = address

    if port and port not in [443, "443"]:
        base_url = f"{base_url}:{port}"

    username = config.get("username")
    password = config.get("password")
    verify_ssl = config.get("verify_ssl", False)

    if not username or not password:
        raise ConnectorError("Username and password are required for GUI authentication")

    return base_url, username, password, verify_ssl


def perform_gui_action(config: dict, params: dict) -> dict:
    base_url, username, password, verify_ssl = get_gui_config(config)

    url = params.get("url")
    if not url:
        raise ConnectorError("URL parameter is required")

    gui_method = params.get("gui_method", "get")
    data = params.get("data")
    if data and not isinstance(data, dict):
        data = json.loads(data)

    try:
        with FortiManagerGUI(base_url, username, password, verify_ssl) as fmg_gui:
            response = fmg_gui.make_request(gui_method, url, data)

            result = {
                "gui_response": response,
                "method": gui_method,
                "url": url
            }

            logger.debug(f"GUI action completed: {gui_method} {url}")
            return result

    except Exception as e:
        logger.error(f"GUI action failed: {str(e)}")
        raise ConnectorError(f"GUI action failed: {str(e)}")


def get_device_vulnerabilities(config: dict, params: dict) -> dict:
    base_url, username, password, verify_ssl = get_gui_config(config)

    adom_oid = params.get("adom_oid")
    if not adom_oid:
        raise ConnectorError("ADOM OID parameter is required")

    url = f"/gui/adoms/{adom_oid}/dvm/psirt"
    fortios_only = params.get("fortios_only", False)
    simplify = params.get("simplify", False)
    exclude_impacted = params.get("exclude_impacted_versions", False)
    severity_filter = params.get("severity_filter")

    try:
        with FortiManagerGUI(base_url, username, password, verify_ssl) as fmg_gui:
            response = fmg_gui.make_request("get", url, None)

            if simplify or fortios_only or exclude_impacted or severity_filter:
                response = _simplify_vulnerability_response(
                    response,
                    fortios_only,
                    exclude_impacted,
                    severity_filter
                )

            result = {
                "vulnerabilities": response.get("vulnerabilities", []),
                "adom_oid": adom_oid,
                "url": url
            }

            logger.debug(f"Retrieved vulnerabilities for ADOM {adom_oid}")
            return result

    except Exception as e:
        logger.error(f"Failed to get vulnerabilities: {str(e)}")
        raise ConnectorError(f"Failed to get vulnerabilities: {str(e)}")


def _simplify_vulnerability_response(
        response: dict,
        fortios_only: bool = False,
        exclude_impacted: bool = False,
        severity_filter: str = None
) -> dict:
    simplified = {"vulnerabilities": []}

    try:
        result_data = response.get("result", [{}])[0].get("data", {})
        by_ir = result_data.get("byIrNumber", {})

        for ir_number, vuln_data in by_ir.items():
            severity = vuln_data.get("threat_severity", "")

            if severity_filter and severity.lower() != severity_filter.lower():
                continue

            products = vuln_data.get("products", {})

            if fortios_only:
                products = {"FortiOS": products.get("FortiOS", [])}

            vuln = {
                "ir_number": ir_number,
                "cve": vuln_data.get("cve", []),
                "title": vuln_data.get("title", ""),
                "severity": severity,
                "cvss_score": vuln_data.get("cvss3", {}).get("cvss3_base_score", ""),
                "description": vuln_data.get("description", ""),
                "products": products
            }

            if not exclude_impacted:
                impacted_products = vuln_data.get("impacted_products", {})
                vuln["impacted_versions"] = _convert_impacted_to_version_strings(
                    impacted_products,
                    fortios_only
                )

            simplified["vulnerabilities"].append(vuln)

    except Exception as e:
        logger.warning(f"Error simplifying response: {str(e)}")
        return response

    return simplified


def _convert_impacted_to_version_strings(impacted_products: dict, fortios_only: bool = False) -> dict:
    """Convert impacted products from dict format to simple version strings"""
    version_strings = {}

    products_to_process = impacted_products
    if fortios_only:
        products_to_process = {"FortiOS": impacted_products.get("FortiOS", [])}

    for product_name, versions in products_to_process.items():
        version_list = []
        for version in versions:
            major = version.get("major", "")
            minor = version.get("minor", "")
            patch = version.get("patch", "")
            version_str = f"{major}.{minor}.{patch}"
            version_list.append(version_str)

        version_strings[product_name] = version_list

    return version_strings
