"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

# The connector modules import `connectors.core.connector`, which only exists
# inside a FortiSOAR appliance. Register a minimal stub so the unit tests can be
# collected and run in a plain virtualenv (CI, laptop) with no FortiSOAR install.

import logging
import sys
import types

if "connectors" not in sys.modules:
    connectors = types.ModuleType("connectors")
    core = types.ModuleType("connectors.core")
    connector = types.ModuleType("connectors.core.connector")

    class ConnectorError(Exception):
        pass

    def get_logger(name):
        return logging.getLogger(name)

    class Connector:
        def execute(self, config, operation, params, **kwargs):
            raise NotImplementedError

    connector.ConnectorError = ConnectorError
    connector.get_logger = get_logger
    connector.Connector = Connector

    core.connector = connector
    connectors.core = core

    sys.modules["connectors"] = connectors
    sys.modules["connectors.core"] = core
    sys.modules["connectors.core.connector"] = connector
