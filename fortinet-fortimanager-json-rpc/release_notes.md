#### What's Improved

Following enhancements have been made to the Fortinet FortiManager JSON RPC Connector in version 1.2.7:

- Workspace locking now reflects behaviour measured against a live appliance rather than assumption:
  - `/securityconsole/install/device` takes a lock again. Without one, an install with pending device-database changes fails inside the queued task while the RPC still reports success.
  - `/securityconsole/install/package`, `/securityconsole/install/device` and `/securityconsole/reinstall/package` now hold their lock until the queued task finishes, and return the task outcome, so an install can no longer fail silently when the caller does not request task tracking.
  - Firmware upgrade (`/um/image/upgrade/ext`) takes no lock, so an upgrade no longer serialises other workers in the ADOM for the duration of the task.
  - A request whose payload carries the `auto_lock_ws` flag is left to FortiManager's own locking instead of being locked twice.
- Minimal locking resolves finer scopes in more cases: a single-package `reinstall/package` takes a package lock via its `target[]` shape, and packages nested inside package folders now resolve to the path FortiManager accepts.
- A request with no resolvable ADOM no longer reports itself as the `global` ADOM, which had the side effect of silently skipping locking for any such payload on any URL.
- Device onboarding URLs (`/dvm/cmd/*`) always take the ADOM lock; no finer scope exists for a device that is not registered yet.
- A lock URL that names something that does not exist now fails immediately instead of being retried to the full retry budget.
