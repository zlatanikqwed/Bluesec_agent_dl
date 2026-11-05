"""Public, observed remote-login attributes shared by harvest and report mapping.

Relation-specific ``logon_properties`` may be a top-level object, or nested in
``properties``; do not silently discard source IPs for either wire format.
No runtime rewards or evaluation metadata are used.
"""
from __future__ import annotations

from typing import Any


def logon_details(relation: dict[str, Any]) -> dict[str, Any]:
    """Merge observed attributes, preferring specialised logon_properties."""
    plain = relation.get("properties")
    plain = plain if isinstance(plain, dict) else {}
    nested = plain.get("logon_properties")
    top = relation.get("logon_properties")
    result = {k: v for k, v in plain.items() if k != "logon_properties"}
    if isinstance(nested, dict):
        result.update(nested)
    if isinstance(top, dict):
        result.update(top)
    for key in ("logon_id", "session_id", "source_ip", "src_ip", "logon_type",
                "authentication_status", "status", "outcome", "success"):
        if key not in result and key in relation:
            result[key] = relation[key]
    return result


def confirmed_remote_login(relation: dict[str, Any]) -> bool:
    """Confirmed login, never a failed attempt or an explicitly local session.

    The ``logged_on_to`` edge attests an established session; for that relation,
    missing status/logon_type is not interpreted as failed. A logon_type of 2
    (interactive/local) is not enough to claim a remote source.
    """
    data = logon_details(relation)
    status = str(data.get("authentication_status") or data.get("status") or
                 data.get("outcome") or "").strip().casefold()
    if status in {"failed", "failure", "denied", "rejected"} or data.get("success") is False:
        return False
    typ = str(data.get("logon_type") or "").strip().casefold()
    if typ and typ not in {"3", "10", "network", "remoteinteractive", "remote_interactive"}:
        return False
    if status in {"success", "successful", "authenticated"} or data.get("success") is True:
        return True
    return relation.get("type") == "logged_on_to" and not status
