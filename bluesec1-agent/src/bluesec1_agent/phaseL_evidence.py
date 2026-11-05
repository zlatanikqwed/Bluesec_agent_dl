"""Phase L public-evidence selectors; no runtime rewards or hidden labels.

Used by the experimental harvester and report selector so that retrieval and
citation refer to the same attributable objects. All selectors are deliberately
bounded to the alert process/session and observed relations.
"""
from __future__ import annotations

import ntpath
import re
from typing import Any

from bluesec1_agent.inbound_evidence import logon_details
from bluesec1_agent.response_mapper import ObservedGraph

_SCRIPT_ARG = re.compile(
    r'(?i)(?:"([^"\r\n]+\.ps1)"|\x27([^\x27\r\n]+\.ps1)\x27|'
    r'((?:[a-z]:[\\/]|\\\\|[\w.-])[\w .\\/\-]*?\.ps1))(?=\s|$|["\x27])'
)
_PROTECTOR = re.compile(
    r'(?i)^(?:avp|ekrn|msmpeng|senseir|sensecncproxy|elastic-agent|'
    r'elastic-endpoint|csfalconservice|csfalconcontainer|sentinelagent|'
    r'sentinelservicehost|cylancesvc|savservice|carbonblack|cb|'
    r'taniumclient|sophoshealth|sophosfileScanner|agent\.worker)\.exe$'
)


def script_name_from_command(command: Any) -> str:
    """Select an explicitly mentioned .ps1, not a guessed generic file."""
    value = str(command or "")
    for match in _SCRIPT_ARG.finditer(value):
        candidate = next((v for v in match.groups() if v), "")
        basename = ntpath.basename(candidate.strip().strip('"\x27'))
        if len(basename) >= 5 and basename.casefold().endswith('.ps1'):
            return basename
    return ""


def scheduled_task_sources(graph: ObservedGraph, trigger: str) -> list[str]:
    """Incoming ran_scheduled_task source is the authorizing task."""
    ids = []
    for rel in graph.inc(trigger, {"ran_scheduled_task"}):
        candidate = rel.get('source_id')
        if isinstance(candidate, str) and candidate != trigger:
            ids.append(candidate)
    # Alternative wire direction: only accept an already typed scheduled_task.
    for rel in graph.out(trigger, {"ran_scheduled_task"}):
        candidate = rel.get('target_id')
        if isinstance(candidate, str) and graph.etype(candidate) == 'scheduled_task':
            ids.append(candidate)
    return list(dict.fromkeys(ids))


def is_protection_process(graph: ObservedGraph, trigger: str) -> bool:
    image = str(graph.props(trigger).get('image_path') or '')
    return bool(_PROTECTOR.fullmatch(ntpath.basename(image)))


def interactive_trigger(graph: ObservedGraph, trigger: str) -> bool:
    image = str(graph.props(trigger).get('image_path') or '')
    return ntpath.basename(image).casefold() in {'userinit.exe', 'explorer.exe'}


def interactive_source_ips(graph: ObservedGraph, trigger: str) -> list[str]:
    """Only sources of the current login; accept local interactive/RDP metadata.

    The login relation must match its actual logon_id (or, when omitted, the
    current user and target host) and must not be explicitly unsuccessful.
    An interactive login without an IP gives no host to cite or guess.
    """
    p = graph.props(trigger)
    logon = str(p.get('logon_id') or '').casefold()
    sid = str(p.get('user_sid') or '').casefold()
    host_id = (graph.entities.get(trigger) or {}).get('host_id')
    actor_ids = {nid for nid, ent in graph.entities.items()
                 if ent.get('type') == 'windows_user' and sid and
                 str(graph.props(nid).get('sid') or graph.props(nid).get('user_sid') or '').casefold() == sid}
    found = []
    for rel in graph.relations.values():
        if rel.get('type') != 'logged_on_to':
            continue
        data = logon_details(rel)
        session = str(data.get('logon_id') or data.get('session_id') or '').casefold()
        if session:
            if not logon or session != logon:
                continue
        elif not (rel.get('source_id') in actor_ids and rel.get('target_id') == host_id):
            continue
        status = str(data.get('status') or data.get('authentication_status') or
                     data.get('outcome') or '').casefold()
        if status in {'failed', 'failure', 'denied', 'rejected'} or data.get('success') is False:
            continue
        ip = str(data.get('source_ip') or data.get('src_ip') or '').strip()
        if ip and ip not in found:
            found.append(ip)
    return found
