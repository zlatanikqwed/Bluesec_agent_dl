"""v22: consequence-first, diversity-aware graph acquisition for SOC investigations.

Each lookup is grounded in a previously observed relation or entity. Reading an
edge is not an examination of its endpoint. Network edges must not crowd out
PowerShell, service, process or file evidence. These heuristics select tests of
competing hypotheses; none assigns a ground-truth verdict.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from bluesec1_agent.soc_v18 import Lead
from bluesec1_agent.soc_v19 import Inspection, SOCV19
from bluesec1_agent.soc_v21 import RiskAdaptiveCaseState, RiskProfile

_IMPACT = {
    'executed_script', 'invoked_cmdlet', 'win_process_create', 'created_process',
    'wrote_file', 'created_file', 'modified_file', 'deleted_file',
    'set_registry_value', 'created_registry_key', 'deleted_registry_value',
    'created_service', 'started_service', 'modified_service',
    'created_scheduled_task', 'injected_into', 'opened_handle',
    'remote_wmi_exec', 'sent_data_to', 'tunneled_via',
    'added_to_group', 'removed_from_group', 'created_account', 'reset_password',
    'dcsync_replication', 'set_password',
}
_REMOTE = {
    'connected_to', 'accepted_connection_from', 'opened_share_session',
    'received_data_from', 'sent_data_to', 'tunneled_via',
}
_SKIP = {'hosts', 'runs_process', 'member_of', 'belongs_to', 'logged_on_to'}
_HUBS = {'host', 'windows_user', 'linux_user', 'linux_group'}
_IDENTITY_EFFECTS = {'added_to_group', 'removed_from_group', 'created_account',
                     'reset_password', 'set_password', 'dcsync_replication'}


class SOCV22(SOCV19):
    """Always inspect important known effect endpoints before sibling edges."""

    @staticmethod
    def _seen(network_type: str, source: str, memory: Any) -> int:
        """Count opened and endpoint-inspected edges of one process/type."""
        return sum(
            rid in memory.fetched_ids and dst in memory.fetched_ids
            for rid, (kind, src, dst) in memory.graph_edges.items()
            if kind.lower() == network_type and src == source
        )

    def _endpoint(self, memory: Any, tools: set[str]) -> Inspection | None:
        if 'get_entity' not in tools:
            return None
        near = self.director.causal_distance(memory)
        candidates: list[tuple[int, int, str, str]] = []
        for rid, (kind, src, dst) in memory.graph_edges.items():
            k = kind.lower()
            if rid not in memory.fetched_ids or k in _SKIP:
                continue
            if near.get(src, 99) > 3 and near.get(dst, 99) > 3:
                continue
            if k not in _IMPACT and k not in _REMOTE:
                continue
            for nid, role in ((dst, 'target'), (src, 'initiator')):
                if (nid not in memory.known_ids or nid in memory.fetched_ids or
                        nid in memory.rejected_ids or
                        (memory.entity_types.get(nid, '').lower() in _HUBS
                         and not (k in _IDENTITY_EFFECTS and role == 'target'))):
                    continue
                # Prioritise the actual affected object. Initial process parents
                # matter, but may not obscure network/source or payload details.
                if role == 'initiator' and k not in {
                    'win_process_create', 'executed_script', 'remote_wmi_exec',
                    'created_service', 'set_registry_value',
                }:
                    continue
                priority = 25 if k in _IMPACT else 21
                if k in {'executed_script', 'win_process_create', 'created_service',
                         'modified_file', 'wrote_file', 'sent_data_to',
                         'added_to_group', 'removed_from_group', 'created_account',
                         'reset_password'}:
                    priority += 4
                if role == 'initiator':
                    priority -= 7
                if k in _REMOTE and self._seen(k, src, memory) >= 3:
                    priority -= 12
                if nid in memory.focus_ids:
                    priority += 2
                if nid in memory.ad_object_ids:
                    continue
                candidates.append((priority, memory.discovery_order.get(nid, 10**9), nid, k))
        if not candidates:
            return None
        priority, _, nid, k = sorted(candidates, key=lambda x: (-x[0], x[1], x[2]))[0]
        if priority < 12:
            return None
        lead = Lead('get_entity', {'entity_id': nid, 'reasoning':
            'Inspect the ACTUAL actor/target properties of a corroborated '+k+
            ' edge. An edge ID alone cannot determine the command, destination, '
            'origin or legitimacy.'}, 'verified '+k+' endpoint, not another sibling edge', priority)
        return Inspection(lead, 'Resolve causal endpoint and consequences: '+k, 'consequence-first')

    def _temp_execution_pivot(self, memory: Any, tools: set[str]) -> Inspection | None:
        """One grounded query for a confirmed cross-identity child executable.

        Never search by an invented filename or benchmark ID. A query result
        remains a *lead*, not a confirmed causal continuation.
        """
        if 'search' not in tools:
            return None
        for finding in self.findings(memory):
            if finding.name != 'service_cross_identity_execution':
                continue
            for nid in finding.entity_ids:
                if nid not in memory.fetched_ids:
                    continue
                props = (memory.observed_nodes.get(nid) or {}).get('properties') or {}
                if not isinstance(props, dict):
                    continue
                path = str(props.get('image_path') or '').strip()
                if (not path or '\\temp\\' not in path.lower()
                        or not path.lower().endswith('.exe')):
                    continue
                args = {'query': path, 'reasoning':
                    'Find independent telemetry for this already-observed cross-identity '
                    'Temp executable. Confirm matches by host/time/process, not name alone.'}
                if memory.cache_key('search', args) in memory.cache:
                    continue
                lead = Lead('search', args,
                    'grounded cross-identity Temp executable follow-up', 16)
                return Inspection(lead, 'Check execution origin and subsequent effects',
                                  'cross-identity-attribution')
        return None

    def next_inspection(self, memory: Any, tools: set[str], *, max_steps: int = 13,
                        minimum_steps: int = 5) -> Inspection | None:
        count = len(memory.calls_made)
        if count >= max_steps:
            return None
        candidate = self._endpoint(memory, tools)
        if candidate is not None:
            return candidate
        previous = super().next_inspection(memory, tools, max_steps=max_steps,
                                            minimum_steps=minimum_steps)
        if previous is None:
            return self._temp_execution_pivot(memory, tools)
        lead = previous.lead
        if lead.tool != 'get_relation':
            return previous
        ident = lead.arguments.get('relation_id')
        typ = memory.relation_types.get(ident, '').lower()
        if typ in _REMOTE:
            owner = memory.relation_owner.get(ident, ('', '', ''))[0]
            # Opening 6 accepted_connection_from edges without reading ANY of
            # their endpoints was a recurring failure in v19-v21. Three sampled
            # connections plus their endpoint attributes are enough before a
            # pivot or a different technique takes priority.
            sibling_open = sum(
                rid in memory.fetched_ids and kind.lower() == typ and src == owner
                for rid, (kind, src, _dst) in memory.graph_edges.items()
            )
            if sibling_open >= 3:
                return None
        return previous


class EvidenceFocusedCaseState(RiskAdaptiveCaseState):
    """Risk-based case control with mandatory causal endpoint inspection."""

    def risk_profile(self, memory: Any) -> RiskProfile:
        initial = super().risk_profile(memory)
        findings = self.engine.findings(memory)
        # A service spawning an interpreter from Temp as ANOTHER account is a
        # concrete cross-identity execution chain, not ordinary baseline.
        # Requires a *joined graph* detector, not matching a filename alone.
        high = {f.name for f in findings if f.severity >= 7}
        if high & {'service_cross_identity_execution', 'staged_process_changed_data',
                   'write_execute_chain', 'remote_control_attribution',
                   'nonstandard_remote_session'}:
            return RiskProfile('corroborate', 10, 15,
                               tuple(sorted(high)[:7]))
        return initial

    def decision_instructions(self, memory: Any) -> str:
        return (
            super().decision_instructions(memory)
            + '\nV22 EVIDENCE FIDELITY: For observed connected_to and '
              'accepted_connection_from actions, distinguish a retrieved '
              'network endpoint from an unread endpoint; internal addressing '
              'or a signed process is not authorization. For a service '
              'running a Temp interpreter under another identity, explicitly '
              'compare its actual command and downstream effects with the '
              'normal-workflow hypothesis. Do not infer absence of attack '
              'from an unexamined downstream graph.'
        )
