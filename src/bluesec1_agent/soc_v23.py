"""v23: source-grounded semantic challenges and one-shot hypothesis pivots.

Facts, assumptions, and proof of authorization are deliberately distinguished.
Neither an unexplained anomaly nor a suspicious program name sets the verdict.
Only confirmed graph nodes/relations participate; search leads are NOT proof.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from bluesec1_agent.soc_v18 import Lead
from bluesec1_agent.soc_v19 import Inspection
from bluesec1_agent.soc_v22 import EvidenceFocusedCaseState, SOCV22


@dataclass(frozen=True)
class ClaimIssue:
    code: str
    weight: int
    explanation: str
    entity_ids: tuple[str, ...] = ()

    def text(self) -> str:
        return f"{self.code} (priority {self.weight}; verified ids: {', '.join(self.entity_ids) or 'none'}): {self.explanation}"


def _facts(memory: Any):
    """Yield examined entities only; a search hit is not an observed causal fact."""
    for nid in sorted(memory.fetched_ids):
        node = memory.observed_nodes.get(nid, {})
        if not isinstance(node, dict):
            continue
        properties = node.get('properties') or {}
        if not isinstance(properties, dict):
            continue
        yield nid, node.get('type', ''), properties


def _support_ids(memory: Any, substrings: tuple[str, ...], keys: tuple[str, ...]):
    hits = []
    for nid, _, props in _facts(memory):
        if any(any(token in str(props.get(k, '')).lower() for token in substrings) for k in keys):
            hits.append(nid)
    return tuple(hits[:5])


class SemanticEvidenceValidator:
    """Check whether confident claims about legitimacy have factual support.

    A warning challenges an LLM, NEVER changes the verdict by itself.
    Unobserved approval may exist; its absence cannot prove malicious intent.
    """

    def issues(self, memory: Any, submission: dict[str, Any]) -> list[ClaimIssue]:
        reasoning = str(submission.get('reasoning') or '').lower()
        if not reasoning:
            return [ClaimIssue('missing_reasoning', 4, 'The submission did not justify a verdict.')]
        findings: list[ClaimIssue] = []
        benign = submission.get('verdict') == 'benign'
        remote_ids = _support_ids(memory, ('psexesvc',), ('pipe_name', 'cmdline', 'image_path'))
        remote_shell_ids = _support_ids(memory, (
            'new-pssession', 'invoke-command', 'winrs ', '-credential', 'net use '
        ), ('cmdline', 'cmdline_decoded', 'script_text', 'script_text_decoded'))
        update_ids = _support_ids(memory, (
            'wuauserv', 'usoclient', 'trustedinstaller', 'windowsupdate'
        ), ('service_name', 'cmdline', 'image_path', 'task_name', 'name'))
        ps_ids = _support_ids(memory, ('powershell', 'pwsh'), ('cmdline', 'image_path'))
        # Approval/authorized workflow must be POSITIVELY corroborated, not
        # extrapolated from signer, SYSTEM or a service account.
        approval_keys = ('approved', 'authorized', 'approval', 'ticket', 'change_id',
                         'change_ticket', 'approval_status', 'is_approved')
        approved = [nid for nid, _, p in _facts(memory)
                    if any(k in p and str(p[k]).lower() not in ('', 'false', '0', 'none', 'no')
                           for k in approval_keys)]
        if benign:
            if re.search(r'\b(approved|authorized|documented|whitelisted|sanctioned)\b', reasoning) and not approved:
                findings.append(ClaimIssue('authorization_not_observed', 4,
                    'Approval or authorization is asserted, but no retrieved evidence positively establishes it. '
                    'This is unknown, not evidence of an attack.'))
            task_claim = ('scheduled task' in reasoning or 'task scheduler' in reasoning)
            task_ids = _support_ids(memory, ('schtasks', 'scheduledtask'),
                                    ('cmdline', 'script_text', 'task_name', 'name'))
            task_edges = [rid for rid, (kind, _, _) in memory.graph_edges.items()
                          if kind.lower() in ('created_scheduled_task', 'ran_scheduled_task',
                                              'started_scheduled_task', 'triggered_task')
                          and rid in memory.fetched_ids]
            if task_claim and not task_ids and not task_edges:
                findings.append(ClaimIssue('scheduled_task_not_observed', 5,
                    'The explanation attributes execution to a scheduled task, '
                    'but fetched process/action telemetry does not establish that trigger.',
                    ps_ids[:3]))
            if ('windows update' in reasoning or 'windowsupdate' in reasoning) and remote_ids and not update_ids:
                findings.append(ClaimIssue('update_explanation_conflicts_with_remote_pipe', 9,
                    'The observed pipe is PsExec-style remote execution. Windows Update '
                    'does not explain it merely because the parent is services.exe or SYSTEM.',
                    remote_ids))
            if remote_ids and any(word in reasoning for word in (
                'routine', 'legitimate', 'normal', 'benign', 'maintenance')):
                findings.append(ClaimIssue('remote_execution_origin_unverified', 7,
                    'PsExec-family named-pipe activity requires attribution to an actual initiator, '
                    'command and authorization or incident-response context. No verdict is implied.',
                    remote_ids))
            if remote_shell_ids and ('normal' in reasoning or 'routine' in reasoning or 'authorized' in reasoning):
                findings.append(ClaimIssue('remote_shell_intent_unverified', 5,
                    'A remote shell/explicit credential action was retrieved. Account privilege '
                    'or internal IP alone does not explain the command and its effects.',
                    remote_shell_ids))
            network_nodes = [(nid, p) for nid, typ, p in _facts(memory)
                             if ('src_ip' in p and ('dst_port' in p or 'dst_ip' in p))]
            smb = [(nid, p) for nid, p in network_nodes
                   if str(p.get('dst_port', '')) in {'445', '139'}]
            # Combining SMB with WinRM is neither normal nor malicious on its
            # own. When both are fetched, a confident 'authorized maintenance'
            # claim requires evidence of WHICH actor invoked WHAT and WHY.
            service_ports = {str(p.get('dst_port', '')) for _, p in network_nodes}
            port_evidence = tuple(nid for nid, p in network_nodes
                                  if str(p.get('dst_port', '')) in ('445', '5985', '5986'))
            if ({'445'} & service_ports and {'5985', '5986'} & service_ports
                    and re.search(r'\b(legitimate|routine|authorized|maintenance|normal)\b', reasoning)):
                findings.append(ClaimIssue('cross_protocol_remote_intent_unverified', 6,
                    'The same alert-connected activity includes SMB and WinRM endpoints. '
                    'These prove network interactions, not authorization, command purpose or '
                    'the actor initiating both. Check source and actual follow-on actions.',
                    port_evidence[:4]))
            if len(smb) >= 2 and re.search(r'(failed (?:ntlm|logons?|authentication)|no successful auth)', reasoning):
                auth_ids = _support_ids(memory, ('fail', 'success', 'logon', 'ntlm'),
                    ('auth_result', 'authentication_status', 'event_id', 'status', 'logon_type'))
                if not auth_ids:
                    findings.append(ClaimIssue('authentication_result_not_observed', 6,
                        'The outcome of authentication is asserted, but retrieved SMB network '
                        'connections alone do not reveal success, failure, or any later host actions.',
                        tuple(nid for nid, _ in smb[:3])))
            if remote_shell_ids and ps_ids and not approved and re.search(r'\b(authorized|approved)\b', reasoning):
                findings.append(ClaimIssue('remote_authorization_unverified', 6,
                    'Remote execution was inferred authorized from service-account context '
                    'without a source supporting that authorization.', remote_shell_ids))
        else:
            # An observed group membership change is a fact; its authorization
            # cannot be inferred from missing approval records. Challenge the
            # unsupported *claim*, never automatically reverse a malicious verdict.
            identity_edges = [(rid, src, dst) for rid, (kind, src, dst)
                              in memory.graph_edges.items()
                              if rid in memory.fetched_ids and
                              kind.lower() in ('added_to_group', 'removed_from_group',
                                               'created_account', 'reset_password')]
            if (identity_edges and re.search(
                    r'\b(unauthori[sz]ed|unapproved|without (?:any )?(?:recorded )?'
                    r'(?:authorization|approval)|no (?:recorded )?approval)\b', reasoning)):
                # Positive proof may be in a ticket or explicitly verified
                # approval edge; absence alone must not be narrated as proof.
                aligned = {v for _, src, dst in identity_edges for v in (src, dst)}
                for rid, (kind, src, dst) in memory.graph_edges.items():
                    if (rid in memory.fetched_ids and kind.lower() in
                            ('approved_by', 'authorized_by', 'part_of_change',
                             'has_approval', 'associated_with_ticket') and
                            (src in aligned or dst in aligned)):
                        aligned.update((src, dst))
                approval_keys = ('approved', 'authorized', 'approval_status',
                                 'change_ticket', 'change_id')
                auth_values = [str(props.get(key)).strip().lower()
                               for nid, _, props in _facts(memory) if nid in aligned
                               for key in approval_keys if props.get(key) is not None]
                positive = any(v not in ('', 'no', 'false', '0', 'none', 'unknown',
                                         'denied', 'rejected') for v in auth_values)
                negative = any(v in ('no', 'false', '0', 'denied', 'rejected')
                               for v in auth_values)
                if positive:
                    findings.append(ClaimIssue('identity_change_authorization_contradicted', 9,
                        'An event-linked approval record conflicts with the assertion '
                        'that the identity change was unauthorized. Verify the scope '
                        'of approval before concluding either verdict.',
                        tuple(dst for _, _, dst in identity_edges[:3])))
                elif not negative:
                    findings.append(ClaimIssue('identity_change_authorization_unverified', 6,
                        'The privilege/account change is observed, but whether it was '
                        'unauthorized is not established by absence of an approval '
                        'record. Examine the affected identity, actor, purpose and '
                        'observed downstream effects.',
                        tuple(dst for _, _, dst in identity_edges[:3])))
            # Also challenge invented malicious techniques; never favor a fixed label.
            if ('dumped lsass' in reasoning or 'lsass dumping' in reasoning):
                lsass = _support_ids(memory, ('lsass', 'sekurlsa', 'minidump'),
                    ('cmdline', 'cmdline_decoded', 'script_text', 'image_path'))
                if not lsass:
                    findings.append(ClaimIssue('credential_dump_not_observed', 6,
                        'The verdict asserts credential dumping; no examined command or '
                        'script corroborates that precise operation.'))
        return sorted(findings, key=lambda a: (-a.weight, a.code))

    def check_text(self, memory: Any, submission: dict[str, Any], *, limit: int = 5) -> str:
        issues = self.issues(memory, submission)[:limit]
        if not issues:
            return 'No high-confidence semantic claim mismatches detected. This does not prove the verdict.'
        return ('SOURCE-GROUNDED CLAIM VALIDATION (uncertainties, NOT predetermined labels):\n'
                + '\n'.join('- ' + x.text() for x in issues)
                + '\nReassess H_attack versus H_normal against observed effects. '
                  'Treat approval, intent and unobserved authentication as UNKNOWN; '
                  'do not replace a weak benign explanation with an equally unsupported malicious one.')


class SOCV23(SOCV22):
    """Read an examined process's created named pipe before concluding.

    Named pipes can encode remote-execution control channels or normal IPC.
    Neither interpretation is justified without the target properties.
    """

    def _endpoint(self, memory: Any, tools: set[str]) -> Inspection | None:
        prior = super()._endpoint(memory, tools)
        if prior is not None or 'get_entity' not in tools:
            return prior
        close = self.director.causal_distance(memory)
        for rid, (kind, actor, target) in sorted(memory.graph_edges.items(),
                key=lambda item: memory.discovery_order.get(item[0], 10**9)):
            if (kind.lower() not in ('created_pipe', 'opened_pipe') or
                    rid not in memory.fetched_ids or close.get(actor, 99) > 3 or
                    target not in memory.known_ids or target in memory.fetched_ids or
                    target in memory.rejected_ids):
                continue
            return Inspection(Lead('get_entity', {'entity_id': target, 'reasoning':
                'Read the named-pipe target of an examined causal edge to distinguish '
                'normal IPC from remote service control; pipe existence alone '
                'does not determine attacker intent.'},
                'inspect actual named-pipe semantics', 17),
                'Resolve actual pipe name and initiating process', 'semantic-attribution')
        return None


@dataclass
class ReasonedEvidenceCaseState(EvidenceFocusedCaseState):
    """v22 plan, with one optional fact-specific pivot after graph collection."""
    pivots_done: set[str] = field(default_factory=set)

    def _semantic_pivot(self, memory: Any, tools: set[str]) -> Inspection | None:
        if 'search' not in tools or self.pivots_done:
            return None
        # A script-block identifier is exact evidence for a more informative
        # PowerShell query than repeating low-value inventory edges.
        for nid, typ, props in _facts(memory):
            block = str(props.get('script_block_id', '')).strip()
            if not (3 <= len(block) <= 100 and re.fullmatch(r'[A-Za-z0-9_\-.]+', block)):
                continue
            if not any(k.lower() in ('invoked_cmdlet', 'executed_script') and dst == nid
                       and rid in memory.fetched_ids
                       for rid, (k, src, dst) in memory.graph_edges.items()):
                continue
            # Do not search every block in legitimate scripts; only ones for
            # which the cmdlet is too generic to explain behavior (Out-Null etc.).
            cmd = str(props.get('command_name', '')).lower()
            if cmd not in ('out-null', 'write-output', 'select-object', 'out-string'):
                continue
            query = block
            arg = {'query': query, 'reasoning':
                   'Find the actual script block associated with a fetched low-information '
                   'PowerShell cmdlet. Matches are leads, not proof of execution or authorization.'}
            if memory.cache_key('search', arg) in memory.cache:
                continue
            self.pivots_done.add(query)
            return Inspection(Lead('search', arg, 'grounded script-block semantics', 14),
                              'Find originating script of otherwise uninformative cmdlet',
                              'semantic-attribution')
        return None

    def select_acquisition(self, memory: Any, tools: set[str], *, step_index: int,
                           max_steps: int, force_finish: bool = False) -> Inspection | None:
        previous = super().select_acquisition(memory, tools, step_index=step_index,
                                              max_steps=max_steps, force_finish=force_finish)
        if previous is not None or force_finish or step_index >= max_steps - 5:
            return previous
        result = self._semantic_pivot(memory, tools)
        if result is not None:
            self.move('ACQUIRE')
        return result

    def decision_instructions(self, memory: Any) -> str:
        return (super().decision_instructions(memory) + '\nV23 SEMANTIC FIDELITY: '
                'Separate observed operation from inferred intent and UNKNOWN authorization. '
                'Identify the actual evidence for scheduled-task origin, remote-session approval, '
                'authentication outcome and service purpose if claiming them. '
                'If evidence does not support a precise statement, do not invent it. '
                'When a prior submission was rejected, do NOT resubmit the identical benign conclusion.')
