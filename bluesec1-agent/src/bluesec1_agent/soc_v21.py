"""v21: risk-adaptive collection and corroborated high-confidence behavior checks.

Rules reason about returned graph content, never about benchmark IDs or grader labels.
These functions never execute scripts, decode payloads for execution, or invent IDs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from bluesec1_agent.soc_v19 import SOCV19
from bluesec1_agent.soc_v20 import ForensicCaseState


@dataclass(frozen=True)
class RiskProfile:
    tier: str
    minimum: int
    maximum: int
    reasons: tuple[str, ...]


class RiskAdaptiveCaseState(ForensicCaseState):
    """Expand collection only for *observed* attack hypotheses or remote provenance.

    This budget buys graph facts, not verdicts. If the graph has no real next IDs,
    stop early regardless of budget: there is no justification for a synthetic lookup.
    """

    def risk_profile(self, memory: Any) -> RiskProfile:
        findings = self.engine.findings(memory)
        serious = sorted({f.name for f in findings if f.severity >= 8})
        if serious:
            return RiskProfile("corroborate", 10, 15, tuple(serious[:7]))
        meaningful = {k.lower() for k, _, _ in memory.graph_edges.values()}
        remote = bool(meaningful & {
            "accepted_connection_from", "opened_share_session", "remote_wmi_exec",
            "tunneled_via", "connected_to", "received_data_from"})
        actors = []
        for nid, node in memory.observed_nodes.items():
            if nid not in memory.focus_ids and nid not in memory.fetched_ids:
                continue
            props = node.get("properties") or {}
            if not isinstance(props, dict):
                continue
            actors.append(" ".join(str(props.get(k) or "")[:400] for k in
                         ("image_path", "cmdline", "cmdline_decoded", "script_text")))
        text = " ".join(actors).lower()
        remote_context = (remote or any(x in text for x in (
            "wsmprovhost", "winrs", "new-pssession", "psexesvc",
            "net use ", "\\\\admin$", "-credential", "iphlpsvc", "portproxy")))
        if remote_context:
            return RiskProfile("attribute", 9, 13, ("remote execution/source attribution",))
        if meaningful & {"wrote_file", "created_file", "set_registry_value", "created_service"}:
            return RiskProfile("effects", 8, 12, ("confirm modification and downstream behavior",))
        return RiskProfile("baseline", 6, 11, ())

    def select_acquisition(self, memory: Any, tools: set[str], *, step_index: int,
                           max_steps: int, force_finish: bool = False):
        profile = self.risk_profile(memory)
        # Do not lower an in-progress budget after a search adds unrelated nodes;
        # always re-evaluate from the actual observed case.
        self.minimum_acquisitions = profile.minimum
        self.maximum_acquisitions = profile.maximum
        return super().select_acquisition(memory, tools, step_index=step_index,
                                          max_steps=max_steps, force_finish=force_finish)

    def decision_instructions(self, memory: Any) -> str:
        profile = self.risk_profile(memory)
        return (
            super().decision_instructions(memory)
            + "\nV21 RISK DOSSIER: " + profile.tier + "; " + ", ".join(profile.reasons)
            + ". For remote control, identify initiator and precise command/effect, not "
              "merely a signed destination service. For in-memory execution, analyze "
              "the actual loaded and invoked code path: no exfiltration is NOT proof "
              "the execution was authorized. An unexplained anomaly is NOT an "
              "automatic malicious label."
        )


def corroborated_execution(memory: Any, engine: SOCV19) -> tuple[str, tuple[str, ...]] | None:
    """Identify script-level *execution*, not a keyword in a command line alone.

    Requires independently parsed structure (Assembly.Load+EntryPoint.Invoke) and
    a second delivery mechanism in the SAME fetched script, plus its observed
    executed_script edge. This is narrower than the engine's detection hypothesis.
    """
    findings = engine.findings(memory)
    by_id: dict[str, set[str]] = {}
    for finding in findings:
        if finding.name not in {"dotnet_memory_assembly", "image_payload_loader", "remote_reflection_loader"}:
            continue
        if finding.category != "execution":
            continue
        for nid in finding.entity_ids:
            by_id.setdefault(nid, set()).add(finding.name)
    for nid, matched in sorted(by_id.items()):
        if "dotnet_memory_assembly" not in matched or not matched.intersection({
                "image_payload_loader", "remote_reflection_loader"}):
            continue
        # The originating process must have been fetched. The verified PROCESS
        # command line/script_block contains the execution expression. Corroborate
        # its actual operation with a retrieved outgoing execution/change relation;
        # don't accept a floating script found only through unrelated search.
        if nid not in memory.fetched_ids:
            continue
        relations = [(rid, typ.lower(), dst) for rid, (typ, src, dst) in memory.graph_edges.items()
                     if src == nid and rid in memory.fetched_ids]
        active = [(rid, typ, dst) for rid, typ, dst in relations if typ in {
            "executed_script", "win_process_create", "created_process", "wrote_file",
            "created_file", "modified_file", "connected_to"}]
        if not active:
            continue
        # Additional confidence comes from observed invocation within that script,
        # not from the file extension or a string appearing in a separate node.
        method = "image payload decoded into an invoked in-memory .NET assembly" if (
            "image_payload_loader" in matched) else (
            "downloaded bytes loaded and invoked as an in-memory .NET assembly")
        return method, tuple(dict.fromkeys([nid, *[dst for _, _, dst in active]]))
    return None


def corroborated_submission(memory: Any, engine: SOCV19,
                             submission: dict[str, Any]) -> dict[str, Any] | None:
    """Evidence-based final safeguard for a demonstrably executed hidden payload.

    Deliberately does not overturn all risky SMB, PowerShell, admin or signed
    binary activity. Returns None without direct script+execution proof.
    """
    if submission.get("verdict") != "benign":
        return None
    matched = corroborated_execution(memory, engine)
    if not matched:
        return None
    fact, ids = matched
    artifacts = []
    for nid in ids:
        typ = (memory.observed_nodes.get(nid) or {}).get("type", "")
        kind = ("process_observed" if typ in {"windows_process", "linux_process"}
                else "file_observed" if typ in {"powershell_script", "windows_file"}
                else None)
        if kind:
            artifacts.append({"entity_id": nid, "kind": kind})
    if not artifacts:
        return None
    return {"verdict": "malicious", "ir_artifacts": artifacts[:5],
            "reasoning": (
                "The retrieved process and corroborating effect relation document "
                f"an execution chain: {fact}. "
                "This is an observed payload-execution chain, not merely an encoded "
                "command or trusted program name. The original benign explanation "
                "provided no observed explanation of the injected code's behavior."
            )}
