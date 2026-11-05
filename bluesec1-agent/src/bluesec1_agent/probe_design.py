"""Phase M: randomized report probe (Practice only).

Phase H-L tested one hypothesis per 30-task run.  Within a template the score is
deterministic, so most arms differed by +/-0.2 and were indistinguishable.
This module instead randomizes MANY report factors inside every task:

* malicious: every observed candidate entity gets a role (trigger_host,
  child_process, modified_file, deleted_file, external_host, ...) and is either
  omitted or reported with one randomly chosen plausible ``kind``;
* benign: every candidate anchor is either omitted or cited with a randomly
  chosen field set.

The choice is a deterministic hash of ``task_id`` and entity id, so a run can be
re-analysed exactly.  The design is written into the trajectory and
``scripts/analyze_probe.py`` regresses the final reward on it with per-scenario
fixed effects.  That yields the value of each (role, kind) / (role, fields)
factor from 2-3 runs instead of 2-3 factors.

The verdict is never changed and no runtime reward is read during the episode.
This mode is for learning the response policy on Practice; do not submit it as
the final agent.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any

from bluesec1_agent.response_mapper import (
    FILE_TYPES,
    PERSISTENCE_TYPES,
    PROCESS_TYPES,
    USER_TYPES,
    ObservedGraph,
    _private,
    malicious_process_set,
)

EXEC_EXT = re.compile(r"\.(?:exe|dll|sys|scr|com|msi|ps1|bat|cmd|vbs|js|hta)$", re.I)
ARCHIVE_EXT = re.compile(r"\.(?:zip|rar|7z|tar|gz|cab|iso)$", re.I)

# Plausible kinds per role.  "omit" is always added by the sampler.
MALICIOUS_ROLE_KINDS: dict[str, tuple[str, ...]] = {
    "trigger_host": ("host_to_isolate",),
    "trigger_user": ("identity_to_rotate", "identity_observed"),
    "trigger_process": ("process_observed",),
    "parent_process": ("process_observed",),
    "child_process": ("process_observed",),
    "written_exec": ("file_to_delete", "file_observed", "cleanup_to_verify"),
    "written_archive": ("file_to_delete", "file_observed", "cleanup_to_verify"),
    "modified_file": ("file_observed", "cleanup_to_verify", "file_to_delete"),
    "written_file": ("file_observed", "cleanup_to_verify", "file_to_delete"),
    "deleted_file": ("cleanup_to_verify", "file_observed"),
    "read_file": ("file_observed",),
    "script": ("file_observed", "artifact_observed"),
    "external_host": ("network_block",),
    "external_conn": ("network_block",),
    "internal_peer_host": ("host_to_isolate",),
    "persistence": ("persistence_to_remove", "registry_observed", "artifact_observed"),
    "group_changed_user": ("identity_to_rotate", "identity_observed"),
    "other_user": ("identity_to_rotate", "identity_observed"),
}

# Candidate property fields per role for benign citations (only present fields are used).
BENIGN_ROLE_FIELDS: dict[str, tuple[tuple[str, ...], ...]] = {
    "trigger_process": (("image_path",), ("cmdline",), ("parent_image",), ("signer",),
                        ("cmdline", "user")),
    "parent_process": (("image_path",), ("cmdline",)),
    "child_process": (("image_path",), ("cmdline",)),
    "trigger_user": (("username",), ("group_memberships",), ("username", "group_memberships")),
    "other_user": (("username",), ("group_memberships",)),
    "group_changed_user": (("username",), ("group_memberships",)),
    "trigger_host": (("hostname",), ("role",), ("hostname", "role")),
    "internal_peer_host": (("hostname",), ("role",), ("hostname", "role")),
    "script": (("path",), ("script_text",), ("name",)),
    "persistence": (("task_name",), ("service_name",), ("binary_path",), ("action",),
                    ("key_path",), ("name",)),
    "written_file": (("path",),),
    "modified_file": (("path",),),
    "read_file": (("path",),),
    "deleted_file": (("path",),),
}
BENIGN_RELATION_ROLES = {
    "logged_on_to": "logon_relation",
    "ran_scheduled_task": "scheduled_task_relation",
    "win_process_create": "spawn_relation",
    "started_service": "service_relation",
    "accepted_connection_from": "inbound_relation",
}

MAX_PER_ROLE = 4
OMIT_PROBABILITY = 0.4


def _unit(*parts: str) -> float:
    digest = hashlib.sha256("|".join(parts).encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def _pick(seq: tuple[Any, ...], *parts: str) -> Any:
    return seq[int(_unit("pick", *parts) * len(seq)) % len(seq)]


def _ip_of(props: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = props.get(key)
        if value:
            try:
                return str(ipaddress.ip_address(str(value)))
            except ValueError:
                continue
    return ""


def _path(props: dict[str, Any]) -> str:
    return str(props.get("path") or props.get("file_path") or props.get("filename")
               or props.get("unc_path") or "")


def candidate_roles(graph: ObservedGraph) -> dict[str, list[str]]:
    """Map role -> observed entity ids (entities actually returned by the runtime)."""
    roles: dict[str, list[str]] = {r: [] for r in MALICIOUS_ROLE_KINDS}
    known = graph.entities
    triggers = [t for t in graph.trigger_ids if graph.etype(t) in PROCESS_TYPES]
    procs = malicious_process_set(graph, triggers)

    def add(role: str, nid: str | None) -> None:
        if nid and nid in known and nid not in roles[role]:
            roles[role].append(nid)

    trigger_hosts: set[str] = set()
    for tid in triggers:
        add("trigger_process", tid)
        host = known.get(tid, {}).get("host_id")
        for rel in graph.inc(tid, {"hosts"}):
            host = host or rel["source_id"]
        if host:
            trigger_hosts.add(host)
            add("trigger_host", host)
        for rel in graph.inc(tid, {"runs_process"}):
            add("trigger_user", rel["source_id"])
        for rel in graph.inc(tid, {"win_process_create", "parent_of"}):
            add("parent_process", rel["source_id"])
    for tid in graph.trigger_ids:
        if graph.etype(tid) == "host":
            trigger_hosts.add(tid)
            add("trigger_host", tid)

    for pid in sorted(procs - set(triggers)):
        add("child_process", pid)

    read_by_chain: set[str] = set()
    written_by_chain: set[str] = set()
    deleted_by_chain: set[str] = set()
    for pid in procs:
        for rel in graph.out(pid, {"read_file"}):
            read_by_chain.add(rel["target_id"])
        for rel in graph.out(pid, {"wrote_file", "renamed_file", "extracted_to", "archived_to"}):
            written_by_chain.add(rel["target_id"])
        for rel in graph.out(pid, {"deleted_file"}):
            deleted_by_chain.add(rel["target_id"])
        for rel in graph.out(pid, {"executed_script"}):
            add("script", rel["target_id"])
        for rel in graph.out(pid, {"created_service", "modified_service", "created_scheduled_task",
                                   "set_registry_value", "created_registry_key"}):
            add("persistence", rel["target_id"])
        for rel in graph.out(pid, {"added_to_group", "removed_from_group", "changed_password",
                                   "created_account"}):
            add("group_changed_user", rel["target_id"])

    for fid in sorted(written_by_chain | deleted_by_chain | read_by_chain):
        if graph.etype(fid) not in FILE_TYPES:
            continue
        path = _path(graph.props(fid))
        if fid in deleted_by_chain:
            add("deleted_file", fid)
        elif fid in written_by_chain and fid in read_by_chain:
            add("modified_file", fid)
        elif fid in written_by_chain and ARCHIVE_EXT.search(path):
            add("written_archive", fid)
        elif fid in written_by_chain and EXEC_EXT.search(path):
            add("written_exec", fid)
        elif fid in written_by_chain:
            add("written_file", fid)
        else:
            add("read_file", fid)

    for nid, ent in known.items():
        etype = ent.get("type")
        props = ent.get("properties") or {}
        if etype == "host" and nid not in trigger_hosts:
            ip = _ip_of(props, ("ip", "ip_address"))
            external = str(props.get("role") or "").lower() == "external" or _private(ip) is False
            add("external_host" if external else "internal_peer_host", nid)
        elif etype == "network_connection":
            ip = _ip_of(props, ("dst_ip", "destination_ip", "remote_ip", "src_ip", "source_ip"))
            if _private(ip) is False:
                add("external_conn", nid)
        elif etype in PERSISTENCE_TYPES:
            add("persistence", nid)
        elif etype in USER_TYPES and nid not in roles["trigger_user"] \
                and nid not in roles["group_changed_user"]:
            add("other_user", nid)
    return {role: ids[:MAX_PER_ROLE] for role, ids in roles.items() if ids}


def _design_malicious(graph: ObservedGraph, seed: str) -> list[dict[str, Any]]:
    design = []
    for role, ids in candidate_roles(graph).items():
        for nid in ids:
            omit = _unit("omit", seed, role, nid) < OMIT_PROBABILITY
            kind = None if omit else _pick(MALICIOUS_ROLE_KINDS[role], seed, role, nid)
            design.append({"entity_id": nid, "role": role, "type": graph.etype(nid),
                           "kind": kind, "included": not omit})
    return design


def _design_benign(graph: ObservedGraph, seed: str) -> list[dict[str, Any]]:
    design = []
    for role, ids in candidate_roles(graph).items():
        options = BENIGN_ROLE_FIELDS.get(role)
        if not options:
            continue
        for nid in ids:
            props = graph.props(nid)
            present = tuple(f for f in options
                            if all(props.get(x) not in (None, "", []) for x in f))
            if not present:
                continue
            omit = _unit("omit", seed, role, nid) < 0.5
            fields = list(_pick(present, seed, role, nid))
            design.append({"anchor": "entity", "entity_id": nid, "role": role,
                           "type": graph.etype(nid), "property_fields": fields,
                           "included": not omit})
    rel_counts: dict[str, int] = {}
    for rid, rel in sorted(graph.relations.items()):
        role = BENIGN_RELATION_ROLES.get(str(rel.get("type")))
        if not role or rel_counts.get(role, 0) >= 2:
            continue
        rel_counts[role] = rel_counts.get(role, 0) + 1
        nested = rel.get("logon_properties") or rel.get("properties") or {}
        fields_opts: list[tuple[str, ...]] = [()]
        for key in ("logon_type", "task_name", "protocol", "source_ip"):
            if nested.get(key) not in (None, ""):
                fields_opts.append((key,))
        omit = _unit("omit", seed, role, rid) < 0.5
        fields = list(_pick(tuple(fields_opts), seed, role, rid))
        design.append({"anchor": "relation", "relation_id": rid, "role": role,
                       "type": rel.get("type"), "property_fields": fields,
                       "included": not omit})
    return design


def apply_random_probe(
    submission: dict[str, Any], graph: ObservedGraph, seed: str, *, max_benign: int = 6,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (randomized submission, design).  The verdict and reasoning are kept."""
    verdict = submission.get("verdict")
    result = {k: v for k, v in submission.items()}
    if verdict == "malicious":
        design = _design_malicious(graph, seed)
        result["ir_artifacts"] = [
            {"entity_id": d["entity_id"], "kind": d["kind"]} for d in design if d["included"]
        ]
    elif verdict == "benign":
        design = _design_benign(graph, seed)
        chosen = [d for d in design if d["included"]][:max_benign]
        chosen_ids = {id(d) for d in chosen}
        for d in design:
            d["included"] = id(d) in chosen_ids
        evidence = []
        for d in chosen:
            if d["anchor"] == "entity":
                evidence.append({"anchor": "entity", "entity_id": d["entity_id"],
                                 "property_fields": d["property_fields"]})
            else:
                evidence.append({"anchor": "relation", "relation_id": d["relation_id"],
                                 "property_fields": d["property_fields"]})
        result["legitimacy_evidence"] = evidence
    else:
        design = []
    return result, {"verdict": verdict, "seed": seed, "factors": design}


# ---------------------------------------------------------------------------
# Phase N: exploration probe.  The report is fixed (baseline inbound_guard);
# right before finish_investigation the agent opens a RANDOM subset of
# not-yet-opened relation endpoints, grouped by category.  Regressing the final
# reward on the categories opened answers: does merely observing a key object
# (thoroughness) raise the score, and which objects are worth a tool call?
# ---------------------------------------------------------------------------

EXPLORE_CATEGORIES: dict[str, frozenset[str]] = {
    "child_process": frozenset({"win_process_create", "parent_of"}),
    "written_file": frozenset({"wrote_file", "renamed_file", "extracted_to", "archived_to"}),
    "read_file": frozenset({"read_file"}),
    "deleted_file": frozenset({"deleted_file"}),
    "group_change": frozenset({"added_to_group", "removed_from_group", "changed_password",
                               "created_account"}),
    "persistence": frozenset({"created_service", "modified_service", "created_scheduled_task",
                              "set_registry_value", "created_registry_key", "ran_scheduled_task",
                              "started_service"}),
    "script": frozenset({"executed_script", "executed_file", "loaded_image"}),
    "network": frozenset({"connected_to", "accepted_connection_from", "sent_data_to"}),
    "cmdlet": frozenset({"invoked_cmdlet"}),
    "handle_target": frozenset({"opened_handle", "opened_handle_on_ad_object", "created_pipe"}),
}
EXPLORE_PER_CATEGORY = 2
EXPLORE_MAX_CALLS = 8


def explore_design(graph: ObservedGraph, seed: str) -> dict[str, Any]:
    """Pick unopened endpoints of observed relations from the trigger chain."""
    triggers = [t for t in graph.trigger_ids if graph.etype(t) in PROCESS_TYPES]
    chain = malicious_process_set(graph, triggers) or set(graph.trigger_ids)
    by_cat: dict[str, list[str]] = {c: [] for c in EXPLORE_CATEGORIES}
    for _rid, rel in sorted(graph.relations.items()):
        rtype = rel.get("type")
        src, dst = rel.get("source_id"), rel.get("target_id")
        if src not in chain:
            continue
        for cat, types in EXPLORE_CATEGORIES.items():
            if rtype in types and isinstance(dst, str) and dst not in graph.entities \
                    and dst not in by_cat[cat]:
                by_cat[cat].append(dst)
    categories = []
    planned: list[tuple[str, str]] = []
    for cat, ids in by_cat.items():
        if not ids:
            continue
        on = _unit("explore", seed, cat) < 0.5
        ranked = sorted(ids, key=lambda i: _unit("order", seed, i))
        chosen = ranked[:EXPLORE_PER_CATEGORY] if on else []
        categories.append({"category": cat, "available": len(ids), "enabled": on,
                           "entity_ids": chosen})
        planned.extend((cat, i) for i in chosen)
    planned.sort(key=lambda ci: _unit("seq", seed, ci[1]))
    planned = planned[:EXPLORE_MAX_CALLS]
    kept = {i for _, i in planned}
    for c in categories:
        c["entity_ids"] = [i for i in c["entity_ids"] if i in kept]
        c["opened"] = len(c["entity_ids"])
    return {"seed": seed, "categories": categories, "calls": planned}


EXPAND_MAX = 3


def expand_design(graph: ObservedGraph, seed: str) -> list[dict[str, Any]]:
    """Child processes of the trigger chain whose own effects were never searched.

    An enabled child gets one unscoped ``search(child_id)``; it returns the
    child's relations, so their endpoints become candidates for explore_design.
    """
    triggers = [t for t in graph.trigger_ids if graph.etype(t) in PROCESS_TYPES]
    chain = malicious_process_set(graph, triggers)
    spawn = {"win_process_create", "parent_of", "hosts", "runs_process"}
    out = []
    for pid in sorted(chain - set(triggers), key=lambda i: _unit("child", seed, i)):
        known_effects = [r for r in graph.out(pid) if r.get("type") not in spawn]
        if known_effects:
            continue
        out.append({"entity_id": pid, "enabled": _unit("expand", seed, pid) < 0.5})
        if len(out) >= EXPAND_MAX:
            break
    return out
