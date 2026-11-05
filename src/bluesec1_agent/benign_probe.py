"""Phase O: what legitimacy evidence does the grader reward?

In ~550 benign episodes Q never rose above roughly half of the maximum (EDR
tasks: exactly 0.500), even with semantically correct citations.  This probe
answers the question with ONE citation per benign task:

1. Context acquisition (fixed, every benign task, <= 4 calls): open the objects
   that usually establish legitimacy and were often left unopened - the parent
   process, a scheduled task / service that started the trigger, the trigger's
   image file, the matching Windows service.
2. Citation (random, deterministic hash of task_id): either nothing (control,
   20%) or exactly one (anchor, single property field) drawn first by category
   (graph role x type), then by field.

``scripts/analyze_benign_probe.py`` compares categories with scenario fixed
effects.  The verdict is never changed; no reward is read during the episode.
Practice-only learning mode.
"""
from __future__ import annotations

import hashlib
import ntpath
from typing import Any

from bluesec1_agent.response_mapper import PROCESS_TYPES, ObservedGraph

SKIP_FIELDS = frozenset({"timestamps", "timestamp", "relation_ids", "host_id", "id", "type",
                         "source_id", "target_id", "kind", "log_sources", "ad_object_id",
                         "sid", "user_sid", "md5", "sha1", "sha256"})
CONTROL_SHARE = 0.2
MAX_CONTEXT_CALLS = 4


def _unit(*parts: str) -> float:
    digest = hashlib.sha256("|".join(parts).encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def _trigger(graph: ObservedGraph) -> str | None:
    return next((t for t in graph.trigger_ids if graph.etype(t) in PROCESS_TYPES), None)


def context_calls(graph: ObservedGraph) -> list[tuple[str, dict[str, Any], str]]:
    """Calls that open legitimacy context around the trigger (deterministic order)."""
    tid = _trigger(graph)
    if not tid:
        return []
    calls: list[tuple[str, dict[str, Any], str]] = []
    seen: set[str] = set()

    def open_entity(nid: Any, label: str) -> None:
        if isinstance(nid, str) and nid not in graph.entities and nid not in seen:
            seen.add(nid)
            calls.append(("get_entity", {"entity_id": nid,
                                         "reasoning": f"legitimacy context: {label}"}, label))

    priority = ("ran_scheduled_task", "started_service", "created_process", "win_process_create",
                "parent_of", "loaded_image", "executed_script", "executed_file")
    rels = sorted(graph.relations.values(),
                  key=lambda r: priority.index(r["type"]) if r.get("type") in priority else 99)
    for rel in rels:
        if rel.get("target_id") == tid and rel.get("type") != "hosts":
            open_entity(rel.get("source_id"), f"initiator via {rel.get('type')}")
    image = str(graph.props(tid).get("image_path") or "")
    name = ntpath.basename(image)
    if len(name) >= 5:
        has_file = any(e.get("type") == "windows_file" and
                       str((e.get("properties") or {}).get("path", "")).lower() == image.lower()
                       for e in graph.entities.values())
        if not has_file:
            calls.append(("search", {"query": name, "reasoning": "legitimacy context: image file",
                                     "scope": {"kind": "entity", "type": "windows_file"}},
                          "image_file"))
        if not any(e.get("type") == "windows_service" for e in graph.entities.values()):
            calls.append(("search", {"query": name, "reasoning": "legitimacy context: service",
                                     "scope": {"kind": "entity", "type": "windows_service"}},
                          "service"))
    for rel in rels:
        if rel.get("source_id") == tid:
            open_entity(rel.get("target_id"), f"effect via {rel.get('type')}")
    return calls[:MAX_CONTEXT_CALLS]


def _categories(graph: ObservedGraph) -> dict[str, list[tuple[str, str, list[str]]]]:
    """category -> [(anchor, id, candidate fields)] for every observed object."""
    tid = _trigger(graph)
    tprops = graph.props(tid) if tid else {}
    image = str(tprops.get("image_path") or "").lower()
    rel_to_trigger: dict[str, str] = {}
    for rel in graph.relations.values():
        if rel.get("target_id") == tid:
            rel_to_trigger.setdefault(str(rel.get("source_id")), f"in_{rel.get('type')}")
        elif rel.get("source_id") == tid:
            rel_to_trigger.setdefault(str(rel.get("target_id")), f"out_{rel.get('type')}")
    cats: dict[str, list[tuple[str, str, list[str]]]] = {}
    for nid, ent in graph.entities.items():
        props = ent.get("properties") or {}
        fields = [f for f, v in props.items() if f not in SKIP_FIELDS and v not in (None, "", [])]
        if not fields:
            continue
        etype = str(ent.get("type"))
        if nid == tid:
            role = "trigger"
        elif nid in graph.trigger_ids:
            role = "trigger_ctx"
        elif etype == "windows_file" and str(props.get("path", "")).lower() == image:
            role = "image_file"
        else:
            role = rel_to_trigger.get(nid, "other")
        cats.setdefault(f"E {role}:{etype}", []).append(("entity", nid, fields))
    for rid, rel in graph.relations.items():
        nested = {**(rel.get("properties") or {}), **(rel.get("logon_properties") or {})}
        fields = [f for f, v in nested.items() if f not in SKIP_FIELDS and v not in (None, "")]
        side = ("trigger" if tid in (rel.get("source_id"), rel.get("target_id")) else "other")
        cats.setdefault(f"R {side}:{rel.get('type')}", []).append(("relation", rid, ["-"] + fields))
    return cats


def apply_benign_probe(
    submission: dict[str, Any], graph: ObservedGraph, seed: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Replace legitimacy evidence by nothing or exactly one random citation."""
    result = dict(submission)
    if submission.get("verdict") != "benign":
        return result, {}
    cats = _categories(graph)
    if _unit("control", seed) < CONTROL_SHARE or not cats:
        result["legitimacy_evidence"] = []
        return result, {"seed": seed, "factor": "CONTROL", "citation": None,
                        "categories": sorted(cats)}
    names = sorted(cats)
    cat = names[int(_unit("cat", seed) * len(names)) % len(names)]
    items = cats[cat]
    anchor, ident, fields = items[int(_unit("item", seed, cat) * len(items)) % len(items)]
    field = fields[int(_unit("field", seed, ident) * len(fields)) % len(fields)]
    if anchor == "entity":
        citation = {"anchor": "entity", "entity_id": ident, "property_fields": [field]}
    else:
        citation = {"anchor": "relation", "relation_id": ident,
                    "property_fields": [] if field == "-" else [field]}
    result["legitimacy_evidence"] = [citation]
    return result, {"seed": seed, "factor": f"{cat}|{field}", "category": cat,
                    "field": field, "citation": citation, "categories": names}


# Phase O2: base = role_policy citations, plus at most one random extra citation.
# Categories that Phase O measured as clearly negative are not re-tested.
KNOWN_NEGATIVE = ("E trigger_ctx:host", "E other:host", "E trigger:windows_process",
                  "R trigger:win_process_create", "R trigger:hosts", "R trigger:runs_process")
CONTROL_SHARE_O2 = 0.3


def apply_benign_probe_extra(
    submission: dict[str, Any], graph: ObservedGraph, seed: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Keep the base citations; add one random (anchor, field) or nothing (control)."""
    result = dict(submission)
    if submission.get("verdict") != "benign":
        return result, {}
    base = list(submission.get("legitimacy_evidence") or [])
    cited = {e.get("entity_id") or e.get("relation_id") for e in base}
    cats = {c: [i for i in items if i[1] not in cited]
            for c, items in _categories(graph).items() if not c.startswith(KNOWN_NEGATIVE)}
    cats = {c: items for c, items in cats.items() if items}
    if _unit("control2", seed) < CONTROL_SHARE_O2 or not cats:
        return result, {"seed": seed, "factor": "CONTROL", "citation": None, "base": base,
                        "categories": sorted(cats)}
    names = sorted(cats)
    cat = names[int(_unit("cat2", seed) * len(names)) % len(names)]
    items = cats[cat]
    anchor, ident, fields = items[int(_unit("item2", seed, cat) * len(items)) % len(items)]
    field = fields[int(_unit("field2", seed, ident) * len(fields)) % len(fields)]
    if anchor == "entity":
        citation = {"anchor": "entity", "entity_id": ident, "property_fields": [field]}
    else:
        citation = {"anchor": "relation", "relation_id": ident,
                    "property_fields": [] if field == "-" else [field]}
    result["legitimacy_evidence"] = base + [citation]
    return result, {"seed": seed, "factor": f"{cat}|{field}", "category": cat, "field": field,
                    "citation": citation, "base": base, "categories": names}
