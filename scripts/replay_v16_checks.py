"""Offline audit of saved BlueSec trajectories; does NOT re-run the LLM or benchmark.

Usage: uv run python scripts/replay_v16_checks.py path/to/run.zip
       uv run python scripts/replay_v16_checks.py runs/<run-id>

This script reports whether the v16 verifier can reconstruct verified effects and
where old benign decisions cited only provenance rather than observed effects.
It cannot estimate v16 reward, hidden ground truth or the revised LLM verdict.
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from bluesec1_agent.agent import InvestigationMemory  # noqa: E402
from bluesec1_agent.evidence_workbench import EvidenceWorkbench  # noqa: E402
from bluesec1_agent.investigation_director import InvestigationDirector  # noqa: E402


def load_cases(path: Path) -> Iterable[tuple[str, dict[str, Any]]]:
    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if name.endswith(".json"):
                    yield Path(name).stem, json.loads(z.read(name))
    else:
        for filename in sorted(path.glob("*.json")):
            yield filename.stem, json.loads(filename.read_text(encoding="utf-8"))


def parse(raw: Any) -> Any:
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (ValueError, TypeError):
            return {}
    return raw


def reconstruct(case: dict[str, Any]) -> tuple[InvestigationMemory, dict[str, Any]]:
    messages = case.get("messages") or []
    memory = InvestigationMemory()
    initial = parse(messages[1].get("content", "{}")) if len(messages) > 1 else {}
    observation = initial.get("initial_observation") or {}
    memory.absorb(observation)
    memory.trigger_ids = set(memory.known_ids)
    alert = observation.get("alert_text") or {}
    anchors = [x for x in alert.get("trigger_entities", [])
               if isinstance(x, dict) and isinstance(x.get("id"), str)]
    memory.focus_ids = {x["id"] for x in anchors
                        if x.get("type") not in {"host", "windows_user", "linux_user"}}
    if not memory.focus_ids:
        memory.focus_ids = {x["id"] for x in anchors}
    for item in alert.get("trigger_relations") or []:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            memory.fetched_ids.add(item["id"])
    latest_tool = ("", {})
    last_finish: dict[str, Any] = {}
    for message in messages[2:]:
        if message.get("role") == "assistant":
            for tc in message.get("tool_calls") or []:
                fn = tc.get("function") or {}
                tool = fn.get("name") or ""
                args = parse(fn.get("arguments") or "{}")
                latest_tool = (tool, args)
                if tool == "finish_investigation":
                    last_finish = args.get("submission") or {}
        elif message.get("role") == "tool":
            event = parse(message.get("content"))
            if not isinstance(event, dict):
                continue
            if event.get("status") == "ok" and event.get("result"):
                memory.absorb(event["result"])
            tool, args = latest_tool
            key = {"get_entity": "entity_id", "get_relation": "relation_id",
                   "get_ad_object_info": "ad_object_id"}.get(tool)
            if key and args.get(key):
                memory.fetched_ids.add(args[key])
            if tool and tool != "finish_investigation":
                memory.calls_made.append(tool)
    return memory, last_finish


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    workbench = EvidenceWorkbench(InvestigationDirector())
    count = 0
    with_effects = 0
    missed_effects = 0
    still_unopened = 0
    fail_rows = []
    for name, data in load_cases(args.path):
        memory, final = reconstruct(data)
        effects = workbench.effects(memory)
        count += 1
        with_effects += bool(effects)
        unobserved = [x for x in effects if x.weight >= 4 and not x.target_opened]
        still_unopened += bool(unobserved)
        if final.get("verdict") == "benign":
            missing = workbench.uncovered(memory, final)
            if missing:
                missed_effects += 1
                fail_rows.append((name[:8], len(missing),
                                  ", ".join(x.kind for x in missing)))
    print(f"Cases: {count}")
    print(f"Cases with alert-linked verified behavioral effects: {with_effects}")
    print(f"Cases with a high-impact endpoint not fully opened: {still_unopened}")
    print(f"Benign submissions with >=1 behavior missing from citations: {missed_effects}")
    for name, n, kinds in fail_rows[:12]:
        print(f"  {name}: uncovered={n}; actions={kinds[:90]}")
    print("This is an OFFLINE citation/coverage diagnostic, NOT a benchmark score.")


if __name__ == "__main__":
    main()
