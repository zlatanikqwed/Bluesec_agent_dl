"""Read-only SOC diagnostic replay. Never calls BlueSec or the LLM.

Usage: uv run python scripts/replay_soc_v17.py runs/<run-id>
       uv run python scripts/replay_soc_v17.py archive.zip
"""
from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path
from typing import Any

from bluesec1_agent.agent import InvestigationMemory, compact, decode_encoded_commands, parse_json_strings
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.security_engine import SecurityEngine


def assess(d: dict[str, Any], soc: SecurityEngine) -> tuple[dict[str, Any], int]:
    m = InvestigationMemory()
    initial = d.get("messages", [{} , {}])[1].get("content", "{}")
    try:
        blob = json.loads(initial)
    except (ValueError, TypeError):
        blob = {}
    observation = blob.get("initial_observation", {})
    m.absorb(compact(decode_encoded_commands(parse_json_strings(observation))))
    m.trigger_ids = set(m.known_ids)
    initial_alert = observation.get("alert_text", {})
    m.focus_ids = {e["id"] for e in initial_alert.get("trigger_entities", [])
                   if e.get("type") not in {"host", "windows_user", "ad_object"} and e.get("id")}
    last_finish = None
    for item in d.get("messages", []):
        if item.get("role") == "tool":
            try:
                obj = json.loads(item.get("content", "{}"))
            except ValueError:
                continue
            if obj.get("status") == "ok":
                m.absorb(obj.get("result"))
                if obj.get("result") and isinstance(obj["result"], dict):
                    ident = obj["result"].get("id")
                    if ident:
                        m.fetched_ids.add(ident)
        elif item.get("role") == "assistant" and item.get("tool_calls"):
            tool = item["tool_calls"][0]["function"]
            if tool.get("name") == "finish_investigation":
                try:
                    last_finish = json.loads(tool["arguments"]).get("submission", {})
                except (ValueError, TypeError):
                    pass
    last_finish = last_finish or {}
    findings = soc.hypotheses(m)
    checks = soc.review_questions(m, last_finish)
    return ({"verdict": last_finish.get("verdict"), "quality": d.get("task_result", {}).get("quality_score"),
             "findings": len(findings), "review_questions": len(checks),
             "top_findings": [f.technique for f in findings[:5]]}, len(m.graph_edges))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    args = parser.parse_args()
    src = Path(args.path)
    if src.suffix.lower() == ".zip":
        with zipfile.ZipFile(src) as z:
            cases = [json.loads(z.read(n)) for n in z.namelist() if n.endswith(".json")]
    else:
        cases = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(src.glob("*.json"))]
    soc = SecurityEngine(InvestigationDirector())
    misses = 0
    for case in cases:
        row, graph_size = assess(case, soc)
        if row["quality"] == 0:
            misses += 1
        print(f"quality={row['quality']!s:>5} verdict={str(row['verdict']):<9} "
              f"edges={graph_size:>2} hypotheses={row['findings']:>2} "
              f"open_questions={row['review_questions']} {','.join(row['top_findings'])}")
    print(f"cases={len(cases)} zero_quality={misses}; offline diagnostic only, no simulated score")


if __name__ == "__main__":
    main()
