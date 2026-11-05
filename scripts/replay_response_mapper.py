"""Offline: what would v25 response mapping submit for saved malicious trajectories?

Usage: uv run python scripts/replay_response_mapper.py runs/<RUN_ID> [--tier 2] [-v]
Read-only diagnostic; it cannot know the hidden ground truth or the score.
"""

from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import sys

import importlib.util  # noqa: E402

# Load the module by path so the replay does not need the agent's runtime deps.
_spec = importlib.util.spec_from_file_location(
    "response_mapper",
    os.path.join(os.path.dirname(__file__), "..", "src", "bluesec1_agent", "response_mapper.py"),
)
_rm = importlib.util.module_from_spec(_spec)
sys.modules["response_mapper"] = _rm
_spec.loader.exec_module(_rm)
ObservedGraph, map_response, merge_submission = _rm.ObservedGraph, _rm.map_response, _rm.merge_submission


def load(path: str) -> tuple[ObservedGraph, dict | None, dict]:
    data = json.load(open(path, encoding="utf-8"))
    graph = ObservedGraph()
    submission = None
    for msg in data.get("messages", []):
        content = msg.get("content") or ""
        if msg.get("role") == "user" and not graph.trigger_ids:
            try:
                graph.absorb_alert(json.loads(content).get("initial_observation", {}))
            except (ValueError, AttributeError):
                pass
        if msg.get("role") == "tool":
            try:
                graph.absorb(json.loads(content).get("result"))
            except (ValueError, AttributeError):
                pass
        for call in msg.get("tool_calls") or []:
            if call["function"]["name"] == "finish_investigation":
                submission = json.loads(call["function"]["arguments"])["submission"]
    return graph, submission, data.get("task_result", {})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--tier", type=int, default=2)
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    before, after = collections.Counter(), collections.Counter()
    for path in sorted(glob.glob(os.path.join(args.run_dir, "*.json"))):
        graph, sub, result = load(path)
        if not sub or sub.get("verdict") != "malicious":
            continue
        merged = merge_submission(sub, graph, max_tier=args.tier)
        before.update(a["kind"] for a in sub["ir_artifacts"])
        after.update(a["kind"] for a in merged["ir_artifacts"])
        q = result.get("quality_score", 0)
        print(f"\n{os.path.basename(path)[:8]} Q={q:.3f}  submitted={len(sub['ir_artifacts'])} "
              f"-> v25={len(merged['ir_artifacts'])}")
        if args.v:
            seeds = [a["entity_id"] for a in sub["ir_artifacts"]] + graph.trigger_ids
            for a in map_response(graph, seeds, max_tier=args.tier):
                p = graph.props(a["entity_id"])
                label = p.get("hostname") or p.get("username") or p.get("path") or p.get(
                    "dst_ip") or p.get("cmdline", "")
                print(f"   T{a['_tier']} {a['kind']:22s} {a['entity_id'][:8]} {str(label)[:70]}"
                      f"  <- {a['_why'][:60]}")
    print("\nkinds before:", dict(before))
    print("kinds after: ", dict(after))


if __name__ == "__main__":
    main()
