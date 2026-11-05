"""Read local Practice trajectories; compare final report before/after A/B switch.

No access to runtime reward during episodes. Usage:
    python scripts/analyze_report_experiments.py runs_report_control runs_report_malicious_files ...
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def read_events(path: Path) -> dict:
    doc = json.loads(path.read_text(encoding="utf-8-sig"))
    experiment = None
    for msg in doc.get("messages", []):
        if msg.get("role") != "audit":
            continue
        try:
            value = json.loads(msg.get("content") or "{}")
        except (ValueError, TypeError):
            continue
        if "report_experiment" in value:
            experiment = value
    task = doc.get("task_result") or {}
    before = (experiment or {}).get("report_before") or {}
    after = (experiment or {}).get("report_after") or {}
    return {
        "source_file": str(path), "task_id": task.get("task_id", path.stem),
        "mode": (experiment or {}).get("report_experiment", "unknown"),
        "completion_reason": task.get("completion_reason", ""),
        "quality_score": task.get("quality_score", ""),
        "efficiency_score": task.get("efficiency_score", ""),
        "steps_taken": task.get("steps_taken", ""),
        "verdict": after.get("verdict", ""),
        "changed_fields": ",".join((experiment or {}).get("report_changed_fields") or []),
        "ir_before": json.dumps(before.get("ir_artifacts") or [], ensure_ascii=False),
        "ir_after": json.dumps(after.get("ir_artifacts") or [], ensure_ascii=False),
        "benign_before": json.dumps(before.get("legitimacy_evidence") or [], ensure_ascii=False),
        "benign_after": json.dumps(after.get("legitimacy_evidence") or [], ensure_ascii=False),
        "reason_before": before.get("reasoning", ""),
        "reason_after": after.get("reasoning", ""),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline report experiment review")
    parser.add_argument("directories", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=Path("report-experiments.csv"))
    args = parser.parse_args()
    paths = []
    for directory in args.directories:
        paths += [p for p in directory.rglob("*.json") if "in_progress" not in p.parts]
    rows = []
    for path in sorted(set(paths)):
        try:
            rows.append(read_events(path))
        except (OSError, ValueError) as exc:
            print(f"Warning: skip {path}: {exc}")
    if not rows:
        print("No complete trajectory JSON files found")
        return
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} cases to {args.out}")
    from collections import defaultdict
    scores: dict[str, list[float]] = defaultdict(list)
    for row in rows:
        try:
            scores[row["mode"]].append(float(row["quality_score"]))
        except (ValueError, TypeError):
            pass
    for mode, values in sorted(scores.items()):
        print(f"{mode}: cases={len(values)} mean_quality={sum(values)/len(values):.4f}")


if __name__ == "__main__":
    main()
