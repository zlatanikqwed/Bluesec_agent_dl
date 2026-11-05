"""One table over all saved runs: sum(Q x E), mean Q, mean E, aborted tasks.

Usage (from the bluesec1-agent folder):
    uv run python scripts/summarize_runs.py                 # every runs* folder here
    uv run python scripts/summarize_runs.py runs_phaseO_*   # selected folders
    uv run python scripts/summarize_runs.py --csv runs_summary.csv

A folder may contain several run ids (one sub-folder per run); each run id is a
row.  in_progress/ is ignored.  The report mode is read from the trajectories
(audit "report_experiment"), so old and new runs are comparable.
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime
from pathlib import Path


def _mode(messages: list[dict]) -> str:
    for msg in messages:
        if msg.get("role") != "audit":
            continue
        text = str(msg.get("content") or "")
        if '"report_experiment"' not in text:
            continue
        try:
            value = json.loads(text).get("report_experiment")
        except ValueError:
            continue
        if value:
            return str(value)
    return "?"


def summarize(folder: Path) -> list[dict]:
    rows = []
    for run_dir in sorted(p for p in folder.iterdir() if p.is_dir() and p.name != "in_progress"):
        tasks, modes, mtime = [], {}, 0.0
        for file in run_dir.glob("*.json"):
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            result = data.get("task_result") if isinstance(data, dict) else None
            if not result:
                continue
            tasks.append(result)
            mode = _mode(data.get("messages") or [])
            modes[mode] = modes.get(mode, 0) + 1
            mtime = max(mtime, file.stat().st_mtime)
        if not tasks:
            continue
        q = [float(t.get("quality_score") or 0) for t in tasks]
        e = [float(t.get("efficiency_score") or 0) for t in tasks]
        aborted = sum(1 for t in tasks if t.get("completion_reason") != "terminated")
        rows.append({
            "folder": folder.name,
            "run_id": run_dir.name[:8],
            "finished": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M"),
            "mode": max(modes, key=modes.get),
            "tasks": len(tasks),
            "sum_QxE": round(sum(a * b for a, b in zip(q, e, strict=True)), 2),
            "per_30": round(30 * sum(a * b for a, b in zip(q, e, strict=True)) / len(tasks), 2),
            "mean_Q": round(sum(q) / len(q), 3),
            "mean_E": round(sum(e) / len(e), 3),
            "aborted": aborted,
        })
    return rows


def main(argv: list[str]) -> None:
    csv_path = None
    if argv[:1] == ["--csv"]:
        csv_path, argv = argv[1], argv[2:]
    folders = [Path(a) for a in argv] or sorted(Path(".").glob("runs*"))
    rows = [r for f in folders if f.is_dir() for r in summarize(f)]
    rows.sort(key=lambda r: r["finished"])
    if not rows:
        sys.exit("no runs found")
    cols = ["finished", "folder", "run_id", "mode", "tasks", "sum_QxE", "per_30",
            "mean_Q", "mean_E", "aborted"]
    width = {c: max(len(c), *(len(str(r[c])) for r in rows)) for c in cols}
    print("  ".join(c.ljust(width[c]) for c in cols))
    for r in rows:
        print("  ".join(str(r[c]).ljust(width[c]) for c in cols))
    best = max(rows, key=lambda r: r["per_30"])
    print(f"\nruns: {len(rows)}; best per 30 tasks: {best['per_30']} "
          f"({best['folder']}, {best['mode']})")
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=cols, delimiter=";")
            writer.writeheader()
            writer.writerows({c: r[c] for c in cols} for r in rows)
        print(f"saved {csv_path}")


if __name__ == "__main__":
    main(sys.argv[1:])
