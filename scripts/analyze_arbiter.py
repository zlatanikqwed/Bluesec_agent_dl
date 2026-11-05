"""Where did the arbiter model decide, and did it differ from the main model?

Usage:
    uv run python scripts/analyze_arbiter.py runs_arbiter1 [runs_arbiter2 ...]

For every arbitration logged by the optional arbiter model it prints the task,
the call type, who answered (arbiter or fallback to the main model), the
arbiter verdict, the main model's shadow verdict and the task quality. A task
with quality 0 almost always means a wrong final verdict.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def main(folders: list[str]) -> None:
    rows = []
    for folder in folders:
        for file in Path(folder).rglob("*.json"):
            if "in_progress" in file.parts:
                continue
            try:
                data = json.loads(file.read_text(encoding="utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            result = data.get("task_result") if isinstance(data, dict) else None
            if not result:
                continue
            for msg in data.get("messages") or []:
                text = msg.get("content")
                if msg.get("role") != "audit" or not isinstance(text, str) or '"arbiter_call"' not in text:
                    continue
                try:
                    rec = json.loads(text)
                except ValueError:
                    continue
                rows.append((str(result.get("task_id", ""))[:8], rec, float(result.get("quality_score") or 0)))
    if not rows:
        sys.exit("no arbiter calls found (is LLM_ARBITER_MODEL set?)")
    print(f"{'task':8}  {'call':12} {'source':13} {'arbiter':9} {'main':9} Q")
    for task, rec, q in rows:
        print(f"{task:8}  {rec.get('arbiter_call', ''):12} {rec.get('source', ''):13} "
              f"{str(rec.get('verdict')):9} {str(rec.get('shadow_main_verdict', '-')):9} {q:.3f}")
    fallback = sum(1 for _, r, _ in rows if r.get("source") != "arbiter")
    differ = [(t, r, q) for t, r, q in rows
              if r.get("shadow_main_verdict") and r.get("shadow_main_verdict") != r.get("verdict")]
    print(f"\narbitrations: {len(rows)}; fallback to main: {fallback}; "
          f"arbiter != main: {len(differ)}")
    for t, r, q in differ:
        verdict_ok = "ok" if q > 0 else "WRONG"
        print(f"  {t}: arbiter={r.get('verdict')} main={r.get('shadow_main_verdict')} "
              f"Q={q:.3f} final verdict {verdict_ok}")


if __name__ == "__main__":
    main(sys.argv[1:])
