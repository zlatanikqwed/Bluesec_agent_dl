"""Read-only v23 semantic evidence diagnostic. NEVER predicts leaderboard results.

Usage: uv run python scripts/replay_soc_v23.py runs/<RUN_ID>
       uv run python scripts/replay_soc_v23.py exported-trajectories.zip
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from replay_soc_v18 import case_memory
from replay_soc_v20 import load
from bluesec1_agent.soc_v23 import SemanticEvidenceValidator


def run(path: Path) -> None:
    cases = load(path)
    validator = SemanticEvidenceValidator()
    zeros = 0
    challenged_cases = 0
    critical_zero = 0
    errors = 0
    breakdown = Counter()
    for case in cases:
        memory, sub = case_memory(case)
        task = case.get('task_result') or {}
        q = float(task.get('quality_score') or 0)
        zero = q == 0
        issues = validator.issues(memory, sub)
        critical = [i for i in issues if i.weight >= 5]
        breakdown.update(i.code for i in critical)
        n_rejects = 0
        for msg in case.get('messages') or []:
            if msg.get('role') != 'tool':
                continue
            try:
                response = json.loads(msg.get('content') or '{}')
            except (ValueError, TypeError):
                continue
            if (response.get('status') == 'error' and
                    'strong observed attack indicators' in str(response.get('message') or '')):
                n_rejects += 1
        errors += n_rejects
        challenged_cases += bool(critical)
        zeros += zero
        critical_zero += zero and bool(critical)
        print(f"{str(task.get('task_id',''))[:8]} Q={q:.2f} "
              f"verdict={sub.get('verdict','?'):<9} semantic_issues={len(issues):2} "
              f"critical={len(critical):2} rejected_finish={n_rejects:2} "
              + ','.join(i.code for i in critical[:4]))
    print(f"cases={len(cases)} zero_quality={zeros} "
          f"cases_with_critical_claims={challenged_cases} "
          f"zero_with_critical_claims={critical_zero} "
          f"rejected_strong_benign_attempts={errors} "
          f"claim_types={dict(breakdown)}. "
          "READ-ONLY: no simulated calls, classifications or score.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=Path)
    run(parser.parse_args().path)
