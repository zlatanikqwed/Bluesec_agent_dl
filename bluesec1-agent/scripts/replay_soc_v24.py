"""Read-only v24 threat-action and citation diagnostic; no predicted scores.

uv run python scripts/replay_soc_v24.py runs/<RUN_ID>
uv run python scripts/replay_soc_v24.py <trajectory-archive>.zip
"""
from __future__ import annotations
import argparse
from pathlib import Path
from replay_soc_v20 import load
from replay_soc_v18 import case_memory
from bluesec1_agent.soc_v24 import ThreatCasebook
from bluesec1_agent.soc_v23 import SemanticEvidenceValidator


def run(path: Path) -> None:
    book=ThreatCasebook(); semantic=SemanticEvidenceValidator()
    zeros=0; missing_zero=0; missing_nonzero=0; total=0
    for case in load(path):
        mem,sub=case_memory(case)
        result=case.get('task_result') or {}
        zero=float(result.get('quality_score') or 0)==0
        if zero:zeros+=1
        actions=book.observed_actions(mem)
        gaps=book.challenge(mem,sub)
        sem=semantic.issues(mem,sub)
        total+=len(actions)
        missing_zero+=bool(zero and gaps)
        missing_nonzero+=bool(not zero and gaps)
        print(f"{str(result.get('task_id',''))[:8]} Q={float(result.get('quality_score') or 0):.2f} "
              f"verdict={str(sub.get('verdict','?')):<9} actions={len(actions):2} "
              f"action_gaps={len(gaps)} semantic_gaps={len(sem)} "
              + ','.join(g.code for g in gaps[:3]))
    print(f'cases={len(load(path))} zero_quality={zeros} observed_actions={total} '
          f'zero_with_action_gaps={missing_zero} nonzero_with_action_gaps={missing_nonzero}. '
          'READ-ONLY DIAGNOSTIC; NO REPLAYED MODEL DECISIONS OR SCORE.')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('path',type=Path)
    run(parser.parse_args().path)
