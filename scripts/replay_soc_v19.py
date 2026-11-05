"""Read-only regression of v19 forensic findings; no simulated score or API calls.

Example: uv run python scripts/replay_soc_v19.py runs/<id>
         uv run python scripts/replay_soc_v19.py trajectories.zip
"""
from __future__ import annotations
import argparse
import json
import zipfile
from pathlib import Path
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.soc_v19 import SOCV19
from replay_soc_v18 import case_memory


def main(path: Path) -> None:
    if path.is_file() and path.suffix.lower()=='.zip':
        with zipfile.ZipFile(path) as z:
            cases=[json.loads(z.read(n)) for n in sorted(z.namelist()) if n.endswith('.json')]
    else:
        cases=[json.loads(p.read_text('utf-8')) for p in sorted(path.glob('*.json'))]
    agent=SOCV19(InvestigationDirector())
    zero=0
    high_zero=0
    empty_evidence=0
    for case in cases:
        mem,submission=case_memory(case)
        res=case.get('task_result') or {}
        findings=agent.findings(mem)
        gaps=agent.benign_gaps(mem,submission)
        repaired, removed=agent.sanitize(submission,mem)
        lead=agent.next_inspection(mem,{'get_entity','get_relation','get_ad_object_info'})
        is_zero=res.get('quality_score') == 0
        zero+=int(is_zero)
        high_zero+=int(is_zero and any(f.severity>=7 for f in findings))
        empty_evidence+=int(submission.get('verdict')=='benign' and not submission.get('legitimacy_evidence'))
        print(f"{str(res.get('task_id',''))[:8]} quality={str(res.get('quality_score')):<6} "
              f"verdict={submission.get('verdict','?'):<9} findings={len(findings):2} "
              f"benign_gaps={len(gaps)} next={lead.lead.tool if lead else '-':<12} "
              f"evidence_after_validation={len(repaired.get('legitimacy_evidence') or repaired.get('ir_artifacts') or []):2} "
              + ','.join(f.name for f in findings[:2]))
    print(f'cases={len(cases)} zero_quality={zero} high_priority_zero={high_zero} '
          f'empty_original_benign={empty_evidence}; READ-ONLY DIAGNOSTIC — no predicted leaderboard score')


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('path',type=Path)
    main(parser.parse_args().path)
