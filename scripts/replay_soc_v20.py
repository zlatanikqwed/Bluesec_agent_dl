"""Read-only v20 diagnostics: old audit timing and the observed SOC evidence gaps.

No remote calls, no inferred true verdicts, and no predicted leaderboard score.
Usage: uv run python scripts/replay_soc_v20.py runs/<run-id>
       uv run python scripts/replay_soc_v20.py exported-run.zip
"""
from __future__ import annotations
import argparse
import json
import zipfile
from pathlib import Path
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.soc_v19 import SOCV19
from bluesec1_agent.soc_v20 import ForensicCaseState
from replay_soc_v18 import case_memory


def load(path: Path):
    if path.is_file() and path.suffix.lower()=='.zip':
        with zipfile.ZipFile(path) as z:
            return [json.loads(z.read(n)) for n in sorted(z.namelist()) if n.endswith('.json')]
    return [json.loads(p.read_text('utf-8')) for p in sorted(path.rglob('*.json'))]


def run(path: Path) -> None:
    cases=load(path)
    early=0;zero=0;high_zero=0;empty_benign=0
    for data in cases:
        mem,sub=case_memory(data)
        result=data.get('task_result') or {}
        engine=SOCV19(InvestigationDirector()); state=ForensicCaseState(engine)
        hypotheses=engine.findings(mem)
        gaps=engine.benign_gaps(mem,sub)
        reviewed_at=[];tools=0;reviews=0
        for msg in data.get('messages',[]):
            if msg.get('role')=='assistant':
                for c in msg.get('tool_calls') or []:
                    if c.get('function',{}).get('name')!='finish_investigation':tools+=1
            if msg.get('role')=='audit':
                try:event=json.loads(msg.get('content') or '{}')
                except (TypeError,ValueError):continue
                if 'blind_review' in event:
                    reviewed_at.append(tools);reviews+=1
        early+=int(any(i<3 for i in reviewed_at))
        q=result.get('quality_score')
        is_zero=q is not None and float(q)==0
        zero+=int(is_zero)
        high_zero+=int(is_zero and any(h.severity>=7 for h in hypotheses))
        empty_benign+=int(sub.get('verdict')=='benign' and not sub.get('legitimacy_evidence'))
        state.update(mem)
        # The case's final graph is known; no counterfactual model calls are performed.
        print(f"{str(result.get('task_id',''))[:8]} quality={q!s:<6} "
              f"verdict={sub.get('verdict','?'):<9} "
              f"first_audit_calls={reviewed_at[0] if reviewed_at else '-':<3} "
              f"findings={len(hypotheses):2} benign_gaps={len(gaps)} "
              f"evidence_revision={state.last_revision}")
    print(f"cases={len(cases)} zero_quality={zero} zero_with_high_findings={high_zero} "
          f"audits_before_3_calls={early} empty_benign={empty_benign}; "
          "READ-ONLY DIAGNOSTIC, NOT A PREDICTED SCORE")


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('path',type=Path)
    run(parser.parse_args().path)
