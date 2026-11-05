"""Read-only v22 evidence endpoint diagnostic; does NOT replay a model or grader.

  uv run python scripts/replay_soc_v22.py runs/<RUN_ID>
  uv run python scripts/replay_soc_v22.py run-archive.zip
"""
from __future__ import annotations

import argparse
from pathlib import Path

from replay_soc_v18 import case_memory
from replay_soc_v20 import load
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.soc_v22 import EvidenceFocusedCaseState, SOCV22


def run(path: Path) -> None:
    cases = load(path)
    zeros = 0
    missed = 0
    missed_zero = 0
    for case in cases:
        memory, sub = case_memory(case)
        result = case.get('task_result') or {}
        state = EvidenceFocusedCaseState(SOCV22(InvestigationDirector()))
        seen = [(k, src, dst) for _,(k,src,dst) in memory.graph_edges.items()
                if k.lower() in {'connected_to','accepted_connection_from',
                    'opened_share_session','wrote_file','win_process_create',
                    'executed_script','set_registry_value','created_service'}]
        unopened = [(k, dst) for k,_,dst in seen
                    if dst in memory.known_ids and dst not in memory.fetched_ids
                    and memory.entity_types.get(dst,'') not in {'host','windows_user','linux_user'}]
        next_step = (state.engine._endpoint(memory, {'get_entity', 'get_relation'})
                     or state.engine._temp_execution_pivot(memory, {'search'}))
        tier = state.risk_profile(memory)
        q = float(result.get('quality_score') or 0)
        zero = q == 0
        zeros += zero
        missed += bool(unopened)
        missed_zero += zero and bool(unopened)
        print(f"{str(result.get('task_id',''))[:8]} Q={q:.2f} "
              f"verdict={str(sub.get('verdict','?')):<9} "
              f"unopened_impact_targets={len(unopened):2} "
              f"risk={tier.tier:<11} "
              f"next={next_step.lead.tool if next_step else '-':<10} "
              f"cause={next_step.lead.reason if next_step else '-'}")
    print(f"cases={len(cases)} zero_quality={zeros} "
          f"cases_with_unopened_targets={missed} "
          f"zero_with_unopened_targets={missed_zero}; "
          "READ-ONLY, no hypothetical score or model decisions")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=Path)
    run(parser.parse_args().path)
