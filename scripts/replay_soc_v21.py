"""Read-only V21 forensic report for existing trajectories; NO counterfactual score."""
from __future__ import annotations

import argparse
from pathlib import Path
from replay_soc_v20 import load
from replay_soc_v18 import case_memory
from bluesec1_agent.soc_v19 import SOCV19
from bluesec1_agent.soc_v21 import RiskAdaptiveCaseState, corroborated_submission
from bluesec1_agent.investigation_director import InvestigationDirector


def run(path: Path) -> None:
    cases = load(path)
    zeros = 0
    zero_corroborated = 0
    all_corroborated = 0
    for data in cases:
        memory, sub = case_memory(data)
        result = data.get('task_result') or {}
        state = RiskAdaptiveCaseState(SOCV19(InvestigationDirector()))
        profile = state.risk_profile(memory)
        found = state.engine.findings(memory)
        gaps = state.engine.benign_gaps(memory, sub)
        check = corroborated_submission(memory, state.engine, sub)
        is_zero = float(result.get('quality_score') or 0) == 0
        zeros += is_zero
        zero_corroborated += bool(check) and is_zero
        all_corroborated += bool(check)
        print(f"{str(result.get('task_id',''))[:8]} "
              f"Q={float(result.get('quality_score') or 0):.2f} "
              f"verdict={str(sub.get('verdict')):<9} "
              f"risk={profile.tier:<11} suggested_min={profile.minimum:2} "
              f"findings={len(found):2} gaps={len(gaps):2} "
              f"confirmed_execution_contradiction={bool(check)}")
    print(f"cases={len(cases)} zero_quality={zeros} "
          f"zero_with_confirmed_execution={zero_corroborated} "
          f"confirmed_execution_total={all_corroborated}. "
          "READ-ONLY: no simulated model decisions, tool calls or scores.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=Path)
    run(parser.parse_args().path)
