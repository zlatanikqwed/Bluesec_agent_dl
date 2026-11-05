"""Read-only offline regression for SOC v18. Does NOT replay API/model decisions.

Usage:
  uv run python scripts/replay_soc_v18.py runs/<run-id>
  uv run python scripts/replay_soc_v18.py run-archive.zip
"""
from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path
from typing import Any

from bluesec1_agent.agent import InvestigationMemory, compact, decode_encoded_commands, parse_json_strings
from bluesec1_agent.investigation_director import InvestigationDirector
from bluesec1_agent.soc_v18 import SOCV18


def case_memory(case: dict[str, Any]) -> tuple[InvestigationMemory, dict[str, Any]]:
    memory = InvestigationMemory()
    messages = case.get('messages') or []
    initial = next((x for x in messages if x.get('role') == 'user'), {})
    try:
        observation = json.loads(initial.get('content') or '{}').get('initial_observation') or {}
    except (TypeError, ValueError, AttributeError):
        observation = {}
    memory.absorb(compact(decode_encoded_commands(parse_json_strings(observation))))
    memory.trigger_ids = set(memory.known_ids)
    alert = observation.get('alert_text') or {}
    memory.focus_ids = {x['id'] for x in alert.get('trigger_entities') or []
                        if isinstance(x, dict) and x.get('id') and
                        x.get('type') not in {'host', 'windows_user', 'linux_user'}}
    submission: dict[str, Any] = {}
    for item in messages:
        if item.get('role') == 'tool':
            try:
                event = json.loads(item.get('content') or '{}')
            except (TypeError, ValueError):
                continue
            if event.get('status') == 'ok':
                payload = event.get('result')
                memory.absorb(payload)
                if isinstance(payload, dict) and isinstance(payload.get('id'), str):
                    memory.fetched_ids.add(payload['id'])
        if item.get('role') == 'assistant' and item.get('tool_calls'):
            for call in item['tool_calls']:
                if call.get('function', {}).get('name') == 'finish_investigation':
                    try:
                        submission = json.loads(call['function']['arguments']).get('submission') or {}
                    except (TypeError, ValueError):
                        continue
    return memory, submission


def run(path: Path) -> None:
    if path.suffix.lower() == '.zip':
        with zipfile.ZipFile(path) as archive:
            cases = [json.loads(archive.read(name)) for name in sorted(archive.namelist())
                     if name.lower().endswith('.json')]
    else:
        cases = [json.loads(f.read_text(encoding='utf-8')) for f in sorted(path.glob('*.json'))]
    soc = SOCV18(InvestigationDirector())
    total_zero = 0
    detected = 0
    for case in cases:
        memory, submission = case_memory(case)
        findings = soc.findings(memory)
        unmet = soc.unmet(memory, submission)
        lead = soc.plan(memory, {'get_entity', 'get_relation', 'get_ad_object_info'})
        result = case.get('task_result') or {}
        zero = result.get('quality_score') == 0
        total_zero += int(zero)
        detected += int(bool(findings) and zero)
        print(f"{str(result.get('task_id',''))[:8]} Q={result.get('quality_score', '?')!s:>6} "
              f"verdict={str(submission.get('verdict','?')):<9} "
              f"techniques={len(findings):2} unexplained={len(unmet):1} "
              f"next={lead.tool if lead else '-':<12} "
              + ','.join(f.name for f in findings[:3]))
    print(f'cases={len(cases)} zero_quality={total_zero} '
          f'zero_with_hypotheses={detected}; OFFLINE DIAGNOSTIC ONLY — no simulated leaderboard score')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=Path)
    args = parser.parse_args()
    run(args.path)
