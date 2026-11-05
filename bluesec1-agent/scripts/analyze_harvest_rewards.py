#!/usr/bin/env python3
"""Offline only: summarize per-tool Harvest reward from saved trajectories.

Usage:
    python scripts/analyze_harvest_rewards.py runs/<run-id>
    python scripts/analyze_harvest_rewards.py runs

This analysis intentionally never runs inside the investigation agent.
No evaluator-only field or reward is passed to the model or used for search.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path, help='run directory or trajectory JSON file')
    args = parser.parse_args()
    paths = [args.path] if args.path.is_file() else list(args.path.rglob('*.json'))
    # Finished trajectories are also copied to runs/in_progress. Avoid double
    # counting them when the whole `runs` root is supplied.
    final_ids = {x.stem for x in paths if 'in_progress' not in x.parts}
    paths = [x for x in paths if 'in_progress' not in x.parts or x.stem not in final_ids]
    by_type: dict[str, list[float]] = defaultdict(list)
    file_count = 0
    skipped_rewards = 0
    for path in sorted(paths):
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        events = []
        for entry in data.get('messages', []):
            if entry.get('role') != 'audit':
                continue
            try:
                event = json.loads(entry.get('content', '{}'))
            except (TypeError, ValueError):
                continue
            if event.get('phase') == 'evidence_harvest':
                events.append(event)
        if not events:
            continue
        file_count += 1
        for event in events:
            reward = event.get('runtime_reward')
            if isinstance(reward, bool) or not isinstance(reward, (int, float)):
                skipped_rewards += 1
                continue
            category = str(event.get('harvest_category') or 'other')
            by_type[category].append(float(reward))
    print(f'Trajectories: {file_count} | Reward observations: '
          f'{sum(len(v) for v in by_type.values())} | Reward missing: {skipped_rewards}')
    print(f'{"Category":<18} {"Calls":>6} {"Positive":>8} {"Reward sum":>12} {"Mean":>10}')
    for category, vals in sorted(by_type.items(), key=lambda kv: -sum(kv[1])):
        print(f'{category:<18} {len(vals):>6} {sum(x > 0 for x in vals):>8} '
              f'{sum(vals):>12.2f} {mean(vals):>10.3f}')


if __name__ == '__main__':
    main()
