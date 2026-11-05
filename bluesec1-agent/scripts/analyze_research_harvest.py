#!/usr/bin/env python3
"""Offline report of Practice graph census; never imported by the agent.

Examples:
    python scripts/analyze_research_harvest.py runs
    python scripts/analyze_research_harvest.py runs/<run-id> --out research-report

Writes CSVs for each call, each case, and grouped by executable template.
Uses reward AFTER the episode only and never suggests decisions by entity ID.
"""
from __future__ import annotations

import argparse
import csv
import json
import ntpath
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean


def read_json(path):
    try:
        return json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        return None


def _items(raw):
    if isinstance(raw, list):
        for x in raw:
            yield from _items(x)
    elif isinstance(raw, dict):
        if raw.get('id') and raw.get('type'):
            yield raw
        for key in ('result', 'results', 'entities', 'relations', 'items',
                    'trigger_entities', 'trigger_relations'):
            if key in raw:
                yield from _items(raw[key])


def _alert(messages):
    for x in messages:
        if x.get('role') != 'user':
            continue
        try:
            obs = json.loads(x.get('content', '{}')).get('initial_observation', {})
        except (ValueError, TypeError):
            continue
        a = obs.get('alert_text', {})
        if isinstance(a, str):
            try: a = json.loads(a)
            except ValueError: a = {}
        for e in a.get('trigger_entities', []):
            if e.get('type') == 'windows_process':
                p = e.get('properties', {})
                img = str(p.get('image_path') or '')
                parent = str(p.get('parent_image') or p.get('parent_image_path') or '')
                return (ntpath.basename(img).lower() or 'unknown',
                        ntpath.basename(parent).lower() or 'unknown',
                        str(p.get('cmdline') or '')[:120])
    return ('unknown', 'unknown', '')


def _write(path, rows, fields):
    with path.open('w', encoding='utf-8-sig', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('path', type=Path)
    p.add_argument('--out', type=Path, default=Path('research-report'))
    a = p.parse_args()
    paths = [a.path] if a.path.is_file() else list(a.path.rglob('*.json'))
    final_stems = {p.stem for p in paths if 'in_progress' not in p.parts}
    paths = [p for p in paths if 'in_progress' not in p.parts or p.stem not in final_stems]
    callrows, cases, grouped = [], [], defaultdict(list)
    for path in sorted(paths):
        payload = read_json(path)
        if not isinstance(payload, dict):
            continue
        messages = payload.get('messages') or []
        events = []
        for entry in messages:
            if entry.get('role') != 'audit':
                continue
            try: event = json.loads(entry.get('content') or '{}')
            except (ValueError, TypeError): continue
            if event.get('phase') == 'evidence_harvest':
                events.append(event)
        if not events or not any(str(e.get('arguments', {}).get('reasoning', '')).startswith('research_')
                                  for e in events):
            continue
        image, parent, cmd = _alert(messages)
        template = image + ' <- ' + parent
        task = str(path.stem)
        seen = set()
        discovered = Counter()
        rewards = []
        for event in events:
            cat = str(event.get('harvest_category') or 'other')
            new_counts = Counter()
            for item in _items(event.get('result')):
                id_ = str(item['id'])
                if id_ not in seen:
                    seen.add(id_)
                    kind = str(item.get('type') or 'unknown')
                    new_counts[kind] += 1
                    discovered[kind] += 1
            reward = event.get('runtime_reward')
            value = float(reward) if isinstance(reward, (int, float)) and not isinstance(reward, bool) else None
            if value is not None:
                rewards.append(value)
            args = event.get('arguments') or {}
            callrows.append({'case': task, 'template': template, 'cmdline': cmd,
                'call': event.get('harvest_call_index'), 'tool': event.get('tool'),
                'category': cat, 'query': str(args.get('query') or args.get('entity_id') or args.get('relation_id') or ''),
                'scope': str((args.get('scope') or {}).get('type') or ''),
                'reward': value, 'new_entities_by_type': json.dumps(new_counts, sort_keys=True),
                'new_entities_total': sum(new_counts.values())})
        result = payload.get('task_result') or {}
        row = {'case': task, 'template': template, 'cmdline': cmd,
               'harvest_calls': len(events), 'reward_total': sum(rewards),
               'positive_calls': sum(v > 0 for v in rewards),
               'new_objects': sum(discovered.values()),
               'types_found': json.dumps(discovered, sort_keys=True),
               'Q': result.get('quality_score'), 'E': result.get('efficiency_score')}
        cases.append(row)
        grouped[template].append(row)
    summary = []
    for template, rows in sorted(grouped.items()):
        summary.append({'template': template, 'cases': len(rows),
            'mean_harvest_calls': round(mean(r['harvest_calls'] for r in rows), 2),
            'mean_reward': round(mean(r['reward_total'] for r in rows), 2),
            'mean_new_objects': round(mean(r['new_objects'] for r in rows), 2),
            'mean_Q': round(mean(float(r['Q']) for r in rows if r['Q'] is not None), 4)
                      if any(r['Q'] is not None for r in rows) else '',
            'mean_E': round(mean(float(r['E']) for r in rows if r['E'] is not None), 4)
                      if any(r['E'] is not None for r in rows) else ''})
    a.out.mkdir(parents=True, exist_ok=True)
    _write(a.out / 'research_calls.csv', callrows,
           ['case', 'template', 'cmdline', 'call', 'tool', 'category', 'query', 'scope',
            'reward', 'new_entities_by_type', 'new_entities_total'])
    _write(a.out / 'research_cases.csv', cases,
           ['case', 'template', 'cmdline', 'harvest_calls', 'reward_total', 'positive_calls',
            'new_objects', 'types_found', 'Q', 'E'])
    _write(a.out / 'research_templates.csv', summary,
           ['template', 'cases', 'mean_harvest_calls', 'mean_reward', 'mean_new_objects',
            'mean_Q', 'mean_E'])
    cat = defaultdict(list)
    for row in callrows:
        if row['reward'] is not None:
            cat[row['category']].append(row['reward'])
    print(f'Research cases: {len(cases)} | calls: {len(callrows)} | templates: {len(summary)}')
    print(f'{"Category":<27} {"Calls":>6} {"Positive":>9} {"Mean":>7}')
    for name, values in sorted(cat.items(), key=lambda x: -sum(x[1])):
        print(f'{name:<27} {len(values):>6} {sum(x>0 for x in values):>9} {mean(values):>7.3f}')
    print(f'CSV files saved in {a.out}')

if __name__ == '__main__':
    main()
