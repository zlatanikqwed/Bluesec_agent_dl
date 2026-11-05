"""Offline Practice diagnostics: where the score is lost.

Usage:
    uv run python scripts/analyze_rewards.py runs_phaseL_* runs_phaseK_inbound_guard
    uv run python scripts/analyze_rewards.py path/to/runs.zip

Reads saved trajectories AFTER the run.  Prints:
1. per-template quality ceiling (best Q ever seen) and implied max reward;
2. which opened objects earn a per-call reward, by (entity type, incoming relation);
3. how many rewarded objects were later reported in the final submission;
4. efficiency vs number of steps.
"""
from __future__ import annotations

import statistics as st
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _trajectories import describe, load  # noqa: E402


def main(paths: list[str]) -> None:
    eps = load(paths)
    if not eps:
        sys.exit("no trajectories found")
    n = len(eps)
    print(f"episodes: {n}; mean Q={st.mean(e['q'] for e in eps):.3f} "
          f"mean E={st.mean(e['e'] for e in eps):.3f} "
          f"sum(QxE) per 30 = {30 * st.mean(e['q'] * e['e'] for e in eps):.2f}")

    print("\n== 1. Ceiling per template (Q is deterministic per scenario variant)")
    by_t = defaultdict(list)
    for e in eps:
        by_t[e["template"]].append(e)
    rows = []
    for t, v in by_t.items():
        qs = [x["q"] for x in v]
        rows.append((st.mean(qs), t, len(v), max(qs),
                     sorted({x["max"] for x in v if x["max"]}),
                     Counter(x["final"].get("verdict") for x in v)))
    for mean_q, t, cnt, best, maxes, vd in sorted(rows):
        print(f"  {t:45s} n={cnt:4d} meanQ={mean_q:.2f} bestQ={best:.2f} "
              f"max={maxes[:4]} {dict(vd)}")

    print("\n== 2. Per-call reward rate of get_entity by (type, incoming relation)")
    rate = defaultdict(lambda: [0, 0])
    for e in eps:
        g = e["graph"]
        for c in e["calls"]:
            if c["tool"] != "get_entity" or not c["first"]:
                continue
            eid = c["first"][0]
            ent = g.get(eid) or {}
            inc = sorted({r["type"] for r in g.values() if r.get("target_id") == eid})
            key = f"{ent.get('type')} <- {'|'.join(inc[:2]) or '-'}"
            rate[key][0] += 1
            rate[key][1] += c["reward"] > 0
    for key, (cnt, pos) in sorted(rate.items(), key=lambda kv: -kv[1][0]):
        if cnt >= 5:
            print(f"  {key:60s} opened={cnt:4d} rewarded={pos:4d} ({100 * pos / cnt:3.0f}%)")

    print("\n== 3. Rewarded (key) objects vs final report (get_entity calls only: unambiguous)")
    found = reported = 0
    missed = Counter()
    for e in eps:
        keys = {k for c in e["calls"] if c["reward"] > 0 and c["tool"] == "get_entity"
                for k in c["first"]}
        f = e["final"]
        ids = {a.get("entity_id") for a in f.get("ir_artifacts") or []}
        ids |= {x.get("entity_id") or x.get("relation_id")
                for x in f.get("legitimacy_evidence") or []}
        found += len(keys)
        reported += len(keys & ids)
        for k in keys - ids:
            missed[describe(e["graph"].get(k))] += 1
    print(f"  key objects first seen in rewarded calls: {found}; reported: {reported}")
    print("  most often NOT reported:", missed.most_common(12))
    zero = sum(1 for e in eps if not any(c["reward"] > 0 for c in e["calls"]))
    print(f"  episodes without any rewarded call: {zero}/{n}")

    print("\n== 4. Efficiency vs steps")
    by_s = defaultdict(list)
    for e in eps:
        if e["steps"] is not None:
            by_s[e["steps"]].append(e["e"])
    for s in sorted(by_s):
        v = by_s[s]
        print(f"  steps={s:3d} n={len(v):4d} meanE={st.mean(v):.3f} minE={min(v):.3f}")


if __name__ == "__main__":
    main(sys.argv[1:] or ["runs"])
