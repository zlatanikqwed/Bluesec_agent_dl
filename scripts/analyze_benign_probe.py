"""Phase O: which single legitimacy citation raises benign quality?

Usage:
    uv run python scripts/analyze_benign_probe.py runs_phaseO_1 runs_phaseO_2 ...

For every benign task the probe cited nothing (CONTROL) or exactly one
(anchor, field).  y = final_reward / max_reward; the scenario variant is a fixed
effect and CONTROL is the reference, so w is "Q gained by this one citation
versus citing nothing".  A real hit shows up as a large jump (+0.1 .. +0.5),
far above the +-0.02 noise of identical reports.
"""
from __future__ import annotations

import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _trajectories import load  # noqa: E402
from analyze_probe import _solve  # noqa: E402


def _fit(rows: list[tuple[str, str, float]], level) -> list[tuple]:
    groups = sorted({g for g, _, _ in rows})
    feats = sorted({level(f) for _, f, _ in rows if f != "CONTROL"})
    idx = {c: i for i, c in enumerate(groups + feats)}
    p = len(idx)
    xtx = [[0.0] * p for _ in range(p)]
    xty = [0.0] * p
    xs = []
    for g, f, y in rows:
        x = {idx[g]: 1.0}
        if f != "CONTROL":
            x[idx[level(f)]] = 1.0
        xs.append((x, y))
        for i, vi in x.items():
            xty[i] += vi * y
            for j, vj in x.items():
                xtx[i][j] += vi * vj
    beta, inv = _solve(xtx, xty)
    res = [y - sum(beta[i] * v for i, v in x.items()) for x, y in xs]
    s2 = sum(r * r for r in res) / max(1, len(rows) - p)
    n = Counter(level(f) for _, f, _ in rows if f != "CONTROL")
    out = []
    for f in feats:
        se = math.sqrt(max(inv[idx[f]][idx[f]] * s2, 1e-12))
        out.append((beta[idx[f]], f, n[f], se, beta[idx[f]] / se))
    return sorted(out, reverse=True)


def main(paths: list[str]) -> None:
    rows, best = [], defaultdict(list)
    for e in load(paths or ["runs"]):
        if e["final"].get("verdict") != "benign" or not e["max"] or e["final_reward"] is None:
            continue
        d = e.get("benign_design")
        if not d:
            continue
        g = f"{e['template']}@{e['max']}"
        y = e["final_reward"] / e["max"]
        rows.append((g, d["factor"], y))
        best[g].append((y, d["factor"]))
    if not rows:
        sys.exit("no benign_probe trajectories found")
    controls = sum(1 for _, f, _ in rows if f == "CONTROL")
    print(f"benign tasks={len(rows)} controls={controls} variants={len(best)}")
    print("\n== per variant: CONTROL vs best single citation")
    for g, v in sorted(best.items()):
        ctrl = [y for y, f in v if f == "CONTROL"]
        top = max(v)
        ref = f"{sum(ctrl) / len(ctrl):.3f}" if ctrl else "  n/a"
        print(f"  {g:45s} n={len(v):2d} control={ref} best={top[0]:.3f} <- {top[1]}")
    for title, level in (("category (role:type)", lambda f: f.split("|")[0]),
                         ("category|field", lambda f: f)):
        print(f"\n== {title}: Q vs CONTROL")
        for w, f, n, se, t in _fit(rows, level):
            flag = "  <== HIT" if w > 0.08 and t >= 2.5 else ""
            print(f"  {f:70s} n={n:3d} w={w:+.3f} se={se:.3f} t={t:+.1f}{flag}")


if __name__ == "__main__":
    main(sys.argv[1:])
