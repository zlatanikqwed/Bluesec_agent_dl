"""Phase N: does opening more objects (thoroughness) raise the score?

Usage:
    uv run python scripts/analyze_explore.py [--fe variant|template] runs_phaseN_* ...

Each ``explore_probe`` task opened a random subset of unopened relation endpoints
right before finish (report fixed).  Three regressions with scenario fixed effects:
  final/max  ~ opened[category]   -> value of OBSERVING an object for the finish reward
  total/max  (= Q)                -> including the per-call rewards
  Q x E                           -> what the leaderboard actually sums
w is per opened object.  A category is worth a call when w(QxE) > 0 with t >= 2.5.
"""
from __future__ import annotations

import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _trajectories import load  # noqa: E402
from analyze_probe import _solve  # noqa: E402


def _fit(rows: list[tuple[str, Counter, float]]) -> dict[str, tuple[float, float, int]]:
    groups = sorted({g for g, _, _ in rows})
    feats = sorted({f for _, c, _ in rows for f in c})
    idx = {c: i for i, c in enumerate(groups + feats)}
    p = len(idx)
    xtx = [[0.0] * p for _ in range(p)]
    xty = [0.0] * p
    xs = []
    for g, c, y in rows:
        x = {idx[g]: 1.0}
        x.update({idx[f]: float(v) for f, v in c.items()})
        xs.append((x, y))
        for i, vi in x.items():
            xty[i] += vi * y
            for j, vj in x.items():
                xtx[i][j] += vi * vj
    beta, inv = _solve(xtx, xty)
    resid = [y - sum(beta[i] * v for i, v in x.items()) for x, y in xs]
    s2 = sum(r * r for r in resid) / max(1, len(rows) - p)
    support = Counter()
    for _, c, _ in rows:
        support.update(c)
    return {f: (beta[idx[f]], math.sqrt(max(inv[idx[f]][idx[f]] * s2, 0.0)), support[f])
            for f in feats}


def main(argv: list[str]) -> None:
    fe = "variant"
    if argv[:1] == ["--fe"]:
        fe, argv = argv[1], argv[2:]
    eps = [e for e in load(argv or ["runs"])
           if e["explore"] and e["max"] and e["final_reward"] is not None]
    if not eps:
        sys.exit("no explore_probe trajectories with a positive quality found")
    targets = {"final/max": [], "Q": [], "QxE": []}
    hit = defaultdict(lambda: [0, 0])
    for e in eps:
        verdict = e["final"].get("verdict")
        g = f"{e['template']}@{e['max']}|{verdict}" if fe == "variant" else \
            f"{e['template']}|{verdict}"
        opened = Counter({c["category"]: c.get("opened", 0)
                          for c in e["explore"]["categories"] if c.get("opened")})
        expanded = sum(1 for x in e["explore"].get("expand") or [] if x.get("enabled"))
        if expanded:
            opened["expand_child"] = expanded
        targets["final/max"].append((g, opened, e["final_reward"] / e["max"]))
        targets["Q"].append((g, opened, e["q"]))
        targets["QxE"].append((g, opened, e["q"] * e["e"]))
        for c in e["calls"]:
            if c.get("category"):
                hit[c["category"]][0] += 1
                hit[c["category"]][1] += c["reward"] > 0
    print(f"episodes={len(eps)} fixed effect={fe}")
    print("\nper-call reward rate of explore calls (offline label of 'key object'):")
    for cat, (n, pos) in sorted(hit.items(), key=lambda kv: -kv[1][0]):
        print(f"  {cat:15s} calls={n:4d} rewarded={pos:4d} ({100 * pos / n:3.0f}%)")
    fits = {name: _fit(rows) for name, rows in targets.items()}
    cats = sorted({f for fit in fits.values() for f in fit})
    print(f"\n{'category':15s} {'n':>4s} | " + " | ".join(f"{t:>20s}" for t in targets))
    for cat in cats:
        cells = []
        for name in targets:
            w, se, n = fits[name].get(cat, (0.0, 0.0, 0))
            t = w / se if se else 0.0
            cells.append(f"{w:+.4f} (t={t:+5.1f})")
        n = fits["Q"].get(cat, (0, 0, 0))[2]
        print(f"{cat:15s} {n:4d} | " + " | ".join(f"{c:>20s}" for c in cells))


if __name__ == "__main__":
    main(sys.argv[1:])
