"""Estimate the value of each report factor from Phase M ``random_probe`` runs.

Usage:
    uv run python scripts/analyze_probe.py [--fe template|variant|verdict] runs_phaseM_* ...

--fe chooses the fixed effect: "variant" (template + max reward, least noise but
needs several episodes per variant, i.e. 6+ runs), "template" (default) or
"verdict" (fewest parameters).  Randomization keeps all three unbiased.

Model (OLS with one fixed effect per scenario variant):
    final_reward / max_reward = a[scenario] + sum_f w[f] * count[f]
where f is "role|kind" (malicious) or "role|anchor|fields" (benign) for every
INCLUDED factor of the logged design.  max_reward = total_reward / quality is
constant per scenario variant, so w[f] is directly "quality points per item".

Read the table as: w > 0 with t >= 2.5 -> report this factor;
w < 0 with t <= -2.5 -> never report it; otherwise -> more data needed.
With ~60 factors expect 1-2 false flags at this threshold: confirm a rule with a
fresh run before making it the default.  Simulation on real Phase K/L graphs:
3 runs (90 tasks) are not enough, 6 runs (180 tasks) recover effects >= 0.04 Q.
Pure Python, no numpy needed.
"""
from __future__ import annotations

import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _trajectories import load  # noqa: E402

RIDGE = 1e-6


def _factor_counts(design: dict) -> Counter:
    c: Counter = Counter()
    for f in design.get("factors") or []:
        if not f.get("included"):
            continue
        if design.get("verdict") == "malicious":
            c[f"M {f['role']}|{f['kind']}"] += 1
        else:
            fields = "+".join(f.get("property_fields") or []) or "-"
            c[f"B {f['role']}|{f.get('anchor')}|{fields}"] += 1
    return c


def _solve(xtx: list[list[float]], xty: list[float]) -> tuple[list[float], list[list[float]]]:
    n = len(xtx)
    a = [row[:] + [1.0 if i == j else 0.0 for j in range(n)] for i, row in enumerate(xtx)]
    for i in range(n):
        a[i][i] += RIDGE
    for col in range(n):
        piv = max(range(col, n), key=lambda r: abs(a[r][col]))
        a[col], a[piv] = a[piv], a[col]
        p = a[col][col]
        if abs(p) < 1e-12:
            continue
        a[col] = [v / p for v in a[col]]
        for r in range(n):
            if r != col and a[r][col]:
                k = a[r][col]
                a[r] = [vr - k * vc for vr, vc in zip(a[r], a[col], strict=True)]
    inv = [row[n:] for row in a]
    beta = [sum(inv[i][j] * xty[j] for j in range(n)) for i in range(n)]
    return beta, inv


def main(argv: list[str]) -> None:
    fe = "template"
    if argv[:1] == ["--fe"]:
        fe, argv = argv[1], argv[2:]
    paths = argv or ["runs"]
    eps = [e for e in load(paths) if e["design"] and e["max"] and e["final_reward"] is not None]
    if not eps:
        sys.exit("no random_probe trajectories with a positive quality found")
    rows = []
    for e in eps:
        verdict = e["design"].get("verdict")
        group = {"variant": f"{e['template']}@{e['max']}|{verdict}",
                 "template": f"{e['template']}|{verdict}",
                 "verdict": str(verdict)}[fe]
        rows.append((group, _factor_counts(e["design"]), e["final_reward"] / e["max"]))
    groups = sorted({g for g, _, _ in rows})
    feats = sorted({f for _, c, _ in rows for f in c})
    cols = groups + feats
    idx = {c: i for i, c in enumerate(cols)}
    p = len(cols)
    xtx = [[0.0] * p for _ in range(p)]
    xty = [0.0] * p
    xs = []
    for g, c, y in rows:
        x = defaultdict(float)
        x[idx[g]] = 1.0
        for f, v in c.items():
            x[idx[f]] = float(v)
        xs.append((x, y))
        for i, vi in x.items():
            xty[i] += vi * y
            for j, vj in x.items():
                xtx[i][j] += vi * vj
    beta, inv = _solve(xtx, xty)
    resid = [y - sum(beta[i] * v for i, v in x.items()) for x, y in xs]
    dof = max(1, len(rows) - p)
    sigma2 = sum(r * r for r in resid) / dof
    print(f"fixed effect={fe} episodes={len(rows)} groups={len(groups)} factors={len(feats)} "
          f"residual sd={math.sqrt(sigma2):.4f} (quality units)")
    print(f"{'factor':58s} {'n':>4s} {'w(Q/item)':>10s} {'se':>7s} {'t':>6s}  verdict")
    support = Counter()
    for _, c, _ in rows:
        for f, v in c.items():
            support[f] += v
    out = []
    for f in feats:
        i = idx[f]
        se = math.sqrt(max(inv[i][i] * sigma2, 0.0))
        t = beta[i] / se if se > 0 else float("inf")
        verdict = "REPORT" if beta[i] > 0 and t >= 2.5 else ("AVOID" if beta[i] < 0 and t <= -2.5
                                                           else "?")
        out.append((beta[i], f, support[f], se, t, verdict))
    for w, f, n, se, t, verdict in sorted(out, reverse=True):
        print(f"{f:58s} {n:4d} {w:10.4f} {se:7.4f} {t:6.1f}  {verdict}")


if __name__ == "__main__":
    main(sys.argv[1:])
