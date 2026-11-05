"""Read local trajectory JSON files and print scorer results plus suspicious loops.

Does not infer the true verdict and does not contain prepared scenario answers.
Usage: python scripts/analyze_trajectories.py runs/<run_id>
   or: python scripts/analyze_trajectories.py exported-run.zip
"""
import argparse
import collections
import json
import statistics
from pathlib import Path
from zipfile import ZipFile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    records = []
    if args.folder.is_file() and args.folder.suffix.lower() == ".zip":
        with ZipFile(args.folder) as archive:
            payloads = [(Path(name).stem, archive.read(name).decode("utf-8"))
                        for name in archive.namelist() if name.endswith(".json")]
    else:
        payloads = [(path.stem, path.read_text(encoding="utf-8"))
                    for path in sorted(args.folder.rglob("*.json"))]
    for task_id, content in payloads:
        try:
            obj = json.loads(content)
        except (ValueError, OSError):
            continue
        result = obj.get("task_result")
        if not isinstance(result, dict):
            continue
        messages = obj.get("messages", [])
        tool_names = []
        arguments = []
        for m in messages:
            for tool_call in m.get("tool_calls", []):
                function = tool_call.get("function", {})
                tool_names.append(function.get("name"))
                if function.get("name") != "finish_investigation":
                    try:
                        arg = json.loads(function.get("arguments", "{}"))
                    except ValueError:
                        arg = {}
                    arg.pop("reasoning", None)
                    arguments.append((function.get("name"), json.dumps(arg, sort_keys=True)))
        duplicates = sum(max(0, count - 1) for count in collections.Counter(arguments).values())
        final = {}
        for m in reversed(messages):
            for tc in m.get("tool_calls", []):
                f = tc.get("function", {})
                if f.get("name") == "finish_investigation":
                    try:
                        final = json.loads(f.get("arguments", "{}"))
                    except ValueError:
                        pass
                    break
            if final:
                break
        sub = final.get("submission", {})
        audit_events = []
        for m in messages:
            if m.get("role") != "audit":
                continue
            try:
                payload = json.loads(m.get("content") or "{}")
            except (ValueError, TypeError):
                continue
            if isinstance(payload, dict):
                audit_events.append(payload)
        records.append({
            "task": result.get("task_id", task_id)[:8],
            "reward": float(result.get("total_reward") or 0),
            "quality": float(result.get("quality_score") or 0),
            "efficiency": float(result.get("efficiency_score") or 0),
            "audit": sum("proposed_submission" in x and "blind_review" in x
                         for x in audit_events),
            "evidence_gate": sum("evidence_gate" in x or "v16_evidence_gate" in x
                                 for x in audit_events),
            "arbitration": sum("arbitration" in x or "consequence_arbitration" in x
                               or "v16_fact_tiebreak" in x for x in audit_events),
            "v16_checks": sum("v16_fact_check" in x for x in audit_events),
            "v19_acquisition": sum("v19_acquisition" in x for x in audit_events),
            "v19_gaps": sum("v19_benign_gaps" in x for x in audit_events),
            "v20_acquire": sum("v20_phase" in x and "v19_acquisition" in x
                                for x in audit_events),
            "v20_decisions": sum(x.get("v20_phase") == "DECIDE" for x in audit_events),
            "v20_reviews": sum(x.get("v20_phase") == "VERIFY" for x in audit_events),
            "v20_fresh": sum(x.get("v20_phase") == "SUBMIT" and x.get("review_current")
                             for x in audit_events),
            "v21_risk_steps": sum("v21_risk_tier" in x for x in audit_events),
            "v21_corroborations": sum("v21_corroborated_execution" in x for x in audit_events),
            "verdict": sub.get("verdict", "?"),
            "calls": int(result.get("tool_calls") or 0),
            "duplicates": duplicates,
            "artifacts": len(sub.get("ir_artifacts", [])),
            "evidence": len(sub.get("legitimacy_evidence", [])),
        })
    if not records:
        parser.error("No completed trajectories found")
    for r in sorted(records, key=lambda x: x["reward"]):
        print(f"{r['task']:8} {r['reward']:7.1f} quality={r['quality']:.2f} "
              f"eff={r['efficiency']:.2f} {r['verdict']:9} calls={r['calls']:2} "
              f"duplicates={r['duplicates']:2} artifacts={r['artifacts']:2} "
              f"evidence={r['evidence']:2}")
    print(f"Completed cases: {len(records)}, mean reward: "
          f"{statistics.mean(r['reward'] for r in records):.2f}, "
          f"mean quality: {statistics.mean(r['quality'] for r in records):.3f}, "
          f"duplicate requests: {sum(r['duplicates'] for r in records)}")
    print(f"sum(quality × efficiency) = "
          f"{sum(r['quality'] * r['efficiency'] for r in records):.8f}; "
          f"independent audits = {sum(r['audit'] for r in records)}; "
          f"evidence gates = {sum(r['evidence_gate'] for r in records)}; "
          f"arbitrations = {sum(r['arbitration'] for r in records)}; "
          f"v16 fact checks = {sum(r['v16_checks'] for r in records)}; "
          f"v19 deterministic acquisitions = {sum(r['v19_acquisition'] for r in records)}; "
          f"v19 benign challenges = {sum(r['v19_gaps'] for r in records)}; "
          f"v20 acquisitions = {sum(r['v20_acquire'] for r in records)}; "
          f"v20 decisions = {sum(r['v20_decisions'] for r in records)}; "
          f"v20 reviews = {sum(r['v20_reviews'] for r in records)}; "
          f"v20 fresh-at-submit = {sum(r['v20_fresh'] for r in records)}; "
          f"v21 risk-adjusted acquisitions = {sum(r['v21_risk_steps'] for r in records)}; "
          f"v21 corroborated memory-execution verdicts = {sum(r['v21_corroborations'] for r in records)}")
    print("Note: mean task reward is NOT necessarily the leaderboard score.")


if __name__ == "__main__":
    main()
