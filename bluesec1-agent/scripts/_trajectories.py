"""Shared offline loader for saved trajectories (directories or ZIP archives).

Practice diagnostics only: the per-call ``runtime_reward`` saved in audits is read
here, offline, after the run.  Nothing in this module is imported by the agent.
"""
from __future__ import annotations

import contextlib
import json
import re
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def iter_raw(paths: list[str]) -> Iterator[tuple[str, dict[str, Any]]]:
    for raw in paths:
        path = Path(raw)
        if path.is_file() and path.suffix.lower() == ".zip":
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    norm = name.replace("\\", "/")
                    if norm.endswith(".json") and "/in_progress/" not in norm:
                        try:
                            yield f"{path.name}:{norm}", json.loads(zf.read(name))
                        except ValueError:
                            continue
        elif path.is_dir():
            for file in sorted(path.rglob("*.json")):
                if "in_progress" in file.parts:
                    continue
                try:
                    yield str(file), json.loads(file.read_text(encoding="utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
        else:
            print(f"skip {raw}: not a directory or .zip", file=sys.stderr)


def _walk(obj: Any, acc: dict[str, dict[str, Any]]) -> None:
    if isinstance(obj, dict):
        if isinstance(obj.get("id"), str) and isinstance(obj.get("type"), str) and (
                "properties" in obj or "source_id" in obj):
            acc.setdefault(obj["id"], obj)
        for value in obj.values():
            _walk(value, acc)
    elif isinstance(obj, list):
        for value in obj:
            _walk(value, acc)


def _base(path: str) -> str:
    name = str(path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return re.sub(r"\d+", "#", name)


def describe(entity: dict[str, Any] | None) -> str:
    if not entity:
        return "?"
    p = entity.get("properties") or {}
    name = (p.get("image_path") or p.get("path") or p.get("hostname") or p.get("username")
            or p.get("name") or p.get("task_name") or p.get("service_name") or "")
    return f"{entity.get('type')}:{_base(name)}"


def load(paths: list[str]) -> list[dict[str, Any]]:
    """One record per finished episode."""
    episodes = []
    for source, data in iter_raw(paths):
        if not isinstance(data, dict) or "task_result" not in data:
            continue
        msgs = data.get("messages") or []
        result = data["task_result"] or {}
        try:
            first_user = next(m for m in msgs if m.get("role") == "user")
            observation = json.loads(first_user["content"])["initial_observation"]
        except (StopIteration, ValueError, KeyError, TypeError):
            continue
        alert = observation.get("alert_text") or {}
        image = parent = ""
        for trig in alert.get("trigger_entities") or []:
            props = trig.get("properties") or {}
            if "image_path" in props:
                image, parent = props.get("image_path", ""), props.get("parent_image", "")
        if not image:
            m = re.search(r"Process (.+?) \(PID", str(alert.get("alert_description", "")))
            image = m.group(1) if m else "?"
        seen: dict[str, dict[str, Any]] = {}
        _walk(alert, seen)
        trigger_ids = {t.get("id") for t in alert.get("trigger_entities") or []}
        calls, final, final_reward, design, explore = [], None, None, None, None
        benign_design = None
        graph: dict[str, dict[str, Any]] = dict(seen)
        for i, msg in enumerate(msgs):
            content = msg.get("content")
            if msg.get("role") == "assistant":
                for tc in msg.get("tool_calls") or []:
                    if tc.get("function", {}).get("name") == "finish_investigation":
                        with contextlib.suppress(ValueError, KeyError, TypeError):
                            final = json.loads(tc["function"]["arguments"])["submission"]
            if not isinstance(content, str):
                continue
            try:
                obj = json.loads(content)
            except ValueError:
                continue
            _walk(obj, graph)
            if msg.get("role") != "audit" or not isinstance(obj, dict):
                continue
            if "report_after" in obj:
                final = obj["report_after"]
            if "probe_design" in obj:
                design = obj["probe_design"]
            if "explore_design" in obj:
                explore = obj["explore_design"]
            if "benign_probe_design" in obj:
                benign_design = obj["benign_probe_design"]
            if "runtime_info_keys" in obj:
                final_reward = obj.get("runtime_reward")
            elif "runtime_reward" in obj:
                if "result" in obj:
                    tool, res = obj.get("tool"), obj.get("result")
                elif "v25_scope_call" in obj:
                    tool = obj["v25_scope_call"].get("tool")
                    nxt = msgs[i + 1] if i + 1 < len(msgs) else {}
                    try:
                        res = json.loads(nxt.get("content", "")).get("result")
                    except (ValueError, AttributeError):
                        res = None
                else:
                    continue
                found: dict[str, dict[str, Any]] = {}
                _walk(res, found)
                new = [k for k in found if k not in seen]
                seen.update(found)
                calls.append({"tool": tool, "reward": obj["runtime_reward"],
                              "category": obj.get("explore_category"),
                              "first": list(found)[:1], "new": new})
        q, e = result.get("quality_score") or 0.0, result.get("efficiency_score") or 0.0
        total = result.get("total_reward")
        episodes.append({
            "source": source, "task": result.get("task_id"), "q": q, "e": e,
            "total": total, "steps": result.get("steps_taken"),
            "template": f"{_base(image)} <- {_base(parent) or '-'}",
            "max": round(total / q, 1) if q and total else None,
            "final": final or {}, "final_reward": final_reward, "calls": calls,
            "graph": graph, "trigger_ids": trigger_ids, "design": design, "explore": explore,
            "benign_design": benign_design,
        })
    return episodes
