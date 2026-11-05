import json
from types import SimpleNamespace
from typing import Any, cast

from bluesec1_agent.agent import SimpleSGRAgent
from bluesec1_agent.models import (
    NextStep,
)
from bluesec1_client import (
    PublicTask,
    RemoteBenchmarkSession,
    TaskResult,
    ToolCallResult,
)


class FakeStepClient:
    """Deterministic structured steps used by the agent unit test."""

    def __init__(self, steps: list[NextStep]) -> None:
        """Store steps in their expected request order.

        Args:
            steps: Prepared LLM steps.
        """
        self.steps = list(steps)
        self.requests: list[list[dict[str, Any]]] = []
        self.finish_only_flags: list[bool] = []

    async def next_step(
        self, messages: list[dict[str, Any]], *, finish_only: bool = False
    ) -> NextStep:
        """Record one conversation and return its next prepared step.

        Args:
            messages: Current LLM history.

        Returns:
            Next prepared structured step.
        """
        self.requests.append([dict(message) for message in messages])
        self.finish_only_flags.append(finish_only)
        return self.steps.pop(0)


class FakeSession:
    """In-memory remote session used by the structured agent test."""

    def __init__(self) -> None:
        """Create a task with a JSON-encoded remote tool catalog."""
        self.task = PublicTask(
            task_id="task-1",
            observation={
                "alert_text": {"trigger_entities": [{"id": "entity-1", "type": "host"}]},
                "available_tools": json.dumps(
                    [
                        {"name": "get_entity", "parameters": {"type": "object"}},
                        {"name": "finish_investigation", "parameters": {"type": "object"}},
                    ]
                ),
            },
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @property
    def task_id(self) -> str:
        """Return the public task identifier.

        Returns:
            Task identifier.
        """
        return self.task.task_id

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ToolCallResult:
        """Record one call and terminate on the finishing tool.

        Args:
            tool_name: Invoked tool name.
            arguments: Invoked tool arguments.

        Returns:
            Fake server response.
        """
        self.calls.append((tool_name, arguments))
        terminal = tool_name == "finish_investigation"
        task_result = None
        if terminal:
            task_result = TaskResult(
                task_id="task-1",
                completion_reason="terminated",
            )
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            reward=1.0,
            terminated=terminal,
            info={
                "tool_status": "ok",
                "tool_result": (
                    [{"entity_id": "process-1", "pid": 42, "host_id": "host-1"}]
                    if not terminal
                    else "Report accepted"
                ),
            },
            task_result=task_result,
        )

    async def abort_task(self, *, error_message: str | None = None) -> TaskResult:
        """Reject unexpected aborts.

        Args:
            error_message: Agent failure diagnostic.

        Raises:
            AssertionError: Always, because this task must finish normally.
        """
        raise AssertionError(f"Unexpected abort: {error_message}")


class FakeClient:
    """Single-task stand-in for an open RemoteBenchmarkClient."""

    def __init__(self, session: FakeSession) -> None:
        """Store the only session returned before queue exhaustion.

        Args:
            session: Prepared task session.
        """
        self.run = SimpleNamespace(run_id="run-1")
        self.session: FakeSession | None = session

    async def start_task(self) -> RemoteBenchmarkSession | None:
        """Lease the prepared session once.

        Returns:
            Prepared session or `None` after it was leased.
        """
        if self.session is None:
            return None
        session = self.session
        self.session = None
        return cast(RemoteBenchmarkSession, session)


def test_tool_feedback_extracts_last_tool_result_from_observation() -> None:
    """The runtime puts the call result into observation.last_tool_result."""
    response = ToolCallResult(
        task_id="task-1",
        tool_name="get_entity",
        observation={
            "alert_text": "huge alert",
            "available_tools": "huge catalog",
            "last_tool_result": json.dumps(
                {"id": "f-1", "type": "windows_file", "properties": {"path": "a.bin", "x": None}}
            ),
        },
        info={"tool_status": "ok"},
    )
    feedback = SimpleSGRAgent._tool_feedback(response)
    assert feedback["result"] == {
        "id": "f-1",
        "type": "windows_file",
        "properties": {"path": "a.bin"},
    }
    assert "available_tools" not in json.dumps(feedback)


def test_decode_encoded_powershell_command() -> None:
    """-EncodedCommand payloads are decoded next to the original field."""
    import base64

    from bluesec1_agent.agent import decode_encoded_commands

    blob = base64.b64encode("Start-Process k.exe".encode("utf-16-le")).decode()
    out = decode_encoded_commands({"cmdline": f"powershell.exe -NonInteractive -enc {blob}"})
    assert out["cmdline_decoded"] == "Start-Process k.exe"


def test_get_entity_on_relation_id_is_routed_to_get_relation() -> None:
    """Relation ids returned in relation_ids are opened with get_relation."""
    from bluesec1_agent.agent import InvestigationMemory

    memory = InvestigationMemory()
    memory.absorb(
        {
            "id": "p-1",
            "type": "windows_process",
            "relation_ids": {"outgoing": ["r-1"]},
        }
    )
    tool, args, note = SimpleSGRAgent._route(
        "get_entity",
        {"entity_id": "r-1", "reasoning": "x"},
        memory,
        {"get_entity", "get_relation"},
    )
    assert tool == "get_relation" and args["relation_id"] == "r-1" and note
    assert "RELATION" in memory.describe("r-1")


def test_host_relations_are_hidden_from_frontier() -> None:
    """Hosts link to everything, so their relations are not suggested."""
    from bluesec1_agent.agent import InvestigationMemory

    memory = InvestigationMemory()
    memory.absorb({"id": "h-1", "type": "host", "relation_ids": {"outgoing": ["r-h"]}})
    memory.absorb({"id": "p-1", "type": "windows_process", "relation_ids": {"incoming": ["r-p"]}})
    assert "r-h" not in memory.frontier() and "r-p" in memory.frontier()


def test_base64_in_cmd_is_decoded() -> None:
    """A base64 blob inside a cmd /c ... FromBase64String call is decoded."""
    import base64

    from bluesec1_agent.agent import decode_encoded_commands

    inner = base64.b64encode("IEX(New-Object Net.WebClient)".encode("utf-16-le")).decode()
    out = decode_encoded_commands({"cmdline": f"cmd /c ...FromBase64String('{inner}')"})
    assert out["cmdline_decoded"] == "IEX(New-Object Net.WebClient)"


def test_incident_classifier_routes_attack_patterns_first() -> None:
    """Attack indicators win over the generic admin pattern."""
    from bluesec1_agent.agent import classify_incident

    assert classify_incident("powershell.exe vssadmin delete shadows") == "ransomware"
    assert classify_incident("powershell -enc AAAA DownloadString") == "encoded_exec"
    assert classify_incident("procdump lsass.dmp") == "credential_theft"
    # a bare signed admin tool with no indicators falls to admin_activity
    assert (
        classify_incident("C:/Windows/System32/WindowsPowerShell/powershell.exe sysvol")
        == "admin_activity"
    )
    assert classify_incident("C:/Users/Public/runtime.exe") == "suspicious_binary"


def test_playbook_injected_into_context() -> None:
    """The matched playbook heads the per-turn context."""
    from bluesec1_agent.agent import PLAYBOOKS, InvestigationMemory

    memory = InvestigationMemory()
    memory.incident_type = "ransomware"
    memory.playbook = PLAYBOOKS["ransomware"]
    memory.absorb({"id": "p-1", "type": "windows_process", "properties": {"x": "y"}})
    text = memory.context_text()
    assert text.startswith("PLAYBOOK — ransomware")
    assert "shadow-copy" in text


def test_external_ip_detection() -> None:
    from bluesec1_agent.agent import _is_external_ip

    assert _is_external_ip("203.0.113.40") is True
    assert _is_external_ip("8.8.8.8") is True
    assert _is_external_ip("192.168.1.10") is False
    assert _is_external_ip("10.0.0.5") is False
    assert _is_external_ip("172.16.4.4") is False
    assert _is_external_ip("127.0.0.1") is False


def test_quiet_process_external_connection_flagged() -> None:
    """A core OS process reaching an external host is flagged by code."""
    from bluesec1_agent.agent import InvestigationMemory

    memory = InvestigationMemory()
    memory.absorb(
        {
            "id": "c-1",
            "type": "network_connection",
            "properties": {
                "image_path": "System",
                "dst_ip": "203.0.113.9",
                "dst_port": "443",
                "direction": "outbound",
            },
        }
    )
    assert any("should never reach external" in k for k in memory.red_flags)


def test_web_server_spawning_shell_flagged() -> None:
    """w3wp spawning cmd is flagged as a probable web shell."""
    from bluesec1_agent.agent import InvestigationMemory

    memory = InvestigationMemory()
    memory.absorb(
        {
            "id": "p-1",
            "type": "windows_process",
            "properties": {"image_path": "C:/Windows/cmd.exe", "parent_image": "w3wp.exe"},
        }
    )
    assert any("web shell" in k for k in memory.red_flags)


