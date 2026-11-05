import asyncio
import json
import re
import time
from types import TracebackType
from typing import Any, Protocol, Self, cast

from loguru import logger
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletionMessageParam
from openai.types.shared_params import ResponseFormatJSONSchema
from pydantic import ValidationError

from bluesec1_agent.models import (
    FINISH_STEP_RESPONSE_FORMAT,
    NEXT_STEP_RESPONSE_FORMAT,
    InvestigationFunction,
    NextStep,
    tool_signatures,
)
from bluesec1_agent.models import (
    inline_schema_refs as inline_schema_refs_fn,
)

ENVIRONMENT_NOTE = """
Environment facts for this telemetry:
- IP addresses in 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 stand for real
  public internet hosts here. Never dismiss them as "test", "documentation" or
  "not a real server"; treat them exactly like any other external address.
- Uploading an archive or data dump (zip, 7z, rar, tar.gz, split parts .001...)
  to an external host is data exfiltration unless the graph shows an approved
  destination; a signed curl/PowerShell binary or a domain user does not make it benign.
- A process acting as a reverse tunnel or SOCKS client to an external host is malicious.
""".strip()

STRUCTURED_OUTPUT_INSTRUCTION = """
Every assistant reply must be exactly one JSON object with these top-level fields:
{
  "current_state": "short evidence-focused string",
  "plan_remaining_steps_brief": ["one to five short step strings"],
  "task_completed": false,
  "function": {
    "tool": "one advertised tool name",
    "...": "that tool's arguments placed directly in this function object"
  }
}

Never use top-level `action`, `parameters`, `tool_name`, or `arguments` fields.
Never wrap tool arguments in a nested `parameters` or `arguments` object.
For example, a call with one advertised argument is:
{"tool":"advertised_tool","argument_name":"value"}
Set task_completed=true only for a function whose tool is finish_investigation.
Return no prose, markdown, XML, comments, or keys outside the required object.
""".strip()

REPAIR_INSTRUCTION = (
    "Your previous reply violated the required NextStep contract. " + STRUCTURED_OUTPUT_INSTRUCTION
)


_CONTEXT_ERROR_TERMS = (
    "exceed_context_size_error",
    "context_length_exceeded",
    "exceeds the available context size",
    "maximum context length",
    "context window exceeded",
    "prompt is too long",
)


def is_context_overflow(exc: Exception) -> bool:
    """Recognize permanent provider context failures, even when wrapped in Engine 400."""
    message = str(exc).lower()
    return any(phrase in message for phrase in _CONTEXT_ERROR_TERMS)


def context_chars_to_free(exc: Exception) -> int:
    """Calculate a conservative initial reduction from a provider token-limit error."""
    message = str(exc).lower()
    prompt = re.search(r'"n_prompt_tokens"\s*:\s*(\d+)', message)
    capacity = re.search(r'"n_ctx"\s*:\s*(\d+)', message)
    if prompt and capacity:
        extra_tokens = max(0, int(prompt.group(1)) - int(capacity.group(1)))
        return max(2400, 5 * (extra_tokens + 350))
    return 4000


def _keep_edges(content: str, chars_to_free: int) -> str:
    """Omit the middle of an oversized prompt, retaining lead and latest evidence."""
    if not content:
        return content
    marker = "\n[Earlier intermediate text omitted to fit LLM context; do not infer missing facts.]\n"
    saved = min(max(0, chars_to_free), max(0, len(content) - 400))
    if saved <= len(marker):
        return content
    keep = len(content) - saved - len(marker)
    front = max(200, int(keep * 0.60))
    back = keep - front
    if back < 100:
        return content
    return content[:front] + marker + content[-back:]


def compact_overflow_messages(
    messages: list[dict[str, Any]], chars_to_free: int, *, finish_only: bool,
) -> tuple[list[dict[str, Any]], int]:
    """Compact a request copy after an actual overflow; never edit the source history.

    Preserve the system prompt, the alert and the most recent verified case facts.
    First remove redundant finish-only tool catalogues and stale conversational
    text. Only then shorten a large user dossier, keeping its beginning and end.
    """
    result = [dict(msg) for msg in messages]
    before = sum(len(str(m.get("content", ""))) for m in result)
    # The finish-only JSON schema already fixes the tool to finish_investigation.
    # Repeating a full catalogue of navigation tools here is unnecessary.
    if finish_only:
        for i, msg in enumerate(result[1:], start=1):
            if msg.get("role") != "user":
                continue
            content = msg.get("content")
            if not isinstance(content, str) or '"available_tools"' not in content:
                continue
            try:
                data = json.loads(content)
            except (ValueError, TypeError):
                continue
            if not isinstance(data, dict) or "initial_observation" not in data:
                continue
            data.pop("available_tools", None)
            data.pop("step_budget", None)
            result[i]["content"] = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    saved = before - sum(len(str(m.get("content", ""))) for m in result)
    if saved >= chars_to_free:
        return result, saved

    # Stale assistant/tool messages are superseded by the latest case dossier.
    for i in range(2, max(2, len(result) - 1)):
        if saved >= chars_to_free:
            break
        msg = result[i]
        if msg.get("role") not in {"assistant", "tool"}:
            continue
        original = msg.get("content")
        if isinstance(original, str) and len(original) > 250:
            msg["content"] = "[Earlier step omitted; rely on the verified case dossier.]"
            saved += len(original) - len(msg["content"])
    # Preserve the alert (index 1) as long as possible; trim the newest case
    # dossier before the alert because the alert is the causal anchor.
    targets = [i for i in range(2, len(result)) if result[i].get("role") == "user"]
    if len(result) > 1 and result[1].get("role") == "user":
        targets.append(1)
    targets.sort(key=lambda i: (i == 1, -len(str(result[i].get("content", "")))))
    for i in targets:
        if saved >= chars_to_free:
            break
        content = result[i].get("content")
        if not isinstance(content, str):
            continue
        shortened = _keep_edges(content, chars_to_free - saved)
        saved += len(content) - len(shortened)
        result[i]["content"] = shortened
    return result, saved


class NextStepRequestError(RuntimeError):
    """Raised when an LLM cannot produce a valid structured step."""


class StructuredStepClient(Protocol):
    """Narrow async contract consumed by the investigation loop."""

    async def next_step(
        self, messages: list[dict[str, Any]], *, finish_only: bool = False
    ) -> NextStep:
        """Generate and validate one investigation step."""
        ...


class OpenAIStructuredStepClient:
    """Portable structured-output client for OpenAI-compatible providers."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_completion_tokens: int,
        max_retries: int,
        client: AsyncOpenAI | None = None,
        disable_thinking: bool = False,
        inline_schema_refs: bool = False,
        extra_body: dict[str, Any] | None = None,
        http_retries: int = 0,
        min_interval_seconds: float = 0.0,
        response_mode: str = "schema",
    ) -> None:
        """Initialize an OpenAI-compatible structured step generator.

        Args:
            base_url: OpenAI-compatible API root.
            api_key: Provider credential.
            model: Provider model identifier.
            timeout_seconds: Timeout applied to each provider request.
            max_completion_tokens: Maximum generated tokens per attempt.
            max_retries: Maximum schema-generation attempts per step.
            client: Optional injected SDK client used by tests.
        """
        self.model = model
        self.max_completion_tokens = max_completion_tokens
        self.max_retries = max_retries
        self.disable_thinking = disable_thinking
        # Provider-specific request fields, e.g. OpenRouter routing/reasoning options.
        self.extra_body = dict(extra_body or {})
        # Free tiers: pace requests below the provider's RPM and retry 429/5xx with backoff.
        self.min_interval_seconds = max(0.0, min_interval_seconds)
        self._last_request_at = 0.0
        self.response_format = self._prepare(NEXT_STEP_RESPONSE_FORMAT, inline_schema_refs)
        self.finish_response_format = self._prepare(FINISH_STEP_RESPONSE_FORMAT, inline_schema_refs)
        # "schema" = strict json_schema (default); "json_object" or "none" for
        # providers whose reasoning models return empty content under a schema.
        self.response_mode = response_mode if response_mode in ("schema", "json_object", "none") else "schema"
        self._owns_client = client is None
        self._client = client or AsyncOpenAI(
            base_url=base_url,
            api_key=api_key,
            timeout=timeout_seconds,
            max_retries=max(0, http_retries),
        )

    async def __aenter__(self) -> Self:
        """Enter the async LLM client context."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close an internally owned provider client."""
        await self.aclose()

    async def _create_with_recovery(self, **kwargs: Any) -> Any:
        """Retry transient provider/engine failures instead of aborting the task.

        Local servers (e.g. LM Studio) sometimes answer HTTP 400 "Engine ... fetch failed"
        when the backend restarts; hosted providers answer 429/5xx when overloaded.
        """
        delays = (5, 15, 45)
        for attempt in range(len(delays) + 1):
            try:
                return await self._client.chat.completions.create(**kwargs)
            except Exception as exc:  # noqa: BLE001 - classified below
                status = getattr(exc, "status_code", None)
                text = str(exc).lower()
                # Context overflow is permanent until the request changes.
                # "Engine protocol" in the provider envelope does NOT make it
                # transient; next_step owns the bounded compaction/retry.
                if is_context_overflow(exc):
                    raise
                transient = (
                    status in {408, 409, 429, 500, 502, 503, 504}
                    or (status == 400 and ("engine" in text or "fetch failed" in text))
                    or type(exc).__name__ in {"APIConnectionError", "APITimeoutError"}
                )
                if not transient or attempt == len(delays):
                    raise
                logger.warning("Transient LLM error ({}), retry in {}s: {}",
                               status or type(exc).__name__, delays[attempt], str(exc)[:200])
                await asyncio.sleep(delays[attempt])
        raise RuntimeError("unreachable")

    async def aclose(self) -> None:
        """Close the provider transport created by this wrapper."""
        if self._owns_client:
            await self._client.close()

    @staticmethod
    def _prepare(response_format: dict[str, Any], inline: bool) -> dict[str, Any]:
        if not inline:
            return response_format
        json_schema = dict(response_format["json_schema"])
        json_schema["schema"] = inline_schema_refs_fn(json_schema["schema"])
        return {"type": "json_schema", "json_schema": json_schema}

    async def next_step(
        self, messages: list[dict[str, Any]], *, finish_only: bool = False
    ) -> NextStep:
        """Return one valid `NextStep`, repairing malformed replies when possible.

        Args:
            messages: Current investigation conversation.

        Returns:
            A locally validated structured investigation step.

        Raises:
            NextStepRequestError: If every provider reply violates the schema.
        """
        request_messages = list(messages)
        if request_messages and request_messages[0].get("role") == "system":
            first_message = dict(request_messages[0])
            first_message["content"] = (
                f"{first_message.get('content', '')}\n\n{ENVIRONMENT_NOTE}\n\n{STRUCTURED_OUTPUT_INSTRUCTION}"
            )
            if self.disable_thinking:
                first_message["content"] += "\n/no_think"
            request_messages[0] = first_message
        else:
            request_messages.insert(
                0,
                {"role": "system", "content": f"{ENVIRONMENT_NOTE}\n\n{STRUCTURED_OUTPUT_INSTRUCTION}"},
            )
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            # Context overflows are deterministic, not rate-limit failures.
            # Retry at most three smaller, independent copies of this request.
            for context_attempt in range(4):
                wait = self._last_request_at + self.min_interval_seconds - time.monotonic()
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last_request_at = time.monotonic()
                started_at = time.perf_counter()
                try:
                    if self.response_mode == "schema":
                        format_kwargs: dict[str, Any] = {"response_format": cast(
                            ResponseFormatJSONSchema,
                            self.finish_response_format if finish_only else self.response_format,
                        )}
                    elif self.response_mode == "json_object":
                        format_kwargs = {"response_format": {"type": "json_object"}}
                    else:
                        format_kwargs = {}
                    response = await self._create_with_recovery(
                        model=self.model,
                        messages=cast(list[ChatCompletionMessageParam], request_messages),
                        **format_kwargs,
                        max_completion_tokens=self.max_completion_tokens,
                        **({"extra_body": self.extra_body} if self.extra_body else {}),
                    )
                    break
                except Exception as exc:
                    if not is_context_overflow(exc) or context_attempt == 3:
                        raise
                    needed = context_chars_to_free(exc) * (context_attempt + 1)
                    reduced, freed = compact_overflow_messages(
                        request_messages, needed, finish_only=finish_only,
                    )
                    if freed < 200:
                        raise
                    request_messages = reduced
                    logger.warning(
                        "LLM context overflow: compacted {} chars for immediate retry ({}/3).",
                        freed, context_attempt + 1,
                    )
            latency_ms = int((time.perf_counter() - started_at) * 1000)
            raw_content = extract_raw_content(response)
            total_tokens = response_total_tokens(response)

            try:
                step = parse_next_step_payload(raw_content)
            except ValueError as exc:
                last_error = exc
                logger.warning(
                    "Invalid structured LLM response on attempt {}/{}: {}",
                    attempt,
                    self.max_retries,
                    raw_content[:2000] or str(exc),
                )
                if attempt == self.max_retries:
                    break
                request_messages.extend(
                    [
                        {"role": "assistant", "content": raw_content or "<empty>"},
                        {"role": "user", "content": repair_message(raw_content, str(exc))},
                    ]
                )
                continue

            logger.info(
                "LLM selected {} in {} ms using {} tokens.",
                step.function.tool,
                latency_ms,
                total_tokens,
            )
            return step

        message = str(last_error or ValueError("Unable to parse model response."))
        raise NextStepRequestError(message) from last_error


def repair_message(raw_content: str, error: str = "") -> str:
    """Explain the concrete contract violation, including valid tool signatures."""
    hint = f"\nProblem: {error}" if error else ""
    try:
        payload = normalize_step_payload(json.loads(extract_json_object(raw_content)))
        tool = payload.get("function", {}).get("tool")
        hint += f"\nYou used tool {tool!r} with arguments {sorted(payload['function'])}."
    except Exception:
        hint += "\nYour reply was not a parseable JSON object."
    return (
        f"{REPAIR_INSTRUCTION}{hint}\nValid tools and their argument names "
        f"(? = optional):\n{tool_signatures()}"
    )


def extract_message_text(message: Any) -> str:
    """Normalize string and multipart assistant content into plain text.

    Args:
        message: Provider-specific chat completion message.

    Returns:
        Concatenated textual message content.
    """
    content = getattr(message, "content", None)
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""

    text_parts: list[str] = []
    for part in content:
        if isinstance(part, dict) and part.get("type") == "text":
            text_parts.append(str(part.get("text", "")))
        elif getattr(part, "type", None) == "text":
            text_parts.append(str(getattr(part, "text", "")))
    return "".join(text_parts)


def extract_raw_content(response: Any) -> str:
    """Extract the first assistant message from a completion response.

    Args:
        response: OpenAI-compatible chat completion response.

    Returns:
        Raw assistant text.

    Raises:
        ValueError: If the provider response is missing a usable message.
    """
    choices = getattr(response, "choices", None)
    if not choices:
        raise ValueError("Model response is missing choices.")

    message = getattr(choices[0], "message", None)
    if message is None:
        raise ValueError("Model response is missing a message.")

    refusal = getattr(message, "refusal", None)
    if refusal:
        raise ValueError(f"Model refused structured output: {refusal}")
    text = extract_message_text(message)
    if not text.strip():
        # Some providers route the guided JSON of reasoning models into the
        # reasoning field and leave content empty. Use it only if it holds JSON.
        reasoning = extract_reasoning_text(message)
        if "{" in reasoning and "}" in reasoning:
            return reasoning
    return text


def extract_reasoning_text(message: Any) -> str:
    """Hidden reasoning text of a message, if the provider returned one."""
    for attr in ("reasoning_content", "reasoning"):
        value = getattr(message, attr, None)
        if isinstance(value, str) and value:
            return value
    extra = getattr(message, "model_extra", None) or {}
    value = extra.get("reasoning_content") or extra.get("reasoning")
    return value if isinstance(value, str) else ""


def extract_json_object(raw_content: str) -> str:
    """Return the first complete JSON object in a reply, ignoring prose and trailing junk.

    Args:
        raw_content: Untrusted assistant response text.

    Returns:
        Candidate JSON object text for local validation.
    """
    stripped = re.sub(r"<think>.*?</think>", "", raw_content, flags=re.DOTALL).strip()
    if not stripped:
        return ""
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped).strip()
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", stripped):
        try:
            value, end = decoder.raw_decode(stripped, match.start())
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return stripped[match.start() : end]
    match = re.search(r"\{.*\}", stripped, re.DOTALL)
    return match.group(0) if match is not None else stripped


TOOL_MODELS = {
    model.model_fields["tool"].annotation.__args__[0]: model
    for model in InvestigationFunction.__args__
}


def normalize_step_payload(data: Any) -> Any:
    """Repair common shape mistakes of local models before strict validation.

    Handles the native tool-call shape {"name", "arguments"}, arguments nested in
    `function.arguments`/`function.parameters`, an empty or too long plan, missing
    notes and an inconsistent task_completed flag (it is derived from the tool).
    """
    if not isinstance(data, dict):
        return data
    data = dict(data)
    if "function" not in data and "name" in data:
        args = data.get("arguments") or data.get("parameters") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        data = {"function": {"tool": data["name"], **(args if isinstance(args, dict) else {})}}
    function = data.get("function")
    if isinstance(function, dict):
        function = dict(function)
        if "tool" not in function and "name" in function:
            function["tool"] = function.pop("name")
        for nested in ("arguments", "parameters"):
            if isinstance(function.get(nested), dict):
                inner = function.pop(nested)
                function = {**inner, **function}
        data["function"] = function
        data["task_completed"] = function.get("tool") == "finish_investigation"
    plan = data.get("plan_remaining_steps_brief")
    if isinstance(plan, str):
        plan = [plan]
    if not isinstance(plan, list) or not plan:
        plan = ["finish" if data.get("task_completed") else "continue"]
    data["plan_remaining_steps_brief"] = [str(item) for item in plan[:5]]
    if not isinstance(data.get("current_state"), str) or not data["current_state"]:
        data["current_state"] = "(no notes)"
    return data


def validation_summary(data: Any, limit: int = 6) -> str:
    """Precise errors for the branch matching the chosen tool, not the whole union."""
    if not isinstance(data, dict):
        return "the reply is not a JSON object"
    function = data.get("function") if isinstance(data.get("function"), dict) else {}
    model = TOOL_MODELS.get(function.get("tool"))
    if model is None:
        return f"unknown tool {function.get('tool')!r}"
    try:
        model.model_validate(function)
    except ValidationError as exc:
        return "; ".join(
            f"function.{'.'.join(str(p) for p in err['loc'])}: {err['msg']}"
            for err in exc.errors()[:limit]
        )
    return "top-level fields are invalid"


def parse_next_step_payload(raw_content: str) -> NextStep:
    """Validate one raw provider reply as a `NextStep` after shape normalization.

    Raises:
        ValueError: If JSON or schema are invalid; the message names the exact problems.
    """
    if not raw_content:
        raise ValueError("Model returned empty content for NextStep response.")

    normalized_content = extract_json_object(raw_content)
    try:
        data = json.loads(normalized_content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Model reply is not valid JSON: {exc}") from exc
    data = normalize_step_payload(data)
    try:
        return NextStep.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Invalid NextStep: {validation_summary(data)}") from exc


def response_total_tokens(response: Any) -> int:
    """Read total token usage when the provider supplies it.

    Args:
        response: OpenAI-compatible chat completion response.

    Returns:
        Non-negative total token count, or zero when unavailable.
    """
    usage = getattr(response, "usage", None)
    total_tokens = getattr(usage, "total_tokens", 0)
    return total_tokens if isinstance(total_tokens, int) and total_tokens >= 0 else 0


def render_json(value: Any) -> str:
    """Serialize participant-visible context for an LLM message.

    Args:
        value: Public JSON-compatible value.

    Returns:
        Stable readable JSON text.
    """
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str)
