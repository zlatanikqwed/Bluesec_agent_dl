import argparse
import asyncio
import contextlib
import json
import sys

import truststore
from pydantic import ValidationError

from bluesec1_agent.agent import SimpleSGRAgent
from bluesec1_agent.llm import OpenAIStructuredStepClient
from bluesec1_agent.settings import Settings
from bluesec1_client import (
    CompetitionClosedError,
    RemoteAuthenticationError,
    RemoteBenchmarkClient,
    RemoteRateLimitError,
    RemoteUnavailableError,
    RunCapacityExceededError,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the remote-runtime command-line interface.

    Returns:
        Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Run the structured-generation agent against scenario-runtime."
    )
    parser.add_argument("--endpoint", help="Override SCENARIO_RUNTIME_ENDPOINT.")
    parser.add_argument("--token", help="Override SCENARIO_RUNTIME_TOKEN.")
    parser.add_argument("--run-label", help="Override REMOTE_RUN_LABEL.")
    parser.add_argument("--agent-name", help="Override AGENT_NAME.")
    parser.add_argument("--arena", help="Override SCENARIO_RUNTIME_ARENA.")
    parser.add_argument(
        "--verify-tls",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Override SCENARIO_RUNTIME_VERIFY_TLS.",
    )
    return parser


async def run(args: argparse.Namespace) -> None:
    """Execute one new remote run and print its task results.

    Args:
        args: Parsed command-line arguments.
    """
    truststore.inject_into_ssl()
    settings = _load_settings()
    llm = OpenAIStructuredStepClient(
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key.get_secret_value(),
        model=settings.llm_default_model,
        timeout_seconds=settings.llm_timeout_seconds,
        max_completion_tokens=settings.llm_max_completion_tokens,
        max_retries=settings.llm_max_step_retries,
        disable_thinking=settings.llm_disable_thinking,
        inline_schema_refs=settings.llm_inline_schema_refs,
        extra_body=json.loads(settings.llm_extra_body) if settings.llm_extra_body.strip() else None,
        http_retries=settings.llm_http_retries,
        min_interval_seconds=settings.llm_min_interval_seconds,
    )
    arbiter_llm = None
    if settings.llm_arbiter_model.strip():
        arbiter_body = settings.llm_arbiter_extra_body.strip() or settings.llm_extra_body.strip()
        arbiter_llm = OpenAIStructuredStepClient(
            base_url=settings.llm_arbiter_base_url.strip() or settings.llm_base_url,
            api_key=(settings.llm_arbiter_api_key.get_secret_value()
                     or settings.llm_api_key.get_secret_value()),
            model=settings.llm_arbiter_model.strip(),
            timeout_seconds=settings.llm_timeout_seconds,
            max_completion_tokens=settings.llm_arbiter_max_completion_tokens,
            max_retries=settings.llm_max_step_retries,
            disable_thinking=settings.llm_arbiter_disable_thinking,
            inline_schema_refs=settings.llm_arbiter_inline_schema_refs,
            extra_body=json.loads(arbiter_body) if arbiter_body else None,
            http_retries=settings.llm_http_retries,
            min_interval_seconds=settings.llm_min_interval_seconds,
            response_mode=settings.llm_arbiter_response_mode,
        )
    agent_name = args.agent_name or settings.agent_name
    verify_tls = (
        settings.scenario_runtime_verify_tls if args.verify_tls is None else args.verify_tls
    )
    async with (
        llm,
        (arbiter_llm or contextlib.nullcontext()),
        RemoteBenchmarkClient(
            endpoint=args.endpoint or settings.scenario_runtime_endpoint,
            token=args.token or settings.scenario_runtime_token.get_secret_value(),
            verify_tls=verify_tls,
            run_label=args.run_label or settings.remote_run_label,
            agent_name=agent_name,
            model_name=settings.llm_default_model,
            arena=args.arena or settings.scenario_runtime_arena,
            metadata={
                "agent": agent_name,
                "implementation": "structured-generation-scenario-runtime-grpc",
                "model": settings.llm_default_model,
                "arbiter_model": settings.llm_arbiter_model.strip() or None,
            },
        ) as client,
    ):
        result = await SimpleSGRAgent(
            llm,
            max_steps=settings.agent_max_steps,
            context_chars=settings.agent_context_chars,
            keep_recent_results=settings.agent_keep_recent_results,
            trajectory_dir=settings.agent_trajectory_dir,
            max_same_relation=settings.agent_max_same_relation,
            max_stale_steps=settings.agent_max_stale_steps,
            min_entities_before_benign=settings.agent_min_entities_before_benign,
            enough_to_decide=settings.agent_enough_to_decide,
            review_enabled=settings.agent_review_enabled,
            gpt_oss_mode=(settings.agent_gpt_oss_mode or
                          "gpt-oss" in settings.llm_default_model.lower()),
            v16_mode=(settings.agent_v16_decision_mode and not (settings.agent_v18_soc_mode or settings.agent_v19_forensic_mode or settings.agent_v20_case_mode or settings.agent_v21_risk_mode or settings.agent_v22_evidence_mode or settings.agent_v23_reasoning_mode or settings.agent_v24_threat_mode) and
                      (settings.agent_gpt_oss_mode or
                       "gpt-oss" in settings.llm_default_model.lower())),
            security_mode=(settings.agent_v17_security_mode and not (settings.agent_v18_soc_mode or settings.agent_v19_forensic_mode or settings.agent_v20_case_mode or settings.agent_v21_risk_mode or settings.agent_v22_evidence_mode or settings.agent_v23_reasoning_mode or settings.agent_v24_threat_mode)),
            soc_v18_mode=settings.agent_v18_soc_mode,
            soc_v19_mode=settings.agent_v19_forensic_mode,
            soc_v20_mode=settings.agent_v20_case_mode,
            soc_v21_mode=settings.agent_v21_risk_mode,
            soc_v22_mode=settings.agent_v22_evidence_mode,
            soc_v23_mode=settings.agent_v23_reasoning_mode,
            soc_v24_mode=settings.agent_v24_threat_mode,
            v25_response_mode=settings.agent_v25_response_mode,
            v25_response_tier=settings.agent_v25_response_tier,
            v25_scope_calls=settings.agent_v25_scope_calls,
            v25_hard_codes=settings.agent_v25_hard_codes,
            v25_benign_anchors=settings.agent_v25_benign_anchors,
            v25_benign_calls=settings.agent_v25_benign_calls,
            v25_benign_max_evidence=settings.agent_v25_benign_max_evidence,
            harvest_mode=settings.agent_harvest_mode,
            harvest_budget=settings.agent_harvest_budget,
            report_experiment=settings.agent_report_experiment,
            drop_deleted_file_artifacts=settings.agent_drop_deleted_file_artifacts,
            arbiter_llm=arbiter_llm,
            arbiter_shadow=settings.llm_arbiter_shadow,
        ).run(client)

    print(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))


def main() -> None:
    """Parse arguments and execute the async remote agent."""
    try:
        asyncio.run(run(build_parser().parse_args()))
    except RunCapacityExceededError as error:
        print(_run_capacity_message(error), file=sys.stderr)
        raise SystemExit(1) from error
    except CompetitionClosedError as error:
        print(
            "The selected competition arena is closed. Check SCENARIO_RUNTIME_ARENA or retry "
            "when the arena opens.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteRateLimitError as error:
        print(
            "Run starts are temporarily rate-limited. Wait before starting another run.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteAuthenticationError as error:
        print(
            "The runtime rejected your key. Check SCENARIO_RUNTIME_TOKEN in .env.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error
    except RemoteUnavailableError as error:
        print(
            "Cannot reach the runtime. Check SCENARIO_RUNTIME_ENDPOINT and "
            "SCENARIO_RUNTIME_VERIFY_TLS in .env.",
            file=sys.stderr,
        )
        raise SystemExit(1) from error


def _load_settings() -> Settings:
    """Load settings and explain what is missing instead of raising a raw error.

    Returns:
        Validated settings.
    """
    try:
        return Settings()
    except ValidationError as error:
        missing = [str(item["loc"][0]) for item in error.errors() if item["type"] == "missing"]
        if not missing:
            raise
        print("Missing configuration: " + ", ".join(missing), file=sys.stderr)
        print(
            "Copy .env.example to .env and fill it in. "
            "Runtime address and key: https://bluesec.team/",
            file=sys.stderr,
        )
        raise SystemExit(1) from error


def _run_capacity_message(error: RunCapacityExceededError) -> str:
    """Explain which run limit was hit and what to do about it.

    Args:
        error: Capacity failure reported by the runtime.

    Returns:
        Message for the participant.
    """
    if getattr(error, "reason", None) == "PROCESS_ACTIVE_RUN_LIMIT_REACHED":
        lines = ["The runtime is at its overall capacity right now. This is not your limit."]
    else:
        lines = [
            "You have reached your limit of concurrent runs.",
            "Wait for a running one to finish. If an agent was killed mid-run, its run stays "
            "open until it is released.",
        ]
    return "\n".join(lines)
