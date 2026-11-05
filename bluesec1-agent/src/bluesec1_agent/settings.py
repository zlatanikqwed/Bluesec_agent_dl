from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class Settings(BaseSettings):
    """Scenario-runtime and OpenAI-compatible provider settings."""

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    scenario_runtime_endpoint: str = Field(
        default="127.0.0.1:50051",
        validation_alias="SCENARIO_RUNTIME_ENDPOINT",
        min_length=1,
    )
    scenario_runtime_token: SecretStr = Field(
        validation_alias="SCENARIO_RUNTIME_TOKEN",
        min_length=1,
    )
    scenario_runtime_verify_tls: bool = Field(
        default=True,
        validation_alias="SCENARIO_RUNTIME_VERIFY_TLS",
    )
    scenario_runtime_arena: str | None = Field(
        default=None,
        validation_alias="SCENARIO_RUNTIME_ARENA",
        min_length=1,
        max_length=64,
    )
    remote_run_label: str = Field(
        default="bluesec1-agent",
        validation_alias="REMOTE_RUN_LABEL",
        min_length=1,
    )
    agent_name: str = Field(
        default="bluesec1-agent",
        validation_alias="AGENT_NAME",
        min_length=1,
        max_length=255,
    )

    llm_base_url: str = Field(validation_alias="LLM_BASE_URL", min_length=1)
    llm_api_key: SecretStr = Field(validation_alias="LLM_API_KEY", min_length=1)
    llm_default_model: str = Field(validation_alias="LLM_DEFAULT_MODEL", min_length=1)
    llm_timeout_seconds: float = Field(
        default=120.0,
        validation_alias="LLM_TIMEOUT_SECONDS",
        gt=0,
    )
    llm_max_completion_tokens: int = Field(
        default=8192,
        validation_alias="LLM_MAX_COMPLETION_TOKENS",
        gt=0,
    )
    llm_max_step_retries: int = Field(
        default=3,
        validation_alias="LLM_MAX_STEP_RETRIES",
        ge=1,
        le=5,
    )
    agent_max_steps: int = Field(
        default=28,
        validation_alias="BLUESEC_AGENT_MAX_STEPS",
        ge=1,
        le=100,
    )
    agent_context_chars: int = Field(
        default=40_000,
        validation_alias="BLUESEC_AGENT_CONTEXT_CHARS",
        ge=5_000,
    )
    agent_keep_recent_results: int = Field(
        default=6,
        validation_alias="BLUESEC_AGENT_KEEP_RECENT_RESULTS",
        ge=1,
    )
    agent_trajectory_dir: str = Field(
        default="runs",
        validation_alias="BLUESEC_AGENT_TRAJECTORY_DIR",
    )
    llm_disable_thinking: bool = Field(
        default=False,
        validation_alias="LLM_DISABLE_THINKING",
    )
    llm_inline_schema_refs: bool = Field(
        default=False,
        validation_alias="LLM_INLINE_SCHEMA_REFS",
    )
    llm_http_retries: int = Field(
        default=0, ge=0, le=20, validation_alias="LLM_HTTP_RETRIES",
    )
    llm_min_interval_seconds: float = Field(
        default=0.0, ge=0.0, le=120.0, validation_alias="LLM_MIN_INTERVAL_SECONDS",
    )
    llm_extra_body: str = Field(
        default="",
        validation_alias="LLM_EXTRA_BODY",
        description="JSON object merged into each chat request (provider-specific options).",
    )
    # Optional second model used ONLY for verdict arbitration (analyst vs blind
    # reviewer disagreement). Empty LLM_ARBITER_MODEL disables it.
    llm_arbiter_model: str = Field(default="", validation_alias="LLM_ARBITER_MODEL")
    llm_arbiter_base_url: str = Field(default="", validation_alias="LLM_ARBITER_BASE_URL")
    llm_arbiter_api_key: SecretStr = Field(default=SecretStr(""), validation_alias="LLM_ARBITER_API_KEY")
    llm_arbiter_max_completion_tokens: int = Field(
        default=8192, ge=256, validation_alias="LLM_ARBITER_MAX_COMPLETION_TOKENS",
    )
    llm_arbiter_inline_schema_refs: bool = Field(
        default=True, validation_alias="LLM_ARBITER_INLINE_SCHEMA_REFS",
    )
    llm_arbiter_disable_thinking: bool = Field(
        default=False, validation_alias="LLM_ARBITER_DISABLE_THINKING",
    )
    llm_arbiter_extra_body: str = Field(
        default="",
        validation_alias="LLM_ARBITER_EXTRA_BODY",
        description="JSON for the arbiter; empty = reuse LLM_EXTRA_BODY.",
    )
    llm_arbiter_response_mode: Literal["schema", "json_object", "none"] = Field(
        default="schema",
        validation_alias="LLM_ARBITER_RESPONSE_MODE",
        description="schema = strict json_schema; json_object / none for models that return empty content.",
    )
    llm_arbiter_shadow: bool = Field(
        default=True,
        validation_alias="LLM_ARBITER_SHADOW",
        description="Also ask the main model and log its verdict (offline comparison only).",
    )
    agent_max_same_relation: int = Field(
        default=8,
        validation_alias="BLUESEC_AGENT_MAX_SAME_RELATION",
        ge=1,
    )
    agent_max_stale_steps: int = Field(
        default=6,
        validation_alias="BLUESEC_AGENT_MAX_STALE_STEPS",
        ge=2,
    )
    agent_min_entities_before_benign: int = Field(
        default=3,
        validation_alias="BLUESEC_AGENT_MIN_ENTITIES_BEFORE_BENIGN",
        ge=0,
    )
    agent_enough_to_decide: int = Field(
        default=14,
        validation_alias="BLUESEC_AGENT_ENOUGH_TO_DECIDE",
        ge=3,
    )

    agent_report_experiment: Literal[
        "control", "malicious_files", "malicious_block", "benign_entities", "fact_reasoning",
        "combined", "internal_source", "service_persistence", "archive_files",
        "baseline_archives", "inbound_sources", "service_persistence_v2", "inbound_guard",
        "scheduled_task", "script_file", "interactive_logon",
        "agent_handles", "agent_handles_nocite", "random_probe", "explore_probe", "role_policy", "benign_probe", "benign_probe2"
    ] = Field(default="control", validation_alias="BLUESEC_AGENT_REPORT_EXPERIMENT")

    agent_drop_deleted_file_artifacts: bool = Field(
        default=True, validation_alias="BLUESEC_AGENT_DROP_DELETED_FILE_ARTIFACTS",
    )

    agent_harvest_mode: bool = Field(
        default=True, validation_alias="BLUESEC_AGENT_HARVEST_MODE",
    )
    agent_harvest_budget: int = Field(
        default=8, ge=1, le=10, validation_alias="BLUESEC_AGENT_HARVEST_BUDGET",
    )

    agent_gpt_oss_mode: bool = Field(
        default=False,
        validation_alias="BLUESEC_AGENT_GPT_OSS_MODE",
    )
    agent_v16_decision_mode: bool = Field(
        default=True, validation_alias="BLUESEC_AGENT_V16_DECISION_MODE",
    )
    agent_v17_security_mode: bool = Field(
        default=False, validation_alias="BLUESEC_AGENT_V17_SECURITY_MODE",
    )
    agent_v18_soc_mode: bool = Field(
        default=False, validation_alias="BLUESEC_AGENT_V18_SOC_MODE",
    )
    agent_v19_forensic_mode: bool = Field(
        default=False, validation_alias="BLUESEC_AGENT_V19_FORENSIC_MODE",
    )
    agent_v24_threat_mode: bool = Field(
        default=False, validation_alias="BLUESEC_AGENT_V24_THREAT_MODE",
    )
    agent_v25_response_mode: bool = Field(
        default=False, validation_alias="BLUESEC_AGENT_V25_RESPONSE_MODE",
    )
    agent_v25_scope_calls: int = Field(
        default=6, ge=0, le=20, validation_alias="BLUESEC_AGENT_V25_SCOPE_CALLS",
    )
    agent_v25_hard_codes: str = Field(
        default=("smb_authentication_outcome_unverified,smb_source_purpose_unverified,"
                 "unaccounted_cross_identity_share,unaccounted_credentialed_share,"
                 "material_remote_action_not_authorized,unaccounted_network_bridge,"
                 "unaccounted_relay_surface,unaccounted_smb_source"),
        validation_alias="BLUESEC_AGENT_V25_HARD_CODES",
    )
    agent_v25_benign_anchors: bool = Field(
        default=False, validation_alias="BLUESEC_AGENT_V25_BENIGN_ANCHORS",
    )
    agent_v25_benign_max_evidence: int = Field(
        default=3, ge=0, le=3, validation_alias="BLUESEC_AGENT_V25_BENIGN_MAX_EVIDENCE",
    )
    agent_v25_benign_calls: int = Field(
        default=3, ge=0, le=10, validation_alias="BLUESEC_AGENT_V25_BENIGN_CALLS",
    )
    agent_v25_response_tier: int = Field(
        default=2, ge=1, le=3, validation_alias="BLUESEC_AGENT_V25_RESPONSE_TIER",
    )
    agent_v23_reasoning_mode: bool = Field(
        default=False, validation_alias="BLUESEC_AGENT_V23_REASONING_MODE",
    )
    agent_v22_evidence_mode: bool = Field(
        default=False, validation_alias="BLUESEC_AGENT_V22_EVIDENCE_MODE",
    )
    agent_v21_risk_mode: bool = Field(
        default=False, validation_alias="BLUESEC_AGENT_V21_RISK_MODE",
    )
    agent_v20_case_mode: bool = Field(
        default=False, validation_alias="BLUESEC_AGENT_V20_CASE_MODE",
    )
    agent_review_enabled: bool = Field(
        default=True,
        validation_alias="BLUESEC_AGENT_REVIEW_ENABLED",
    )
