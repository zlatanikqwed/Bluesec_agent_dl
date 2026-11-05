"""Quick availability/latency probe for several models on the configured provider.

Usage:
  uv run --env-file .env python scripts/probe_models.py moonshotai/kimi-k2.6 z-ai/glm-5.3

For each model: one small JSON request with enough tokens for a reasoning model.
Prints HTTP status, latency and whether a valid JSON object came back. The API key
is read from .env and never printed.
"""

import json
import sys
import time

from openai import OpenAI

from bluesec1_agent.settings import Settings

SCHEMA = {
    "type": "json_schema",
    "json_schema": {
        "name": "probe",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {"verdict": {"type": "string", "enum": ["benign", "malicious"]}},
            "required": ["verdict"],
            "additionalProperties": False,
        },
    },
}
PROMPT = (
    "A signed Windows Update service downloaded an MSI from the internal WSUS server and "
    'installed it. Answer only with JSON like {"verdict": "benign"} or {"verdict": "malicious"}.'
)


def main() -> None:
    models = sys.argv[1:]
    if not models:
        sys.exit("Pass one or more model IDs.")
    s = Settings()
    client = OpenAI(base_url=s.llm_base_url, api_key=s.llm_api_key.get_secret_value(),
                    timeout=s.llm_timeout_seconds, max_retries=0)
    for model in models:
        started = time.perf_counter()
        try:
            r = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": PROMPT}],
                max_tokens=2048,
                response_format=SCHEMA,
            )
            text = (r.choices[0].message.content or "").strip()
            try:
                ok = isinstance(json.loads(text), dict)
            except ValueError:
                ok = False
            print(f"{model:45s} OK   {time.perf_counter() - started:6.1f}s  json={ok}  {text[:60]!r}")
        except Exception as exc:  # report and continue with the next model
            status = getattr(exc, "status_code", type(exc).__name__)
            print(f"{model:45s} FAIL {time.perf_counter() - started:6.1f}s  {status}")


if __name__ == "__main__":
    main()
