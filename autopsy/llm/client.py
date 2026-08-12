"""Anthropic API client wrapper with streaming, error handling, and model routing."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from anthropic import Anthropic, APIError, APIConnectionError, RateLimitError

# Load .env from project root (walk up from this file)
_env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(_env_path)

# Model configuration
HAIKU_MODEL = "claude-haiku-4-5-20251001"
# NOTE: the original analysis model, "claude-sonnet-4-20250514", was retired by
# Anthropic and now returns a 404 not_found_error, which broke the benchmark.
# Pinned to its date-stamped successor for reproducibility (updated 2026-06-18).
SONNET_MODEL = "claude-sonnet-4-5-20250929"


# ── Token-usage accounting (reviewer #14: cost normalization) ──────────────────
# Captures input/output tokens per model so the eval harness can report
# tokens/cost per KLOC. Additive — does not affect detection.
_USAGE = {"haiku_in": 0, "haiku_out": 0, "sonnet_in": 0, "sonnet_out": 0, "calls": 0}


def reset_usage() -> None:
    for k in _USAGE:
        _USAGE[k] = 0


def get_usage() -> dict:
    return dict(_USAGE)


def _record(model: str, usage) -> None:
    try:
        _USAGE[f"{model}_in"] += getattr(usage, "input_tokens", 0) or 0
        _USAGE[f"{model}_out"] += getattr(usage, "output_tokens", 0) or 0
        _USAGE["calls"] += 1
    except Exception:  # pragma: no cover — accounting must never break a scan
        pass


def get_client() -> Anthropic:
    """Get an Anthropic client, checking for API key."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY not set. Export it: export ANTHROPIC_API_KEY=sk-..."
        )
    return Anthropic(api_key=api_key)


def call_haiku(
    system: str,
    user_message: str,
    max_tokens: int = 2048,
) -> str:
    """Call Haiku for fast triage. Non-streaming (triage should be quick).

    Returns the text response or raises on failure.
    """
    client = get_client()
    try:
        response = client.messages.create(
            model=HAIKU_MODEL,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user_message}],
        )
        _record("haiku", getattr(response, "usage", None))
        return response.content[0].text
    except RateLimitError:
        raise RuntimeError("Rate limited by Anthropic API. Wait a moment and retry.")
    except APIConnectionError:
        raise RuntimeError("Cannot connect to Anthropic API. Check your network.")
    except APIError as e:
        raise RuntimeError(f"Anthropic API error: {e.message}")


def stream_sonnet(
    system: str,
    user_message: str,
    max_tokens: int = 8192,
):
    """Stream a response from Sonnet for deep reasoning.

    Yields text chunks as they arrive. This is the main output the user sees.

    max_tokens raised 4096 -> 8192: a 4096 cap truncated the scan mid-finding on
    larger inputs (observed a cut-off '## [SEVERITY: MEDIUM]' header), which can
    drop real findings at the end of a long report and understate recall. Only
    allows more output; never forces it (cost rises only when output was being
    truncated).

    API errors are NOT caught here. They previously yielded an error string into
    the scan text, which made a failed call indistinguishable from a scan that
    legitimately found nothing: the caller saw a normal return, the findings
    parser saw no findings, and the run was scored as recall=0 at zero cost.
    Letting RateLimitError / APIConnectionError / APIError propagate means a
    failed call fails loudly instead of being recorded as a result.
    """
    client = get_client()
    with client.messages.stream(
        model=SONNET_MODEL,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user_message}],
    ) as stream:
        for text in stream.text_stream:
            yield text
        try:
            _record("sonnet", stream.get_final_message().usage)
        except Exception:  # pragma: no cover
            pass
