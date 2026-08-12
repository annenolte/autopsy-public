"""stream_sonnet must let API errors propagate, never swallow them.

Regression test for the defect found during the Aug 2026 replication: the client
caught RateLimitError / APIConnectionError / APIError and yielded the error text
into the scan output. A failed call therefore looked identical to a scan that
legitimately found nothing — normal return, zero findings parsed, recall scored
as 0 at $0.00 cost — and the eval harness's retry path never fired.

No network access: get_client is patched, so no API key is required either.
"""
from unittest.mock import MagicMock, patch

import httpx
import pytest
from anthropic import APIConnectionError, APIError, RateLimitError

from autopsy.llm import client as llm_client

_REQUEST = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
_RESPONSE = httpx.Response(429, request=_REQUEST)

FAILURES = [
    pytest.param(
        APIError("boom", request=_REQUEST, body=None), APIError, id="api_error"),
    pytest.param(
        APIConnectionError(request=_REQUEST), APIConnectionError, id="connection_error"),
    pytest.param(
        RateLimitError("slow down", response=_RESPONSE, body=None),
        RateLimitError, id="rate_limit_error"),
]


def _client_raising(exc):
    """A stand-in Anthropic client whose .messages.stream(...) raises `exc`."""
    fake = MagicMock()
    fake.messages.stream.side_effect = exc
    return fake


@pytest.mark.parametrize("exc,expected", FAILURES)
def test_stream_sonnet_propagates_api_errors(exc, expected):
    """The exception reaches the caller instead of becoming scan text."""
    with patch.object(llm_client, "get_client", return_value=_client_raising(exc)):
        with pytest.raises(expected):
            list(llm_client.stream_sonnet("system", "user message"))


@pytest.mark.parametrize("exc,expected", FAILURES)
def test_stream_sonnet_yields_no_error_text(exc, expected):
    """Nothing is emitted before the failure — no partial '[ERROR] ...' output.

    This is the property that actually mattered: the old handlers yielded a
    string, so `"".join(stream_sonnet(...))` returned successfully and the
    caller scored it. Here the generator must raise on first iteration.
    """
    with patch.object(llm_client, "get_client", return_value=_client_raising(exc)):
        gen = llm_client.stream_sonnet("system", "user message")
        collected = []
        with pytest.raises(expected):
            for chunk in gen:
                collected.append(chunk)
        assert collected == [], f"leaked output before raising: {collected!r}"


def test_stream_sonnet_still_streams_and_records_usage_on_success():
    """The happy path is unchanged: chunks stream through and usage is recorded."""
    stream_ctx = MagicMock()
    stream_ctx.text_stream = iter(["alpha ", "beta"])
    stream_ctx.get_final_message.return_value = MagicMock(
        usage=MagicMock(input_tokens=11, output_tokens=7))

    fake = MagicMock()
    fake.messages.stream.return_value.__enter__.return_value = stream_ctx

    with patch.object(llm_client, "get_client", return_value=fake):
        llm_client.reset_usage()
        out = list(llm_client.stream_sonnet("system", "user message"))

    assert out == ["alpha ", "beta"]
    usage = llm_client.get_usage()
    assert usage["sonnet_in"] == 11
    assert usage["sonnet_out"] == 7
    assert usage["calls"] == 1
