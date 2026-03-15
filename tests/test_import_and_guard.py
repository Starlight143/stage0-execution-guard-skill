import io
import json
import urllib.error
import urllib.request

import pytest

from stage0_execution_guard import (
    ExecutionGuard,
    ExecutionIntent,
    PolicyResponse,
    QuotaExceededError,
    Stage0Client,
    __version__,
)


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None


def test_package_imports_and_version() -> None:
    assert __version__ == "1.2.4"


def test_execution_intent_validation_defaults() -> None:
    intent = ExecutionIntent(
        goal="Summarize the weekly report",
        tools=["filesystem", "llm"],
        side_effects=[],
    )

    assert intent.constraints == []
    assert intent.success_criteria == []
    assert intent.context == {}
    assert intent.pro is False


def test_guard_is_not_configured_without_api_key() -> None:
    guard = ExecutionGuard()
    assert guard.is_allowed(
        ExecutionIntent(
            goal="Read a local configuration file",
            tools=["filesystem"],
            side_effects=[],
        )
    ) is False


def test_policy_response_parses_new_runtime_fields() -> None:
    response = PolicyResponse.from_dict(
        {
            "verdict": "DEFER",
            "reason": "Need approval evidence",
            "risk_score": 61,
            "high_risk": True,
            "guardrail_checks": {
                "high_risk": True,
                "internal_tools": {"approval_required": True},
            },
            "clarifying_questions": ["Who approved this action?"],
            "issues": [
                {
                    "code": "APPROVAL_REQUIRED_PENDING",
                    "severity": "MEDIUM",
                    "message": "Approval is required before execution.",
                }
            ],
        }
    )

    assert response.verdict == "DEFER"
    assert response.high_risk is True
    assert response.guardrail_checks["high_risk"] is True
    assert response.guardrail_checks["internal_tools"]["approval_required"] is True


def test_client_get_usage_parses_daily_quota_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {
        "request_id": "req_usage_123",
        "api_key_id": "key_abc",
        "plan": "paid",
        "month_key": "2026-03",
        "monthly_used": 11,
        "monthly_quota": 100,
        "monthly_remaining": 89,
        "day_key": "2026-03-15",
        "daily_used": 3,
        "daily_quota": 20,
        "daily_remaining": 17,
        "per_minute_limit": 5,
        "minute_used": 1,
        "minute_remaining": 4,
        "environment": "production",
        "source": "snapshot",
        "evaluated_at": 1742000000.0,
    }

    def fake_urlopen(request: urllib.request.Request, timeout: int) -> _FakeResponse:
        assert request.full_url.endswith("/usage")
        assert request.get_method() == "GET"
        assert timeout == 30
        return _FakeResponse(payload)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    usage = Stage0Client(api_key="test-key").get_usage()

    assert usage.plan == "paid"
    assert usage.daily_quota == 20
    assert usage.daily_remaining == 17
    assert usage.monthly_remaining == 89
    assert usage.minute_remaining == 4


def test_client_raises_quota_exceeded_error_for_402_quota_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_urlopen(request: urllib.request.Request, timeout: int) -> _FakeResponse:
        raise urllib.error.HTTPError(
            url=request.full_url,
            code=402,
            msg="Payment Required",
            hdrs=None,
            fp=io.BytesIO(
                json.dumps(
                    {
                        "detail": "Monthly quota exceeded",
                        "request_id": "req_quota_123",
                    }
                ).encode("utf-8")
            ),
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    client = Stage0Client(api_key="test-key")

    with pytest.raises(QuotaExceededError) as exc_info:
        client.check(
            goal="Summarize account activity",
            tools=["filesystem"],
            side_effects=[],
        )

    assert exc_info.value.request_id == "req_quota_123"
