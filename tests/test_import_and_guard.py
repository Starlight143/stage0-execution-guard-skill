from stage0_execution_guard import ExecutionGuard, ExecutionIntent, PolicyResponse, __version__


def test_package_imports_and_version() -> None:
    assert __version__ == "1.2.3"


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
