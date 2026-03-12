from stage0_execution_guard import ExecutionGuard, ExecutionIntent, __version__


def test_package_imports_and_version() -> None:
    assert __version__ == "1.2.2"


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
