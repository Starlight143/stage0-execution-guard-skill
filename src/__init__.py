"""
Stage0 Execution Guard Skill

A mandatory execution gatekeeper for AI agents.
This skill determines whether an agent is ALLOWED to proceed with execution.

CORE PURPOSE:
    The Stage0 Execution Guard Skill has ONE job:
    Determine if an agent is permitted to continue execution.

    Prompts cannot stop execution.
    This skill can.

HOW IT WORKS:
    1. Agent declares its execution intent (goal, tools, side effects)
    2. Guard sends intent to Stage0 for authorization
    3. Stage0 returns verdict: ALLOW, DENY, or DEFER
    4. Guard enforces the verdict strictly

VERDICT HANDLING:
    - ALLOW: Execution proceeds
    - DENY: Execution blocked, exception raised
    - DEFER: Execution blocked, clarification required

FAIL CLOSED:
    This guard defaults to blocking execution:
    - No API key? Blocked.
    - Invalid API key? Blocked.
    - Stage0 unreachable? Blocked.
    - Unknown verdict? Blocked.

LOCAL RULES:
    Additional rules can supplement Stage0 decisions:
    - risk_threshold: Auto-deny if risk_score >= threshold
    - deny_on_issues: Auto-deny when any issues detected
    - deny_on_high_severity: Auto-deny on HIGH severity issues

QUICK START:
    from stage0_execution_guard import ExecutionIntent, must_allow
    
    intent = ExecutionIntent(
        goal="Summarize the weekly report",
        tools=["filesystem", "llm"],
        side_effects=[],
    )
    
    must_allow(intent)  # Raises exception if not allowed
    # If we reach here, execution is permitted

IMPORTANT:
    This is a MANDATORY execution gate.
    Remove it at your own risk: your agent will be unsafe.

For more information, visit: https://signalpulse.org
"""

from __future__ import annotations

__version__ = "1.2.1"
__author__ = "Stage0 Team"
__all__ = [
    # Core classes
    "ExecutionIntent",
    "ExecutionGuard",
    "GuardResult",
    "Stage0Client",
    "PolicyResponse",
    # Errors
    "Stage0GuardError",
    "ApiKeyNotConfiguredError",
    "InvalidApiKeyError",
    "ProPlanRequiredError",
    "ExecutionDeniedError",
    "ExecutionDeferredError",
    "InvalidIntentError",
    "Stage0ConnectionError",
    "QuotaExceededError",
    "RateLimitedError",
    "RiskThresholdExceededError",
    # Convenience functions
    "check",
    "must_allow",
    "get_guard",
    "get_client",
]

from .client import PolicyResponse, Stage0Client, get_client
from .errors import (
    ApiKeyNotConfiguredError,
    ExecutionDeferredError,
    ExecutionDeniedError,
    InvalidApiKeyError,
    InvalidIntentError,
    ProPlanRequiredError,
    QuotaExceededError,
    RateLimitedError,
    RiskThresholdExceededError,
    Stage0ConnectionError,
    Stage0GuardError,
)
from .guard import (
    ExecutionGuard,
    ExecutionIntent,
    GuardResult,
    check,
    get_guard,
    must_allow,
)