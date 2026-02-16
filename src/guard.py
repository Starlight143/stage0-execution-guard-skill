"""
Stage0 Execution Guard Skill - Core Guard Logic

This module implements the core execution guard logic.
It is the single point of authorization for all agent executions.

CORE PRINCIPLE: Fail Closed
- If Stage0 is unreachable, deny execution
- If API key is missing/invalid, deny execution
- If verdict is not ALLOW, deny execution

This guard is NOT optional. It is a mandatory execution gate.
Remove it at your own risk: your agent will be unsafe.

LOCAL RULES:
The guard can apply additional local rules on top of Stage0 decisions:
- risk_threshold: Auto-deny if risk_score >= threshold (default: 100, disabled)
- deny_on_issues: Auto-deny when any issues are detected (default: False)
- deny_on_high_severity: Auto-deny when HIGH severity issues are found (default: True)

These rules provide extra protection layers, especially useful for free tier users.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .client import PolicyResponse, Stage0Client, get_client
from .errors import (
    ApiKeyNotConfiguredError,
    ExecutionDeferredError,
    ExecutionDeniedError,
    InvalidIntentError,
    RiskThresholdExceededError,
    Stage0GuardError,
)


@dataclass
class ExecutionIntent:
    """
    Represents an agent's execution intent.
    
    This structure captures what the agent intends to do before it does it.
    All fields must be explicitly declared - no implicit assumptions.
    
    Attributes:
        goal: A single, clear sentence describing what the agent intends to do.
        tools: List of tool names the agent plans to use.
        side_effects: List of potential side effects (use empty list if none).
        constraints: Additional constraints or limitations (optional).
        success_criteria: How success will be measured (optional).
        context: Additional context for the check (optional).
        pro: Whether to use pro-mode evaluation (requires paid plan).
    """
    
    goal: str
    tools: List[str]
    side_effects: List[str]
    constraints: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    pro: bool = False
    
    def __post_init__(self) -> None:
        """Validate the intent after initialization."""
        self._validate()
    
    def _validate(self) -> None:
        """
        Validate the execution intent.
        
        Raises:
            InvalidIntentError: If the intent is invalid.
        """
        # Goal is required and must be a non-empty string
        if not isinstance(self.goal, str):
            raise InvalidIntentError("goal must be a string")
        if not self.goal.strip():
            raise InvalidIntentError("goal is required and cannot be empty")
        
        # Goal length check
        if len(self.goal) > 8000:
            raise InvalidIntentError("goal must be 8000 characters or less")
        
        # Tools must be a list of strings
        if not isinstance(self.tools, list):
            raise InvalidIntentError("tools must be a list")
        for i, tool in enumerate(self.tools):
            if not isinstance(tool, str):
                raise InvalidIntentError(f"tools[{i}] must be a string")
        
        # Tools count check
        if len(self.tools) > 200:
            raise InvalidIntentError("tools cannot have more than 200 items")
        
        # Side effects must be a list of strings (can be empty)
        if not isinstance(self.side_effects, list):
            raise InvalidIntentError("side_effects must be a list")
        for i, effect in enumerate(self.side_effects):
            if not isinstance(effect, str):
                raise InvalidIntentError(f"side_effects[{i}] must be a string")
        
        # Side effects count check
        if len(self.side_effects) > 200:
            raise InvalidIntentError("side_effects cannot have more than 200 items")
        
        # Constraints must be a list of strings (can be empty)
        if not isinstance(self.constraints, list):
            raise InvalidIntentError("constraints must be a list")
        for i, constraint in enumerate(self.constraints):
            if not isinstance(constraint, str):
                raise InvalidIntentError(f"constraints[{i}] must be a string")
        
        # Success criteria must be a list of strings (can be empty)
        if not isinstance(self.success_criteria, list):
            raise InvalidIntentError("success_criteria must be a list")
        for i, criterion in enumerate(self.success_criteria):
            if not isinstance(criterion, str):
                raise InvalidIntentError(f"success_criteria[{i}] must be a string")
        
        # Context must be a dictionary
        if not isinstance(self.context, dict):
            raise InvalidIntentError("context must be a dictionary")
        
        # Pro must be a boolean
        if not isinstance(self.pro, bool):
            raise InvalidIntentError("pro must be a boolean")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the intent to a dictionary for API calls."""
        return {
            "goal": self.goal,
            "tools": self.tools,
            "side_effects": self.side_effects,
            "constraints": self.constraints,
            "success_criteria": self.success_criteria,
            "context": self.context,
            "pro": self.pro,
        }


@dataclass
class GuardResult:
    """
    Result of an execution guard check.
    
    This represents the outcome of asking Stage0 whether execution is allowed.
    
    Attributes:
        allowed: Whether execution is allowed.
        verdict: The Stage0 verdict (ALLOW, DENY, or DEFER).
        request_id: Unique identifier for this check (for debugging).
        issues: List of issues found during evaluation.
        clarifying_questions: Questions to answer for DEFER verdicts.
        risk_score: Overall risk score (0-100).
        raw_response: The complete raw response from Stage0.
        locally_denied: Whether the denial was applied by local rules.
    """
    
    allowed: bool
    verdict: str
    request_id: Optional[str] = None
    issues: List[str] = field(default_factory=list)
    clarifying_questions: List[str] = field(default_factory=list)
    risk_score: int = 0
    raw_response: Dict[str, Any] = field(default_factory=dict)
    locally_denied: bool = False
    
    def __str__(self) -> str:
        status = "ALLOWED" if self.allowed else f"BLOCKED ({self.verdict})"
        local = " [local rule]" if self.locally_denied else ""
        return f"GuardResult({status}{local}, risk_score={self.risk_score})"


class ExecutionGuard:
    """
    The execution gatekeeper.
    
    This class is the single point of authorization for all agent executions.
    It calls Stage0 to determine whether an execution should proceed.
    
    IMPORTANT: This guard does NOT make decisions. It ONLY enforces
    the decisions made by Stage0. All authorization logic lives on
    the Stage0 server.
    
    Local rules can supplement Stage0 decisions:
    - risk_threshold: Auto-deny if risk_score >= threshold
    - deny_on_issues: Auto-deny when any issues are detected
    - deny_on_high_severity: Auto-deny when HIGH severity issues are found
    
    Usage:
        guard = ExecutionGuard()
        
        # This will raise an exception if execution is not allowed
        result = guard.check(intent)
        
        # If we reach here, execution is allowed
        proceed_with_execution()
    
    The default behavior is FAIL CLOSED:
    - No API key? Execution blocked.
    - Invalid API key? Execution blocked.
    - Stage0 unreachable? Execution blocked.
    - Verdict is DENY? Execution blocked.
    - Verdict is DEFER? Execution blocked.
    
    Only an explicit ALLOW verdict permits execution.
    """
    
    def __init__(
        self,
        client: Optional[Stage0Client] = None,
        risk_threshold: int = 100,
        deny_on_issues: bool = False,
        deny_on_high_severity: bool = True,
    ) -> None:
        """
        Initialize the execution guard.
        
        Args:
            client: Stage0Client instance. If not provided, uses the default.
            risk_threshold: Auto-deny if risk_score >= threshold.
                           Default 100 means disabled (risk scores are 0-100).
                           Set lower (e.g., 50) to deny risky operations.
            deny_on_issues: If True, auto-deny when ANY issues are detected.
                           Default False lets Stage0 decide based on severity.
            deny_on_high_severity: If True, auto-deny when HIGH severity issues
                                  are found. Default True for extra safety.
        """
        self._client = client or get_client()
        self._risk_threshold = risk_threshold
        self._deny_on_issues = deny_on_issues
        self._deny_on_high_severity = deny_on_high_severity
    
    def check(self, intent: ExecutionIntent) -> GuardResult:
        """
        Check whether the execution intent is allowed.
        
        This is the main entry point for the guard. It sends the intent
        to Stage0 and returns the result.
        
        IMPORTANT: This method raises an exception if execution is NOT allowed.
        The exception contains details about why execution was blocked.
        
        Args:
            intent: The execution intent to check.
        
        Returns:
            GuardResult with allowed=True if execution is permitted.
        
        Raises:
            ApiKeyNotConfiguredError: No API key is configured.
            ExecutionDeniedError: Stage0 returned DENY verdict.
            ExecutionDeferredError: Stage0 returned DEFER verdict.
            RiskThresholdExceededError: Local risk threshold exceeded.
            Stage0GuardError: Other guard-related errors.
        """
        # Check if API key is configured
        if not self._client.is_configured():
            raise ApiKeyNotConfiguredError()
        
        # Call Stage0
        response = self._client.check(
            goal=intent.goal,
            tools=intent.tools,
            side_effects=intent.side_effects,
            constraints=intent.constraints,
            success_criteria=intent.success_criteria,
            context=intent.context,
            pro=intent.pro,
        )
        
        # Apply local rules BEFORE processing verdict
        # This allows local rules to override Stage0's ALLOW
        if response.verdict == "ALLOW":
            local_result = self._apply_local_rules(response)
            if local_result is not None:
                return local_result
        
        # Process the Stage0 verdict
        return self._process_verdict(response)
    
    def _apply_local_rules(self, response: PolicyResponse) -> Optional[GuardResult]:
        """
        Apply local validation rules.
        
        These rules can supplement Stage0 decisions by applying
        additional checks on top of the API response.
        
        Args:
            response: The Stage0 API response.
        
        Returns:
            GuardResult with allowed=False if local rules deny,
            None if local rules pass.
        """
        # Check risk threshold
        if response.risk_score >= self._risk_threshold:
            raise RiskThresholdExceededError(
                risk_score=response.risk_score,
                threshold=self._risk_threshold,
            )
        
        # Check for issues if deny_on_issues is enabled
        if self._deny_on_issues and response.has_issues():
            issues = self._format_issues(response.issues)
            raise ExecutionDeniedError(
                message=f"Issues detected: {response.reason}",
                issues=issues,
                request_id=response.request_id,
                risk_score=response.risk_score,
            )
        
        # Check for HIGH severity issues if deny_on_high_severity is enabled
        if self._deny_on_high_severity and response.has_high_severity_issues():
            issues = self._format_issues(response.issues)
            raise ExecutionDeniedError(
                message=f"HIGH severity issues detected: {response.reason}",
                issues=issues,
                request_id=response.request_id,
                risk_score=response.risk_score,
            )
        
        return None
    
    def _process_verdict(self, response: PolicyResponse) -> GuardResult:
        """
        Process the Stage0 verdict and raise appropriate exceptions.
        
        Args:
            response: The Stage0 API response.
        
        Returns:
            GuardResult for ALLOW verdict.
        
        Raises:
            ExecutionDeniedError: For DENY verdict.
            ExecutionDeferredError: For DEFER verdict.
        """
        issues = self._format_issues(response.issues)
        
        if response.verdict == "ALLOW":
            return GuardResult(
                allowed=True,
                verdict=response.verdict,
                request_id=response.request_id,
                issues=issues,
                clarifying_questions=response.clarifying_questions,
                risk_score=response.risk_score,
                raw_response=response.raw_response,
            )
        
        if response.verdict == "DENY":
            message = f"Execution denied by Stage0: {response.reason}"
            raise ExecutionDeniedError(
                message=message,
                issues=issues,
                request_id=response.request_id,
                risk_score=response.risk_score,
            )
        
        if response.verdict == "DEFER":
            message = f"Execution deferred: {response.reason}"
            raise ExecutionDeferredError(
                message=message,
                clarifying_questions=response.clarifying_questions,
                issues=issues,
                request_id=response.request_id,
                risk_score=response.risk_score,
            )
        
        # Unknown verdict - fail closed
        raise ExecutionDeniedError(
            message=f"Unknown verdict from Stage0: {response.verdict}",
            issues=issues,
            request_id=response.request_id,
            risk_score=response.risk_score,
        )
    
    def _format_issues(self, raw_issues: List[Any]) -> List[str]:
        """Format raw issues into human-readable strings."""
        formatted = []
        for issue in raw_issues:
            if isinstance(issue, dict):
                code = issue.get("code", "UNKNOWN")
                severity = issue.get("severity", "")
                message = issue.get("message", "")
                formatted.append(f"[{severity}] {code}: {message}")
            elif isinstance(issue, str):
                formatted.append(issue)
        return formatted
    
    def check_or_raise(self, intent: ExecutionIntent) -> None:
        """
        Check the intent and raise an exception if not allowed.
        
        This is a convenience method for when you only care about
        whether execution is blocked (you don't need the result details).
        
        Args:
            intent: The execution intent to check.
        
        Raises:
            Stage0GuardError: If execution is not allowed.
        """
        self.check(intent)
    
    def is_allowed(self, intent: ExecutionIntent) -> bool:
        """
        Check if execution is allowed without raising an exception.
        
        This is useful for conditional logic where you want to check
        without handling exceptions.
        
        Args:
            intent: The execution intent to check.
        
        Returns:
            True if execution is allowed, False otherwise.
        """
        try:
            result = self.check(intent)
            return result.allowed
        except Stage0GuardError:
            return False


# Module-level guard instance for convenience
_default_guard: Optional[ExecutionGuard] = None


def get_guard() -> ExecutionGuard:
    """
    Get the default execution guard instance.
    
    Returns:
        The default ExecutionGuard instance.
    """
    global _default_guard
    if _default_guard is None:
        _default_guard = ExecutionGuard()
    return _default_guard


def check(intent: ExecutionIntent) -> GuardResult:
    """
    Check an execution intent using the default guard.
    
    This is a convenience function for the common case.
    
    Args:
        intent: The execution intent to check.
    
    Returns:
        GuardResult with allowed=True if execution is permitted.
    
    Raises:
        Stage0GuardError: If execution is not allowed.
    """
    return get_guard().check(intent)


def must_allow(intent: ExecutionIntent) -> None:
    """
    Ensure execution is allowed, raise otherwise.
    
    This is the simplest way to use the guard - just call this
    before executing. If it returns, execution is allowed.
    
    Args:
        intent: The execution intent to check.
    
    Raises:
        Stage0GuardError: If execution is not allowed.
    """
    get_guard().check(intent)