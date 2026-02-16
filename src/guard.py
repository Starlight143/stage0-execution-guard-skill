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
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .client import Stage0Client, get_client
from .errors import (
    ApiKeyNotConfiguredError,
    ExecutionDeferredError,
    ExecutionDeniedError,
    InvalidIntentError,
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
        
        # Tools must be a list of strings
        if not isinstance(self.tools, list):
            raise InvalidIntentError("tools must be a list")
        for i, tool in enumerate(self.tools):
            if not isinstance(tool, str):
                raise InvalidIntentError(f"tools[{i}] must be a string")
        
        # Side effects must be a list of strings (can be empty)
        if not isinstance(self.side_effects, list):
            raise InvalidIntentError("side_effects must be a list")
        for i, effect in enumerate(self.side_effects):
            if not isinstance(effect, str):
                raise InvalidIntentError(f"side_effects[{i}] must be a string")
        
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
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionIntent":
        """
        Create an ExecutionIntent from a dictionary.
        
        Args:
            data: Dictionary containing intent data.
        
        Returns:
            A new ExecutionIntent instance.
        
        Raises:
            InvalidIntentError: If required fields are missing or invalid.
        """
        required_fields = ["goal", "tools", "side_effects"]
        for field_name in required_fields:
            if field_name not in data:
                raise InvalidIntentError(f"Missing required field: {field_name}")
        
        return cls(
            goal=data["goal"],
            tools=data["tools"],
            side_effects=data["side_effects"],
            constraints=data.get("constraints", []),
            success_criteria=data.get("success_criteria", []),
            context=data.get("context", {}),
            pro=data.get("pro", False),
        )


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
    """
    
    allowed: bool
    verdict: str
    request_id: Optional[str] = None
    issues: List[str] = field(default_factory=list)
    clarifying_questions: List[str] = field(default_factory=list)
    risk_score: int = 0
    raw_response: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self) -> str:
        status = "ALLOWED" if self.allowed else f"BLOCKED ({self.verdict})"
        return f"GuardResult({status}, risk_score={self.risk_score})"


class ExecutionGuard:
    """
    The execution gatekeeper.
    
    This class is the single point of authorization for all agent executions.
    It calls Stage0 to determine whether an execution should proceed.
    
    IMPORTANT: This guard does NOT make decisions. It ONLY enforces
    the decisions made by Stage0. All authorization logic lives on
    the Stage0 server.
    
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
        fail_closed: bool = True,
    ) -> None:
        """
        Initialize the execution guard.
        
        Args:
            client: Stage0Client instance. If not provided, uses the default.
            fail_closed: If True (default), block execution on errors.
                        If False, allow execution on errors (NOT RECOMMENDED).
        """
        self._client = client or get_client()
        self._fail_closed = fail_closed
    
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
        
        # Parse the response
        verdict = response.get("verdict", "DENY").upper()
        request_id = response.get("request_id")
        
        # Extract issues
        issues = []
        raw_issues = response.get("issues", [])
        if isinstance(raw_issues, list):
            for issue in raw_issues:
                if isinstance(issue, dict):
                    code = issue.get("code", "UNKNOWN")
                    message = issue.get("message", "")
                    issues.append(f"[{code}] {message}")
                elif isinstance(issue, str):
                    issues.append(issue)
        
        # Extract clarifying questions
        clarifying_questions = []
        raw_questions = response.get("clarifying_questions", [])
        if isinstance(raw_questions, list):
            for q in raw_questions:
                if isinstance(q, str):
                    clarifying_questions.append(q)
        
        risk_score = response.get("risk_score", 0)
        
        # Enforce the verdict
        if verdict == "ALLOW":
            return GuardResult(
                allowed=True,
                verdict=verdict,
                request_id=request_id,
                issues=issues,
                clarifying_questions=clarifying_questions,
                risk_score=risk_score,
                raw_response=response,
            )
        
        if verdict == "DENY":
            message = "Execution denied by Stage0."
            if issues:
                message += f" Issues: {'; '.join(issues[:3])}"
            raise ExecutionDeniedError(
                message=message,
                issues=issues,
                request_id=request_id,
            )
        
        if verdict == "DEFER":
            message = "Execution deferred. Additional information required."
            raise ExecutionDeferredError(
                message=message,
                clarifying_questions=clarifying_questions,
                issues=issues,
                request_id=request_id,
            )
        
        # Unknown verdict - fail closed
        raise ExecutionDeniedError(
            message=f"Unknown verdict from Stage0: {verdict}",
            issues=issues,
            request_id=request_id,
        )
    
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
