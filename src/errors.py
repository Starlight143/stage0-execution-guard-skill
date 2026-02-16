"""
Stage0 Execution Guard Skill - Error Definitions

This module defines all error types used by the execution guard.
These errors are designed to be clear, actionable, and immediately
inform the agent/user why execution was blocked.
"""

from __future__ import annotations

from typing import List, Optional


class Stage0GuardError(Exception):
    """
    Base exception for all Stage0 Execution Guard errors.
    
    This is the parent class for all guard-related errors.
    Catching this exception will catch all guard-specific errors.
    """
    
    def __init__(
        self,
        message: str,
        verdict: Optional[str] = None,
        issues: Optional[List[str]] = None,
        clarifying_questions: Optional[List[str]] = None,
        request_id: Optional[str] = None,
        risk_score: int = 0,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.verdict = verdict
        self.issues = issues or []
        self.clarifying_questions = clarifying_questions or []
        self.request_id = request_id
        self.risk_score = risk_score
    
    def __str__(self) -> str:
        return self.message
    
    def to_dict(self) -> dict:
        """Convert error to a dictionary for serialization."""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "verdict": self.verdict,
            "issues": self.issues,
            "clarifying_questions": self.clarifying_questions,
            "request_id": self.request_id,
            "risk_score": self.risk_score,
        }


class ApiKeyNotConfiguredError(Stage0GuardError):
    """
    Raised when STAGE0_API_KEY is not configured.
    
    This is a critical error that blocks all execution.
    The user must register at https://signalpulse.org to obtain an API key.
    """
    
    def __init__(self) -> None:
        super().__init__(
            message=(
                "Stage0 API Key is not configured.\n"
                "Please visit https://signalpulse.org to register and obtain an API Key."
            ),
            verdict="DENY",
        )


class InvalidApiKeyError(Stage0GuardError):
    """
    Raised when the Stage0 API key is invalid or revoked.
    
    The key may have been revoked, expired, or never existed.
    """
    
    def __init__(self, request_id: Optional[str] = None) -> None:
        super().__init__(
            message=(
                "Stage0 API Key is invalid or has been revoked.\n"
                "Please visit https://signalpulse.org to check your API Key status."
            ),
            verdict="DENY",
            request_id=request_id,
        )


class ProPlanRequiredError(Stage0GuardError):
    """
    Raised when a Pro feature is requested but the API key is on a free plan.
    
    Pro features include:
    - MEDIUM severity issue enforcement (DENY on MEDIUM issues)
    - Advanced risk scoring
    - Pro-mode checks
    
    Free tier provides full DENY functionality for HIGH severity issues.
    """
    
    def __init__(
        self,
        message: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> None:
        detail = message or "Pro checks require a paid plan"
        super().__init__(
            message=(
                f"{detail}\n"
                "Please visit https://signalpulse.org to upgrade your plan."
            ),
            verdict="DENY",
            request_id=request_id,
            issues=["PRO_PLAN_REQUIRED: This feature requires a Pro plan"],
        )


class ExecutionDeniedError(Stage0GuardError):
    """
    Raised when Stage0 returns a DENY verdict.
    
    The proposed execution is not allowed to proceed.
    This is the primary blocking error for unsafe operations.
    """
    
    def __init__(
        self,
        message: str,
        issues: Optional[List[str]] = None,
        request_id: Optional[str] = None,
        risk_score: int = 0,
    ) -> None:
        super().__init__(
            message=message,
            verdict="DENY",
            issues=issues,
            request_id=request_id,
            risk_score=risk_score,
        )


class ExecutionDeferredError(Stage0GuardError):
    """
    Raised when Stage0 returns a DEFER verdict.
    
    The execution requires additional information or clarification
    before it can be allowed to proceed.
    """
    
    def __init__(
        self,
        message: str,
        clarifying_questions: Optional[List[str]] = None,
        issues: Optional[List[str]] = None,
        request_id: Optional[str] = None,
        risk_score: int = 0,
    ) -> None:
        super().__init__(
            message=message,
            verdict="DEFER",
            issues=issues,
            clarifying_questions=clarifying_questions,
            request_id=request_id,
            risk_score=risk_score,
        )


class InvalidIntentError(Stage0GuardError):
    """
    Raised when the execution intent format is invalid.
    
    The intent must conform to the required structure:
    - goal: string (required)
    - tools: list of strings (required)
    - side_effects: list of strings (required, can be empty)
    - constraints: list of strings (optional)
    """
    
    def __init__(self, message: str) -> None:
        super().__init__(
            message=f"Invalid execution intent format: {message}",
            verdict="DENY",
        )


class Stage0ConnectionError(Stage0GuardError):
    """
    Raised when unable to connect to Stage0 API.
    
    This could be due to network issues, timeout, or service unavailability.
    The default behavior is to fail closed (deny execution).
    """
    
    def __init__(self, original_error: Optional[str] = None) -> None:
        detail = f" ({original_error})" if original_error else ""
        super().__init__(
            message=f"Unable to connect to Stage0 API. Execution blocked.{detail}",
            verdict="DENY",
        )


class QuotaExceededError(Stage0GuardError):
    """
    Raised when the API key's quota has been exceeded.
    
    The user needs to upgrade their plan or wait for quota reset.
    """
    
    def __init__(self, request_id: Optional[str] = None) -> None:
        super().__init__(
            message="API quota exceeded. Please visit https://signalpulse.org to upgrade your plan.",
            verdict="DENY",
            request_id=request_id,
        )


class RateLimitedError(Stage0GuardError):
    """
    Raised when rate limit is exceeded.
    
    The client should wait before retrying.
    """
    
    def __init__(
        self,
        retry_after_seconds: Optional[int] = None,
        request_id: Optional[str] = None,
    ) -> None:
        retry_msg = f"Please wait {retry_after_seconds} seconds before retrying." if retry_after_seconds else "Please wait before retrying."
        super().__init__(
            message=f"Rate limit exceeded. {retry_msg}",
            verdict="DENY",
            request_id=request_id,
        )


class RiskThresholdExceededError(Stage0GuardError):
    """
    Raised when the risk score exceeds the configured threshold.
    
    This is a local enforcement rule that can supplement API decisions.
    Useful for free tier users who want additional risk-based blocking.
    """
    
    def __init__(
        self,
        risk_score: int,
        threshold: int,
    ) -> None:
        super().__init__(
            message=f"Risk score ({risk_score}) exceeds configured threshold ({threshold}).",
            verdict="DENY",
            risk_score=risk_score,
            issues=[f"RISK_THRESHOLD_EXCEEDED: Risk score {risk_score} > threshold {threshold}"],
        )