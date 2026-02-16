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
    ) -> None:
        super().__init__(message)
        self.message = message
        self.verdict = verdict
        self.issues = issues or []
        self.clarifying_questions = clarifying_questions or []
        self.request_id = request_id
    
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
                "尚未設定 Stage0 API Key。\n"
                "請前往 https://signalpulse.org 註冊帳號並取得 API Key。"
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
                "Stage0 API Key 無效或已被撤銷。\n"
                "請前往 https://signalpulse.org 檢查您的 API Key 狀態。"
            ),
            verdict="DENY",
            request_id=request_id,
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
    ) -> None:
        super().__init__(
            message=message,
            verdict="DENY",
            issues=issues,
            request_id=request_id,
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
    ) -> None:
        super().__init__(
            message=message,
            verdict="DEFER",
            issues=issues,
            clarifying_questions=clarifying_questions,
            request_id=request_id,
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
            message=f"執行意圖格式無效: {message}",
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
            message=f"無法連接 Stage0 API，執行已被阻擋。{detail}",
            verdict="DENY",
        )


class QuotaExceededError(Stage0GuardError):
    """
    Raised when the API key's quota has been exceeded.
    
    The user needs to upgrade their plan or wait for quota reset.
    """
    
    def __init__(self, request_id: Optional[str] = None) -> None:
        super().__init__(
            message="API 配額已用盡。請前往 https://signalpulse.org 升級方案。",
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
        retry_msg = f"請等待 {retry_after_seconds} 秒後重試。" if retry_after_seconds else "請稍後重試。"
        super().__init__(
            message=f"請求頻率過高。{retry_msg}",
            verdict="DENY",
            request_id=request_id,
        )
