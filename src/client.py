"""
Stage0 Execution Guard Skill - API Client

This module provides the HTTP client for communicating with the Stage0 API.
It handles authentication, request formatting, and response parsing.

API Behavior:
- HIGH severity issues → DENY (enforced by API)
- MEDIUM severity issues → DENY only with pro=true, otherwise ALLOW
- DEFER verdict for low-value/under-specified tasks
- Free tier provides full DENY functionality for HIGH severity issues
- Pro plan unlocks MEDIUM severity DENY and advanced features
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .errors import (
    InvalidApiKeyError,
    ProPlanRequiredError,
    QuotaExceededError,
    RateLimitedError,
    Stage0ConnectionError,
)


# Auto-load .env file if python-dotenv is available
# This is optional - if not installed, environment variables must be set manually
_ENV_LOADED = False


def _load_env_if_available() -> None:
    """Load .env file if python-dotenv is installed."""
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    
    try:
        from dotenv import load_dotenv
        # Try to load from current directory and parent directories
        load_dotenv()
        _ENV_LOADED = True
    except ImportError:
        # python-dotenv not installed, rely on environment variables
        pass


# Load .env on module import
_load_env_if_available()


# Default Stage0 API base URL
DEFAULT_STAGE0_API_BASE = "https://api.signalpulse.org"

# Request timeout in seconds
DEFAULT_TIMEOUT_SECONDS = 30

# Maximum request body size in bytes
MAX_REQUEST_BODY_SIZE = 1_000_000


def _get_version() -> str:
    """Get the package version."""
    try:
        from . import __version__
        return __version__
    except ImportError:
        return "unknown"


@dataclass
class PolicyResponse:
    """
    Structured response from Stage0 policy check.
    
    This class wraps the raw API response and provides convenient
    methods for accessing common fields.
    """
    
    verdict: str  # ALLOW, DENY, or DEFER
    reason: str
    raw_response: Dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    issues: List[Dict[str, Any]] = field(default_factory=list)
    clarifying_questions: List[str] = field(default_factory=list)
    constraints_applied: List[str] = field(default_factory=list)
    cached: bool = False
    request_id: Optional[str] = None
    
    def __post_init__(self) -> None:
        """Normalize verdict to uppercase."""
        self.verdict = self.verdict.upper()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyResponse":
        """
        Parse policy response from API response dictionary.
        
        Args:
            data: Raw API response dictionary.
        
        Returns:
            Parsed PolicyResponse instance.
        """
        verdict_str = str(data.get("verdict", "DENY")).upper()
        
        # Handle invalid verdict values gracefully (fail-safe)
        if verdict_str not in ("ALLOW", "DENY", "DEFER"):
            verdict_str = "DENY"
        
        # Parse issues list
        issues = data.get("issues") or []
        if not isinstance(issues, list):
            issues = []
        
        # Parse clarifying questions
        questions = data.get("clarifying_questions") or []
        if not isinstance(questions, list):
            questions = []
        
        # Parse constraints
        constraints = data.get("constraints_applied") or data.get("guardrails") or []
        if not isinstance(constraints, list):
            constraints = []
        
        # Build reason from issues if not provided
        reason = data.get("reason") or data.get("decision") or ""
        if not reason and issues:
            issue_messages = [
                f"{i.get('code', 'UNKNOWN')}: {i.get('message', '')}"
                for i in issues
                if isinstance(i, dict)
            ]
            reason = "; ".join(issue_messages) if issue_messages else "No reason provided"
        elif not reason:
            reason = "No reason provided"
        
        return cls(
            verdict=verdict_str,
            reason=reason,
            raw_response=data,
            risk_score=int(data.get("risk_score", 0)),
            issues=issues,
            clarifying_questions=[str(q) for q in questions if isinstance(q, str)],
            constraints_applied=[str(c) for c in constraints if isinstance(c, str)],
            cached=bool(data.get("cached", False)),
            request_id=data.get("request_id"),
        )
    
    def has_issues(self) -> bool:
        """Check if there are any issues detected."""
        return len(self.issues) > 0
    
    def get_issue_severities(self) -> List[str]:
        """Get list of issue severity levels."""
        return [
            str(issue.get("severity", "UNKNOWN")).upper()
            for issue in self.issues
            if isinstance(issue, dict)
        ]
    
    def has_high_severity_issues(self) -> bool:
        """Check if there are any HIGH severity issues."""
        return "HIGH" in self.get_issue_severities()
    
    def has_medium_severity_issues(self) -> bool:
        """Check if there are any MEDIUM severity issues."""
        return "MEDIUM" in self.get_issue_severities()
    
    def get_issue_codes(self) -> List[str]:
        """Get list of issue codes."""
        return [
            str(issue.get("code", "UNKNOWN"))
            for issue in self.issues
            if isinstance(issue, dict)
        ]


class Stage0Client:
    """
    HTTP client for the Stage0 API.
    
    This client handles all communication with Stage0, including:
    - API key authentication via x-api-key header
    - Request formatting and validation
    - Response parsing and error handling
    - Pro plan detection and handling
    
    The client is designed to be simple, stateless, and dependency-free
    (uses only the standard library).
    
    Usage:
        client = Stage0Client(api_key="your-key")
        response = client.check(
            goal="Read configuration file",
            tools=["filesystem"],
            side_effects=[],
        )
        if response.verdict == "ALLOW":
            proceed()
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ) -> None:
        """
        Initialize the Stage0 client.
        
        Args:
            api_key: Stage0 API key. If not provided, reads from
                     STAGE0_API_KEY environment variable.
            base_url: Stage0 API base URL. Defaults to
                      https://api.signalpulse.org
            timeout_seconds: Request timeout in seconds. Defaults to 30.
        """
        self.api_key = api_key or os.environ.get("STAGE0_API_KEY")
        self.base_url = (base_url or os.environ.get("STAGE0_API_BASE") or DEFAULT_STAGE0_API_BASE).rstrip("/")
        self.timeout_seconds = timeout_seconds or int(
            os.environ.get("STAGE0_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS))
        )
    
    def is_configured(self) -> bool:
        """
        Check if the client has an API key configured.
        
        Returns:
            True if an API key is set, False otherwise.
        """
        return bool(self.api_key and self.api_key.strip())
    
    def check(
        self,
        goal: str,
        tools: List[str],
        side_effects: List[str],
        constraints: Optional[List[str]] = None,
        success_criteria: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
        pro: bool = False,
    ) -> PolicyResponse:
        """
        Call the Stage0 /check endpoint.
        
        This is the primary method for requesting execution authorization.
        
        Args:
            goal: Single-sentence, clear execution goal.
            tools: List of tools the agent intends to use.
            side_effects: List of potential side effects (can be empty).
            constraints: Additional constraint conditions (optional).
            success_criteria: Criteria for success (optional).
            context: Additional context information (optional).
            pro: Whether this is a pro-mode check (requires paid plan).
        
        Returns:
            PolicyResponse with the verdict and reasoning.
        
        Raises:
            InvalidApiKeyError: If the API key is invalid.
            ProPlanRequiredError: If pro=true but on free plan.
            QuotaExceededError: If the API quota is exceeded.
            RateLimitedError: If rate limit is hit.
            Stage0ConnectionError: If unable to connect to Stage0.
        """
        if not self.is_configured():
            raise InvalidApiKeyError()
        
        payload: Dict[str, Any] = {
            "goal": goal,
            "tools": tools,
            "side_effects": side_effects,
            "constraints": constraints or [],
            "success_criteria": success_criteria or [],
            "context": context or {},
            "pro": pro,
        }
        
        return self._post("/check", payload)
    
    def _post(self, path: str, payload: Dict[str, Any]) -> PolicyResponse:
        """
        Make a POST request to the Stage0 API.
        
        Args:
            path: API endpoint path (e.g., "/check").
            payload: Request body as a dictionary.
        
        Returns:
            Parsed PolicyResponse.
        """
        url = f"{self.base_url}{path}"
        
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if len(body) > MAX_REQUEST_BODY_SIZE:
            raise Stage0ConnectionError("Request body too large")
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-api-key": self.api_key,
            "User-Agent": f"stage0-execution-guard/{_get_version()}",
        }
        
        request = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method="POST",
        )
        
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                response_body = response.read().decode("utf-8")
                data = json.loads(response_body)
                return PolicyResponse.from_dict(data)
        
        except urllib.error.HTTPError as e:
            return self._handle_http_error(e)
        
        except urllib.error.URLError as e:
            raise Stage0ConnectionError(str(e.reason))
        
        except json.JSONDecodeError as e:
            raise Stage0ConnectionError(f"Invalid JSON response: {e}")
        
        except TimeoutError:
            raise Stage0ConnectionError("Request timed out")
        
        except Exception as e:
            raise Stage0ConnectionError(str(e))
    
    def _handle_http_error(self, error: urllib.error.HTTPError) -> PolicyResponse:
        """
        Handle HTTP error responses from the Stage0 API.
        
        Maps HTTP status codes to appropriate exceptions or responses.
        """
        request_id = None
        error_data: Dict[str, Any] = {}
        
        try:
            body = error.read().decode("utf-8")
            error_data = json.loads(body)
            request_id = error_data.get("request_id")
        except Exception:
            pass
        
        status_code = error.code
        
        # 401 Unauthorized - Invalid API key
        if status_code == 401:
            raise InvalidApiKeyError(request_id)
        
        # 402 Payment Required - Pro feature requested on free plan
        if status_code == 402:
            detail = error_data.get("detail", "Pro checks require a paid plan")
            if isinstance(detail, dict):
                detail = detail.get("detail", str(detail))
            raise ProPlanRequiredError(message=str(detail), request_id=request_id)
        
        # 429 Too Many Requests - Rate limited
        if status_code == 429:
            retry_after = error_data.get("retry_after_seconds")
            raise RateLimitedError(
                retry_after_seconds=retry_after,
                request_id=request_id,
            )
        
        # 503 Service Unavailable
        if status_code == 503:
            raise Stage0ConnectionError("Stage0 service temporarily unavailable")
        
        # For other errors, return a DENY response with the error details
        # This allows the caller to inspect the error details
        return PolicyResponse(
            verdict="DENY",
            reason=f"HTTP {status_code}: {error.reason}",
            raw_response=error_data,
            request_id=request_id,
            issues=[{
                "code": "HTTP_ERROR",
                "severity": "HIGH",
                "message": f"HTTP {status_code}: {error.reason}",
            }],
        )


# Module-level client instance for convenience
_default_client: Optional[Stage0Client] = None


def get_client() -> Stage0Client:
    """
    Get the default Stage0 client instance.
    
    Creates a new client if one doesn't exist, using environment variables
    for configuration.
    
    Returns:
        The default Stage0Client instance.
    """
    global _default_client
    if _default_client is None:
        _default_client = Stage0Client()
    return _default_client


def reset_client() -> None:
    """
    Reset the default client instance.
    
    Useful for testing or when changing configuration.
    """
    global _default_client
    _default_client = None