"""
Stage0 Execution Guard Skill - API Client

This module provides the HTTP client for communicating with the Stage0 API.
It handles authentication, request formatting, and response parsing.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .errors import (
    InvalidApiKeyError,
    QuotaExceededError,
    RateLimitedError,
    Stage0ConnectionError,
)


# Default Stage0 API base URL
DEFAULT_STAGE0_API_BASE = "https://api.signalpulse.org"

# Request timeout in seconds
DEFAULT_TIMEOUT_SECONDS = 30

# Maximum request body size in bytes
MAX_REQUEST_BODY_SIZE = 1_000_000


class Stage0Client:
    """
    HTTP client for the Stage0 API.
    
    This client handles all communication with Stage0, including:
    - API key authentication via x-api-key header
    - Request formatting and validation
    - Response parsing and error handling
    - Retry logic for transient failures
    
    The client is designed to be simple, stateless, and dependency-free
    (uses only the standard library).
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
        self.timeout_seconds = timeout_seconds or int(os.environ.get("STAGE0_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS)))
    
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
    ) -> Dict[str, Any]:
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
            The parsed JSON response from Stage0 as a dictionary.
            Expected keys: verdict, decision, issues, clarifying_questions, etc.
        
        Raises:
            InvalidApiKeyError: If the API key is invalid.
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
    
    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make a POST request to the Stage0 API.
        
        Args:
            path: API endpoint path (e.g., "/check").
            payload: Request body as a dictionary.
        
        Returns:
            Parsed JSON response as a dictionary.
        """
        url = f"{self.base_url}{path}"
        
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if len(body) > MAX_REQUEST_BODY_SIZE:
            raise Stage0ConnectionError("Request body too large")
        
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-api-key": self.api_key,
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
                return json.loads(response_body)
        
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
    
    def _handle_http_error(self, error: urllib.error.HTTPError) -> Dict[str, Any]:
        """
        Handle HTTP error responses from the Stage0 API.
        
        Maps HTTP status codes to appropriate exceptions.
        """
        request_id = None
        
        try:
            body = error.read().decode("utf-8")
            data = json.loads(body)
            request_id = data.get("request_id")
        except Exception:
            data = {}
        
        status_code = error.code
        
        if status_code == 401:
            raise InvalidApiKeyError(request_id)
        
        if status_code == 402:
            raise QuotaExceededError(request_id)
        
        if status_code == 429:
            retry_after = data.get("retry_after_seconds")
            raise RateLimitedError(
                retry_after_seconds=retry_after,
                request_id=request_id,
            )
        
        if status_code == 503:
            raise Stage0ConnectionError("Stage0 service temporarily unavailable")
        
        # For other errors, return the response body if available
        # This allows the caller to inspect the error details
        if data:
            data.setdefault("request_id", request_id)
            return data
        
        raise Stage0ConnectionError(f"HTTP {status_code}: {error.reason}")


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
