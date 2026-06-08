"""
Async HTTP client for Nukez SDK.

Uses httpx.AsyncClient as the transport layer, sharing error-handling
logic with the sync HTTPClient via module-level functions in _http.py.
"""

import httpx
from typing import Dict, Any, Optional

from .errors import NukezError
from ._http import (
    STANDARD_HEADERS,
    handle_error_response,
    parse_json_response,
)


class AsyncHTTPClient:
    """
    Internal async HTTP client with Nukez-specific error handling.

    Mirrors HTTPClient's interface exactly — only the transport is async.
    Shares all error-handling and response-parsing logic via _http.py
    module-level functions.

    The default timeout (120s) matches AsyncNukez's effective default — see
    AsyncNukez.__init__'s ``self.timeout = timeout or 120``. Per-call
    overrides are supported by passing ``timeout=`` through ``post()`` /
    ``get()`` / ``put()`` / ``delete()``.
    """

    def __init__(self, base_url: str, timeout: int = 120):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            timeout=timeout,
            headers=STANDARD_HEADERS.copy(),
            follow_redirects=True,
        )

    async def aclose(self):
        """Close the underlying async HTTP client."""
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.aclose()

    async def get(
        self,
        path: str,
        params: dict = None,
        headers: dict = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """Execute async GET request. Extra kwargs (e.g. ``timeout=``) flow to httpx."""
        url = f"{self.base_url}{path}"

        try:
            response = await self.client.get(
                url,
                params=params,
                headers=headers or {},
                **kwargs,
            )
        except httpx.TimeoutException:
            raise NukezError(f"Request timed out after {self.timeout}s: GET {path}")
        except httpx.HTTPError as e:
            raise NukezError(f"Request failed: GET {path}: {e}")

        if response.status_code >= 400:
            handle_error_response(response)

        return parse_json_response(response, "GET", path)

    async def post(
        self,
        path: str,
        json: dict = None,
        headers: dict = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Execute async POST request."""
        url = f"{self.base_url}{path}"

        try:
            response = await self.client.post(
                url,
                json=json,
                headers=headers or {},
                **kwargs
            )
        except httpx.TimeoutException:
            raise NukezError(f"Request timed out after {self.timeout}s: POST {path}")
        except httpx.HTTPError as e:
            raise NukezError(f"Request failed: POST {path}: {e}")

        if response.status_code >= 400:
            handle_error_response(response)

        return parse_json_response(response, "POST", path)

    async def delete(
        self,
        path: str,
        headers: dict = None
    ) -> Dict[str, Any]:
        """Execute async DELETE request."""
        url = f"{self.base_url}{path}"

        try:
            response = await self.client.delete(
                url,
                headers=headers or {},
            )
        except httpx.TimeoutException:
            raise NukezError(f"Request timed out after {self.timeout}s: DELETE {path}")
        except httpx.HTTPError as e:
            raise NukezError(f"Request failed: DELETE {path}: {e}")

        if response.status_code >= 400:
            handle_error_response(response)

        return parse_json_response(response, "DELETE", path)

    async def put(
        self,
        path: str,
        json: dict = None,
        content: bytes = None,
        headers: dict = None
    ) -> Dict[str, Any]:
        """Execute async PUT request."""
        url = f"{self.base_url}{path}"

        try:
            response = await self.client.put(
                url,
                json=json,
                content=content,
                headers=headers or {},
            )
        except httpx.TimeoutException:
            raise NukezError(f"Request timed out after {self.timeout}s: PUT {path}")
        except httpx.HTTPError as e:
            raise NukezError(f"Request failed: PUT {path}: {e}")

        if response.status_code >= 400:
            handle_error_response(response)

        return parse_json_response(response, "PUT", path)
