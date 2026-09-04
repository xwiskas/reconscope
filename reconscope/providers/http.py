"""HTTP client wrapper for passive providers (PRD §12.5, P4).

Wraps ``httpx`` with a bounded timeout and at most one automatic retry with
jitter. The underlying ``httpx.Client`` is injectable so tests can supply an
``httpx.MockTransport`` and never touch the network.
"""

from __future__ import annotations

import random
import time

import httpx

_DEFAULT_TIMEOUT = 30.0
_USER_AGENT = "ReconScope/0.1 (+local passive recon; educational)"


class ProviderError(RuntimeError):
    """A provider request failed. Carries a stable, source-specific code.

    The job runner turns this into a *failed* job for one module without
    failing the whole project (graceful degradation, PRD P4 / M1 exit).
    """

    def __init__(self, provider: str, code: str, detail: str):
        self.provider = provider
        self.code = code
        self.detail = detail
        super().__init__(f"{provider}: {code}: {detail}")


class HttpClient:
    """Minimal GET-only client with retry and a fixed user agent."""

    def __init__(
        self,
        client: httpx.Client | None = None,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        max_retries: int = 1,
        sleep: callable = time.sleep,
    ):
        self._client = client or httpx.Client(
            timeout=timeout, follow_redirects=True, headers={"User-Agent": _USER_AGENT}
        )
        self._max_retries = max_retries
        self._sleep = sleep

    def get_json(self, provider: str, url: str, params: dict | None = None):
        """GET ``url`` and parse JSON, or raise :class:`ProviderError`."""
        response = self._get(provider, url, params)
        try:
            return response.json()
        except ValueError as exc:
            raise ProviderError(provider, "invalid_json", str(exc)) from exc

    def get_text(self, provider: str, url: str, params: dict | None = None) -> str:
        return self._get(provider, url, params).text

    def get_raw(
        self, provider: str, url: str, *, follow_redirects: bool = False
    ) -> httpx.Response:
        """Issue a single GET without automatic redirects (for scope-checked hops).

        No retry: the caller owns the redirect loop and its scope checks.
        """
        try:
            return self._client.get(url, follow_redirects=follow_redirects)
        except httpx.TimeoutException as exc:
            raise ProviderError(provider, "timeout", str(exc)) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(provider, "network_error", str(exc)) from exc

    def _get(self, provider: str, url: str, params: dict | None) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = self._client.get(url, params=params)
            except httpx.TimeoutException as exc:
                last_exc = ProviderError(provider, "timeout", str(exc))
            except httpx.HTTPError as exc:
                last_exc = ProviderError(provider, "network_error", str(exc))
            else:
                if response.status_code >= 500:
                    last_exc = ProviderError(
                        provider, "provider_unavailable",
                        f"HTTP {response.status_code}",
                    )
                elif response.status_code >= 400:
                    # 4xx is not retryable and usually means "no data".
                    raise ProviderError(
                        provider, "provider_error", f"HTTP {response.status_code}"
                    )
                else:
                    return response
            if attempt < self._max_retries:
                # Retry once with jitter (PRD P4).
                self._sleep(0.2 + random.random() * 0.3)
        assert last_exc is not None
        raise last_exc

    def close(self) -> None:
        self._client.close()
