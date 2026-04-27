"""Base class for all vulnerability sources."""
from abc import ABC, abstractmethod
from typing import Any, List, Optional

from core.logger import get_logger
from core.types import NormalizedVulnerabilityDict

logger = get_logger(__name__)


class VulnerabilitySource(ABC):
    """
    Abstract base class for vulnerability data sources.
    
    Each source must implement:
    - query(cpe): Search for vulnerabilities affecting a CPE
    - healthy(): Quick liveness check
    """
    
    DEFAULT_TIMEOUT = 30.0
    MAX_RETRIES = 3
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable source name (e.g., 'EUVD', 'OSV', 'NVD')."""
        pass
    
    @abstractmethod
    async def query(self, cpe: str) -> List[NormalizedVulnerabilityDict]:
        """
        Query this source for vulnerabilities affecting the given CPE.
        
        Returns a list of normalized vulnerability dicts — each must contain:
          {
            "cve_ids":      ["CVE-2021-44228"],     # list of CVE IDs
            "euvd_id":      "EUVD-2021-1234",       # (optional) EUVD ID
            "source":       "EUVD",                 # source name
            "base_score":   10.0,                   # CVSS score or None
            "base_vector":  "CVSS:3.1/...",         # CVSS vector or None
            "base_version": "3.1",                  # CVSS version
            "description":  "...",                  # vulnerability desc or ""
            "references":   ["https://..."],        # reference URLs or []
            "affects_version": True,                # whether this version affected
            "raw":          { ... }                 # original response (debugging)
          }
        
        Args:
            cpe: CPE 2.3 string
        
        Returns:
            List of normalized vulnerability data
        
        Raises:
            SourceError: If query fails (retryable or not)
        """
        pass
    
    @abstractmethod
    async def healthy(self) -> bool:
        """
        Quick liveness check.
        
        Returns:
            True if source is reachable and responsive, False otherwise
        """
        pass
    
    async def search(self, query: str, **kwargs) -> List[dict]:
        """
        Generic search method (optional override by subclasses).
        
        Args:
            query: Search query
            **kwargs: Additional parameters
        
        Returns:
            List of search results
        """
        logger.warning(f"[{self.name}] search() not implemented")
        return []
    
    async def fetch_by_id(self, item_id: str) -> Optional[dict]:
        """
        Fetch a specific vulnerability by ID (optional override).
        
        Args:
            item_id: Vulnerability ID
        
        Returns:
            Vulnerability data or None
        """
        logger.warning(f"[{self.name}] fetch_by_id() not implemented")
        return None


class CachingSourceMixin:
    """Mixin to add caching capability to sources."""
    
    _cache: dict = {}
    _cache_ttl = 3600  # 1 hour
    
    def _get_cache_key(self, method: str, *args, **kwargs) -> str:
        """Generate cache key."""
        return f"{self.name}:{method}:{':'.join(str(a) for a in args)}"
    
    def _get_from_cache(self, key: str) -> Optional[Any]:
        """Get value from cache."""

        if key in self._cache:
            value, timestamp = self._cache[key]
            import time
            if time.time() - timestamp < self._cache_ttl:
                return value
            del self._cache[key]
        return None

    def _set_in_cache(self, key: str, value: Any) -> None:
        """Store value in cache."""
        import time
        self._cache[key] = (value, time.time())


class RateLimitedSourceMixin:
    """Mixin to add rate limiting to sources."""
    
    REQUEST_DELAY = 0.1  # 100ms between requests
    _last_request_time = 0.0
    
    async def _apply_rate_limit(self) -> None:
        """Apply rate limiting."""
        import time
        import asyncio
        
        elapsed = time.time() - self._last_request_time
        if elapsed < self.REQUEST_DELAY:
            await asyncio.sleep(self.REQUEST_DELAY - elapsed)
        self._last_request_time = time.time()