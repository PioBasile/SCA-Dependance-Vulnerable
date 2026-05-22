"""EUVD (EU Vulnerability Database) source implementation."""
import logging
from typing import List, Optional, Dict, Any
from core.config import make_client, EUVD_SEARCH, EUVD_BY_ID, settings
from core.types import NormalizedVulnerabilityDict
from core.logger import get_logger
from matching.version import item_affects_version
from matching.cpe import parse_cpe, resolve_euvd_names
from sources.base import VulnerabilitySource, CachingSourceMixin, RateLimitedSourceMixin

logger = get_logger(__name__)


class EUVDSource(VulnerabilitySource, CachingSourceMixin, RateLimitedSourceMixin):
    """EUVD source for fetching European vulnerability data."""

    @property
    def name(self) -> str:
        return "EUVD"

    async def healthy(self) -> bool:
        """Check EUVD API health."""
        async with make_client() as client:
            try:
                resp = await client.get(f"{EUVD_SEARCH}?size=1", timeout=5.0)
                return resp.status_code == 200
            except Exception as e:
                logger.warning(f"[EUVD] Health check failed: {e}")
                return False

    async def fetch_by_id(self, euvd_id: str) -> Optional[Dict[str, Any]]:
        """Fetch vulnerability by EUVD ID."""
        cache_key = self._get_cache_key("fetch_by_id", euvd_id)
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            return cached
        
        try:
            await self._apply_rate_limit()
            async with make_client() as client:
                resp = await client.get(EUVD_BY_ID, params={"id": euvd_id}, timeout=10.0)
                resp.raise_for_status()
                result = resp.json()
                self._set_in_cache(cache_key, result)
                return result
        except Exception as e:
            logger.warning(f"[EUVD] fetch_by_id failed for {euvd_id}: {e}")
            return None

    async def search_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up an EUVD entry that aliases ``cve_id``.

        EUVD's `/search?text=CVE-XXXX-YYYY` returns up to ``size`` items whose
        aliases mention the CVE; we walk the page and return the first item
        whose alias list actually contains ``cve_id``.
        """
        cache_key = self._get_cache_key("search_by_cve", cve_id)
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            return cached

        try:
            await self._apply_rate_limit()
            async with make_client() as client:
                resp = await client.get(
                    EUVD_SEARCH,
                    params={"text": cve_id, "size": 25},
                    timeout=10.0,
                )
                resp.raise_for_status()
                items = resp.json().get("items", [])
        except Exception as e:
            logger.warning(f"[EUVD] search_by_cve({cve_id}) failed: {e}")
            return None

        for item in items:
            aliases = (item.get("aliases") or "").split("\n")
            if any(a.strip().upper() == cve_id.upper() for a in aliases):
                self._set_in_cache(cache_key, item)
                return item

        self._set_in_cache(cache_key, None)
        return None

    async def search_by_product(
        self, vendor: str, product: str, size: int = 100
    ) -> List[Dict[str, Any]]:
        """Search for vulnerabilities by vendor/product."""
        cache_key = self._get_cache_key("search_by_product", vendor, product, size)
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            return cached
        
        try:
            await self._apply_rate_limit()
            async with make_client() as client:
                resp = await client.get(
                    EUVD_SEARCH,
                    params={"vendor": vendor, "product": product, "size": size},
                    timeout=15.0
                )
                resp.raise_for_status()
                items = resp.json().get("items", [])
                self._set_in_cache(cache_key, items)
                return items
        except Exception as e:
            logger.warning(f"[EUVD] search_by_product({vendor}/{product}) failed: {e}")
            return []

    async def query(self, cpe: str) -> List[NormalizedVulnerabilityDict]:
        """Query EUVD for vulnerabilities affecting a CPE."""
        try:
            parsed = parse_cpe(cpe)
            target_version = parsed["version"]
            name_candidates = resolve_euvd_names(cpe)
            results: List[NormalizedVulnerabilityDict] = []

            for vendor, product in name_candidates:
                items = await self.search_by_product(vendor, product)
                if not items:
                    continue

                # Match against the canonical product name we just searched
                # with — that name is what EUVD entries use, and it lets us
                # reject sibling products like "Spring Cloud Function" when
                # the user queried "spring framework".
                variant_results = []
                for item in items:
                    affected = item_affects_version(
                        item, target_version, product_hint=product
                    )
                    cve_ids = [
                        a.strip() for a in item.get("aliases", "").split("\n")
                        if a.strip().upper().startswith("CVE-")
                    ]
                    if cve_ids:
                        variant_results.append({
                            "cve_ids": cve_ids,
                            "euvd_id": item.get("id"),
                            "source": self.name,
                            "base_score": item.get("baseScore"),
                            "base_vector": item.get("baseScoreVector"),
                            "base_version": item.get("baseScoreVersion", "3.1"),
                            "description": item.get("description", ""),
                            "references": [r.strip() for r in item.get("references", "").split("\n") if r.strip()],
                            "affects_version": affected,
                            "raw": item,
                        })

                results.extend(variant_results)
                # Stop only when this variant confirmed at least one version match.
                # If everything came back affects_version=False the product name
                # may have matched a sibling entry — try the next name variant.
                if any(r["affects_version"] for r in variant_results):
                    break

            logger.info(f"[EUVD] Found {len(results)} vulnerabilities for {cpe}")
            return results
        except Exception as e:
            logger.error(f"[EUVD] query({cpe}) failed: {e}", exc_info=True)
            return []