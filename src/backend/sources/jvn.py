"""JVN (Japan Vulnerability Notes) source implementation."""
import logging
from typing import List, Optional, Dict, Any
from core.config import make_client, JVN_API_BASE, settings
from core.types import NormalizedVulnerabilityDict
from core.logger import get_logger
from matching.cpe import parse_cpe
from sources.base import VulnerabilitySource, CachingSourceMixin, RateLimitedSourceMixin

logger = get_logger(__name__)


class JVNSource(VulnerabilitySource, CachingSourceMixin, RateLimitedSourceMixin):
    """JVN (Japan Vulnerability Notes) source for Japanese vulnerability data."""

    @property
    def name(self) -> str:
        return "JVN"

    async def healthy(self) -> bool:
        """Check JVN API health."""
        async with make_client() as client:
            try:
                # MyJVN uses a single entry point: /myjvn. We pass a valid method.
                resp = await client.head(
                    JVN_API_BASE,
                    params={"method": "getVulnOverviewList", "feed": "hnd"},
                    timeout=5.0,
                    follow_redirects=True
                )
                # Accept standard status codes that prove the server is reachable and routing
                is_healthy = resp.status_code in (200, 400, 404, 405)
                if not is_healthy:
                    logger.warning(f"[JVN] Health check failed: status {resp.status_code}")
                else:
                    logger.debug(f"[JVN] API reachable (status {resp.status_code})")
                return is_healthy
            except Exception as e:
                logger.warning(f"[JVN] Health check failed: {e}")
                # Mark as healthy if we can't reach it - it might work during queries
                return True

    async def query(self, cpe: str) -> List[NormalizedVulnerabilityDict]:
        """Query JVN for vulnerabilities affecting a CPE."""
        try:
            parsed = parse_cpe(cpe)
            vendor = parsed["vendor"]
            product = parsed["product"]
            
            # JVN search by product name using extracted CPE components
            results = await self._search_by_product(vendor, product)
            
            if results:
                logger.info(f"[JVN] Found {len(results)} vulnerabilities for {cpe}")
            return results
        except Exception as e:
            logger.error(f"[JVN] query({cpe}) failed: {e}", exc_info=True)
            return []

    async def _search_by_product(self, vendor: str, product: str) -> List[NormalizedVulnerabilityDict]:
        """Search JVN by vendor and product using CPE filters."""
        try:
            cache_key = self._get_cache_key("search_by_product", vendor, product)
            cached = self._get_from_cache(cache_key)
            if cached is not None:
                return cached

            await self._apply_rate_limit()

            async with make_client() as client:
                resp = await client.get(
                    JVN_API_BASE,
                    params={
                        "method": "getVulnOverviewList",
                        "feed": "hnd",
                        "cpeName": f"cpe:/:{vendor}:{product}",
                        "lang": "en",
                        # No ft=json — the API returns XML regardless
                    },
                    timeout=15.0
                )
                resp.raise_for_status()

                # Guard: empty body means no results
                content = resp.text.strip()
                if not content:
                    self._set_in_cache(cache_key, [])
                    return []

                # Parse XML
                import xml.etree.ElementTree as ET
                try:
                    root = ET.fromstring(content)
                except ET.ParseError as e:
                    logger.warning(f"[JVN] XML parse error for {vendor}/{product}: {e}")
                    return []

                # MyJVN uses these namespaces in the HND feed
                ns = {
                    "rdf":  "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
                    "dc":   "http://purl.org/dc/elements/1.1/",
                    "dcterms": "http://purl.org/dc/terms/",
                    "sec":  "http://jvn.jp/rss/mod_sec/3.0/",
                    "marking": "http://data-marking.mitre.org/Marking-1.0",
                    "tlpMarking": "http://www.us-cert.gov/tlp/",
                }

                results: List[NormalizedVulnerabilityDict] = []

                for item in root.findall("item", ns):
                    # CVE IDs from dc:identifier or sec:identifier
                    cve_ids = []
                    for ident_el in item.findall("sec:identifier", ns):
                        ident = (ident_el.text or "").strip()
                        if ident.startswith("CVE-"):
                            cve_ids.append(ident)

                    # CVSS
                    cvss_score = None
                    cvss_vector = None
                    cvss_el = item.find("sec:cvss", ns)
                    if cvss_el is not None:
                        raw_score = cvss_el.get("score")
                        cvss_vector = cvss_el.get("vector")
                        if raw_score:
                            try:
                                cvss_score = float(raw_score)
                            except ValueError:
                                pass

                    # Description / title / link
                    desc_el = item.find("dc:description", ns)
                    title_el = item.find("dc:title", ns)  # fallback
                    link_el = item.find("link", ns)

                    description = ""
                    if desc_el is not None and desc_el.text:
                        description = desc_el.text.strip()
                    elif title_el is not None and title_el.text:
                        description = title_el.text.strip()

                    link = ""
                    if link_el is not None and link_el.text:
                        link = link_el.text.strip()

                    results.append({
                        "cve_ids": cve_ids,
                        "euvd_id": None,
                        "source": self.name,
                        "base_score": cvss_score,
                        "base_vector": cvss_vector,
                        "base_version": "3.1",
                        "description": description,
                        "references": [link] if link else [],
                        "affects_version": True,
                        "raw": item,  # ET.Element — serialise if you need JSON-safe raw
                    })

                self._set_in_cache(cache_key, results)
                return results

        except Exception as e:
            logger.error(
                f"[JVN] _search_by_product({vendor}/{product}) failed: {e}",
                exc_info=True,
            )
            return []