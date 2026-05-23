"""NVD (National Vulnerability Database) source implementation."""
import logging
import asyncio
import re
from typing import List, Dict, Tuple, Optional
from core.config import make_client, NVD_API_BASE, NVD_API_KEY, settings
from core.types import NormalizedVulnerabilityDict
from core.logger import get_logger
from matching.cpe import parse_cpe
from matching.version import _parse_version_safe
from sources.base import VulnerabilitySource, CachingSourceMixin, RateLimitedSourceMixin

logger = get_logger(__name__)

NVD_CPE_MAP: dict[tuple, tuple] = {
    ("apache", "log4j-core"):   ("apache", "log4j2"),
    ("apache", "log4j-api"):    ("apache", "log4j2"),
    ("apache", "struts2-core"): ("apache", "struts"),
    ("com.fasterxml.jackson.core", "jackson-databind"): ("fasterxml", "jackson-databind"),
    ("commons-collections", "commons-collections"):     ("apache", "commons_collections"),
    ("apache", "commons-text"):  ("apache", "commons_text"),
    ("snakeyaml", "snakeyaml"):  ("snakeyaml_project", "snakeyaml"),
    ("org.yaml",  "snakeyaml"):  ("snakeyaml_project", "snakeyaml"),
    ("com.h2database", "h2"):    ("h2database", "h2"),
    ("hibernate-core", "hibernate-core"): ("redhat", "hibernate_orm"),
    ("org.hibernate",  "hibernate-core"): ("redhat", "hibernate_orm"),
    ("com.thoughtworks.xstream", "xstream"): ("xstream_project", "xstream"),
    ("com.alibaba", "fastjson"): ("alibaba", "fastjson"),
    ("com.google.guava", "guava"): ("google", "guava"),
    ("netty-all",    "netty-all"):    ("netty", "netty"),
    ("netty-buffer", "netty-buffer"): ("netty", "netty"),
    ("io.netty",     "netty-all"):    ("netty", "netty"),
    ("org.eclipse.jetty", "jetty-server"): ("eclipse", "jetty"),
    ("apache",                  "tomcat-embed-core"): ("apache", "tomcat"),
    ("org.apache.tomcat.embed", "tomcat-embed-core"): ("apache", "tomcat"),
    ("apache",      "shiro-core"): ("apache", "shiro"),
    ("org.springframework", "spring-webmvc"): ("pivotal_software", "spring_framework"),
    ("spring-cloud-function-context", "spring-cloud-function-context"): ("pivotal_software", "spring_cloud_function"),
    ("spring-cloud-gateway-server",   "spring-cloud-gateway-server"):   ("pivotal_software", "spring_cloud_gateway"),
    ("org.bouncycastle", "bcprov-jdk15on"): ("bouncycastle", "bouncy-castle-crypto-package"),
    ("org.bouncycastle", "bcprov-jdk18on"): ("bouncycastle", "bouncy-castle-crypto-package"),
}


class NVDSource(VulnerabilitySource, CachingSourceMixin, RateLimitedSourceMixin):
    """
    NVD is used ONLY as a CPE→CVE ID index.
    No vulnerability data is taken from NVD — we only extract CVE IDs,
    then enrich them via EUVD.
    """

    # NVD allows 50 req / 30 s with an API key (≈600 ms each) and only
    # 5 req / 30 s without. Spacing requests prevents the 403 → 5 s sleep
    # spiral that wrecked benchmark tail latencies.
    REQUEST_DELAY = 0.6

    @property
    def name(self) -> str:
        return "NVD"

    async def healthy(self) -> bool:
        """Check NVD API health."""
        async with make_client() as client:
            try:
                # Querying a specific, known CVE is much lighter on NVD's DB 
                # than requesting a generic page of results.
                headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
                resp = await client.get(
                    NVD_API_BASE,
                    params={"cveId": "CVE-2021-44228"},
                    headers=headers,
                    timeout=10.0
                )
                is_healthy = resp.status_code < 500
                if not is_healthy:
                    logger.warning(f"[NVD] Health check failed: status {resp.status_code}")
                return is_healthy
            except Exception as e:
                logger.warning(f"[NVD] Health check failed: {e}")
                return False

    # Maven ecosystem appends classifiers like -jre, -android, -lts to the
    # version component that NVD's CPE dictionary never includes. Strip them
    # so "32.0-jre" becomes "32.0" and matches NVD's "google:guava:32.0" entry.
    _VERSION_QUALIFIER_RE = re.compile(r"-(jre|android|lts|jdk\d*)\d*$", re.IGNORECASE)

    def _normalize_cpe(self, cpe: str) -> List[str]:
        """Normalize CPE to try multiple variants from mapping table."""
        parts = cpe.split(":")
        vendor = parts[3] if len(parts) > 3 else ""
        product = parts[4] if len(parts) > 4 else ""
        version = parts[5] if len(parts) > 5 else "*"

        # Strip Maven version qualifiers NVD doesn't know about (e.g. 32.0-jre → 32.0)
        version = self._VERSION_QUALIFIER_RE.sub("", version)

        candidates = []
        has_explicit = False
        key = (vendor, product)
        if key in NVD_CPE_MAP:
            v, p = NVD_CPE_MAP[key]
            candidates.append(f"cpe:2.3:a:{v}:{p}:{version}:*:*:*:*:*:*:*")
            has_explicit = True

        short_vendor = vendor.split(".")[-1] if "." in vendor else vendor
        short_key = (short_vendor, product)
        if short_key in NVD_CPE_MAP and short_key != key:
            v, p = NVD_CPE_MAP[short_key]
            candidates.append(f"cpe:2.3:a:{v}:{p}:{version}:*:*:*:*:*:*:*")
            has_explicit = True

        # Only fall back to the raw CPE when no explicit mapping exists.
        # When a mapping is known, the raw Maven-style vendor (e.g.
        # "com.google.guava") is never in NVD's CPE dictionary — querying it
        # just wastes a full NVD round-trip (~13 s).
        if not has_explicit:
            candidates.append(cpe)

        seen, result = set(), []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                result.append(c)
        return result

    def _version_in_range(self, nvd_vuln: dict, target: str) -> bool:
        """Check if the target version falls within the vulnerable ranges."""
        try:
            t = _parse_version_safe(target)
            for config in nvd_vuln.get("cve", {}).get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if not match.get("vulnerable"):
                            continue
                        if not t:
                            return target.lower() in match.get("criteria", "").lower()

                        si = _parse_version_safe(match.get("versionStartIncluding", ""))
                        se = _parse_version_safe(match.get("versionStartExcluding", ""))
                        ei = _parse_version_safe(match.get("versionEndIncluding", ""))
                        ee = _parse_version_safe(match.get("versionEndExcluding", ""))

                        if si and t < si: continue
                        if se and t <= se: continue
                        if ee and t >= ee: continue
                        if ei and t > ei:  continue
                        return True
        except Exception:
            pass
        return False

    async def get_cve_ids(self, cpe: str) -> Dict[str, str]:
        """Query NVD for CVEs affecting a CPE.

        Returns a dict of {cve_id: english_description} for all affected CVEs.
        Description is empty string when NVD doesn't provide one.
        """
        cache_key = self._get_cache_key("nvd_cve_ids", cpe)
        cached = self._get_from_cache(cache_key)
        if cached is not None:
            return cached

        try:
            parsed = parse_cpe(cpe)
            target_version = parsed["version"]

            # NVD uses real vendor names from its own CPE dictionary. Syft-style
            # CPEs where vendor==product (e.g. micrometer-core:micrometer-core)
            # never appear in NVD — skip immediately to avoid a 20-second timeout.
            if parsed["vendor"] == parsed["product"] and parsed["vendor"] not in NVD_CPE_MAP:
                logger.debug(f"[NVD] skipping {cpe}: vendor==product not in NVD CPE map")
                return {}

            headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
            cpe_variants = self._normalize_cpe(cpe)

            async with make_client() as client:
                for cpe_try in cpe_variants:
                    await self._apply_rate_limit()

                    try:
                        resp = await client.get(
                            NVD_API_BASE,
                            params={"cpeName": cpe_try, "resultsPerPage": 100},
                            headers=headers,
                            timeout=20.0,
                        )

                        if resp.status_code == 403:
                            logger.warning(f"[NVD] Rate limited (403) on variant {cpe_try}. Sleeping...")
                            await asyncio.sleep(5)
                            continue

                        resp.raise_for_status()
                        vulns = resp.json().get("vulnerabilities", [])

                        result: Dict[str, str] = {}
                        for v in vulns:
                            cve_data = v.get("cve", {})
                            cve_id = cve_data.get("id", "")
                            if not cve_id or not self._version_in_range(v, target_version):
                                continue
                            # Extract English description — NVD always includes it
                            desc = ""
                            for d in cve_data.get("descriptions", []):
                                if d.get("lang") == "en":
                                    desc = d.get("value", "")
                                    break
                            result[cve_id] = desc

                        if result:
                            logger.info(f"[NVD] Found {len(result)} CVEs for {cpe_try}")
                            self._set_in_cache(cache_key, result)
                            return result

                    except Exception as e:
                        logger.warning(f"[NVD] Variant {cpe_try} failed: {e}")
                        continue

            self._set_in_cache(cache_key, {})
            return {}

        except Exception as e:
            logger.error(f"[NVD] get_cve_ids({cpe}) failed: {e}", exc_info=True)
            return {}

    async def query(self, cpe: str) -> List[NormalizedVulnerabilityDict]:
        """NVD query: returns CVE stubs with descriptions extracted from the NVD response."""
        try:
            cve_map = await self.get_cve_ids(cpe)
            results: List[NormalizedVulnerabilityDict] = [
                {
                    "cve_ids": [cve_id],
                    "euvd_id": None,
                    "source": self.name,
                    "base_score": None,
                    "base_vector": None,
                    "base_version": "3.1",
                    "description": desc,
                    "references": [],
                    "affects_version": True,
                    "raw": {},
                }
                for cve_id, desc in cve_map.items()
            ]
            if results:
                logger.info(f"[NVD] Returning {len(results)} vulnerabilities for {cpe}")
            return results
        except Exception as e:
            logger.error(f"[NVD] query({cpe}) failed: {e}", exc_info=True)
            return []