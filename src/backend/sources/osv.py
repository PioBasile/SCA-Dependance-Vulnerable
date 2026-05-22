"""OSV (Open Source Vulnerabilities) source implementation."""
import logging
from typing import List, Optional, Dict, Any
from core.config import make_client, OSV_API_BASE, settings
from core.types import NormalizedVulnerabilityDict
from core.logger import get_logger
from matching.cpe import parse_cpe, cpe_to_osv_package
from sources.base import VulnerabilitySource, CachingSourceMixin

logger = get_logger(__name__)


class OSVSource(VulnerabilitySource, CachingSourceMixin):
    """OSV source for open source vulnerability data."""

    @property
    def name(self) -> str:
        return "OSV"

    async def healthy(self) -> bool:
        """Check OSV API health."""
        async with make_client() as client:
            try:
                resp = await client.post(
                    OSV_API_BASE,
                    json={"package": {"name": "log4j", "ecosystem": "Maven"},
                          "version": "2.14.1"},
                    timeout=5.0
                )
                return resp.status_code == 200
            except Exception as e:
                logger.warning(f"[OSV] Health check failed: {e}")
                return False

    @staticmethod
    def _extract_version_range(vuln: dict) -> tuple[str | None, str | None]:
        """Return (version_start_including, version_end_excluding) from OSV vuln.

        Walks the first ECOSYSTEM or SEMVER range's events and returns the
        introduced/fixed pair. Returns (None, None) when no structured range
        is present.
        """
        for affected in vuln.get("affected", []):
            for rng in affected.get("ranges", []):
                if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue
                introduced: str | None = None
                for event in rng.get("events", []):
                    if "introduced" in event:
                        val = event["introduced"]
                        introduced = None if val == "0" else val
                    elif "fixed" in event:
                        return introduced, event["fixed"]
                return introduced, None
        return None, None

    async def query(self, cpe: str) -> List[NormalizedVulnerabilityDict]:
        """Query OSV for vulnerabilities affecting a CPE."""
        try:
            parsed = parse_cpe(cpe)
            version = parsed["version"]
            package = await cpe_to_osv_package(cpe)

            if not package:
                logger.info(f"[OSV] No OSV package mapping for {cpe}")
                return []

            async with make_client() as client:
                resp = await client.post(
                    OSV_API_BASE,
                    json={"package": package, "version": version},
                    timeout=15.0
                )
                resp.raise_for_status()
                vulns = resp.json().get("vulns", [])
                results: List[NormalizedVulnerabilityDict] = []

                for vuln in vulns:
                    cve_ids = []
                    vuln_id = vuln.get("id", "")
                    if vuln_id.startswith("CVE-"):
                        cve_ids.append(vuln_id)
                    for alias in vuln.get("aliases", []):
                        if alias.startswith("CVE-") and alias not in cve_ids:
                            cve_ids.append(alias)

                    # OSV already confirmed this version is affected
                    if cve_ids:
                        v_start, v_end = self._extract_version_range(vuln)
                        results.append({
                            "cve_ids": cve_ids,
                            "euvd_id": None,
                            "source": self.name,
                            "base_score": None,  # Enriched later via EUVD
                            "base_vector": None,
                            "base_version": "3.1",
                            "description": vuln.get("summary", ""),
                            "references": [r.get("url", "") for r in vuln.get("references", []) if r.get("url")],
                            "affects_version": True,  # OSV confirms it
                            "version_start_including": v_start,
                            "version_end_excluding": v_end,
                            "raw": vuln,
                        })

                logger.info(f"[OSV] Found {len(results)} vulnerabilities for {cpe}")
                return results

        except Exception as e:
            logger.warning(f"[OSV] query({cpe}) failed: {e}")
            return []