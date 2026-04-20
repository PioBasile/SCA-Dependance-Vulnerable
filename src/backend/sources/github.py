"""GitHub Advisory Database source — uses REST API, not GraphQL."""
import logging
from matching.cpe import parse_cpe, cpe_to_osv_package
from matching.version import version_is_affected
from config import make_client, GITHUB_TOKEN
from sources.base import VulnerabilitySource

logger = logging.getLogger(__name__)

# REST endpoint 
GITHUB_ADVISORY_REST = "https://api.github.com/advisories"

class GitHubSource(VulnerabilitySource):

    @property
    def name(self) -> str:
        return "GitHub"

    def _get_headers(self) -> dict:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        return headers

    async def healthy(self) -> bool:
        async with make_client() as client:
            try:
                resp = await client.get(
                    "https://api.github.com/rate_limit",
                    headers=self._get_headers(),
                    timeout=5.0
                )
                return resp.status_code == 200
            except Exception as e:
                logger.warning(f"[GitHub] Health check failed: {e}")
                return False

    def _resolve_package(self, cpe: str) -> str | None:
        return cpe_to_osv_package(cpe)

    def _check_version_affected(self, advisory: dict, target_version: str) -> bool:
        """
        Check if target_version falls in any vulnerable range in the advisory.
        GitHub REST response structure:
          vulnerabilities[].vulnerable_version_range  e.g. ">= 2.0.0, < 2.15.0"
          vulnerabilities[].first_patched_version     e.g. "2.15.0"
        """
        for vuln in advisory.get("vulnerabilities", []):
            vvr = vuln.get("vulnerable_version_range", "")
            if not vvr:
                return True  # no range info → assume affected

            # GitHub uses comma-separated constraints like ">= 2.0.0, < 2.15.0"
            # We need to check all constraints are satisfied
            constraints = [c.strip() for c in vvr.split(",")]
            all_match   = True

            for constraint in constraints:
                if not version_is_affected(constraint, target_version):
                    all_match = False
                    break

            if all_match:
                return True

        return False

    async def query(self, cpe: str) -> list[dict]:
        parsed         = parse_cpe(cpe)
        target_version = parsed["version"]
        package_name   = self._resolve_package(cpe)

        if not package_name:
            logger.debug(f"[GitHub] No package mapping for {cpe}")
            return []

        logger.info(f"[GitHub] Querying: ecosystem=maven package={package_name}")

        async with make_client() as client:
            try:
                
                resp = await client.get(
                    GITHUB_ADVISORY_REST,
                    params={
                        "ecosystem":    "maven",
                        "package":      package_name,
                        "per_page":     100,
                        "type":         "reviewed",  # only human-reviewed advisories
                    },
                    headers=self._get_headers(),
                    timeout=15.0,
                )

                if resp.status_code == 401:
                    logger.warning("[GitHub] 401 — token missing or invalid")
                    return []
                if resp.status_code == 403:
                    logger.warning("[GitHub] 403 — rate limited")
                    return []
                if resp.status_code != 200:
                    logger.warning(f"[GitHub] HTTP {resp.status_code} for {package_name}: {resp.text[:200]}")
                    return []

                advisories = resp.json()
                if not isinstance(advisories, list):
                    logger.warning(f"[GitHub] Unexpected response format: {type(advisories)}")
                    return []

                results = []
                for advisory in advisories:
                    affected = self._check_version_affected(advisory, target_version)

                    # Extract CVE IDs from identifiers list
                    cve_ids = [
                        i["value"] for i in advisory.get("identifiers", [])
                        if i.get("type") == "CVE"
                    ]
                    # Also check top-level cve_id field
                    if advisory.get("cve_id") and advisory["cve_id"] not in cve_ids:
                        cve_ids.append(advisory["cve_id"])

                    if not cve_ids:
                        # Use GHSA ID as fallback identifier
                        ghsa = advisory.get("ghsa_id")
                        if ghsa:
                            cve_ids = [ghsa]

                    cvss     = advisory.get("cvss", {}) or {}
                    severity = advisory.get("severity", "")

                    # Map severity to approximate score if no CVSS
                    score_map = {"critical": 9.5, "high": 7.5, "moderate": 5.0, "low": 2.0}
                    base_score = (cvss.get("score")
                                  or score_map.get(severity.lower()))

                    results.append({
                        "cve_ids":         cve_ids,
                        "euvd_id":         None,
                        "source":          self.name,
                        "base_score":      base_score,
                        "base_vector":     cvss.get("vector_string"),
                        "base_version":    "3.1",
                        "description":     advisory.get("summary", ""),
                        "references":      advisory.get("references", []),
                        "affects_version": affected,
                        "raw":             advisory,
                    })

                matched = [r for r in results if r["affects_version"]]
                logger.info(
                    f"[GitHub] {package_name}: {len(advisories)} advisories, "
                    f"{len(matched)} affect v{target_version}"
                )
                return results

            except Exception as e:
                logger.info(f"[GitHub] query({cpe}) failed: {e}", exc_info=True)
                return []