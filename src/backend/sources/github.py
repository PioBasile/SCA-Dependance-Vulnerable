"""GitHub Advisory Database source — uses REST API, not GraphQL."""
from core.config import GITHUB_TOKEN, make_client
from core.logger import get_logger
from matching.cpe import cpe_to_osv_package, parse_cpe
from matching.version import _parse_version_safe, version_is_affected
from sources.base import VulnerabilitySource

logger = get_logger(__name__)

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

    async def _resolve_package(self, cpe: str) -> str | None:
        """Return ``"groupId:artifactId"`` for Maven CPEs, else ``None``."""
        pkg = await cpe_to_osv_package(cpe)
        if not pkg:
            return None
        if (pkg.get("ecosystem") or "").lower() != "maven":
            return None
        return pkg.get("name")

    def _check_version_affected(
        self, advisory: dict, target_version: str, package_name: str
    ) -> bool:
        """
        Return True only if some advisory entry confirms ``target_version``
        is in scope for ``package_name``.

        GitHub REST response structure (per advisory):
            vulnerabilities[].package = {"ecosystem": "maven", "name": "..."}
            vulnerabilities[].vulnerable_version_range  e.g. ">= 2.0.0, < 2.15.0"
            vulnerabilities[].first_patched_version     e.g. "2.15.0"

        We require:
          1. the entry's package matches our queried Maven artifact;
          2. ``first_patched_version`` (when present) is *strictly greater* than
             ``target_version`` — otherwise the lib is already patched;
          3. every comma-separated clause in ``vulnerable_version_range`` holds.
        Empty ranges no longer auto-match — without a range we can't claim a
        specific version is affected.
        """
        target = _parse_version_safe(target_version)
        wanted = (package_name or "").lower()

        for vuln in advisory.get("vulnerabilities", []):
            pkg = vuln.get("package") or {}
            if (pkg.get("ecosystem") or "").lower() != "maven":
                continue
            if wanted and (pkg.get("name") or "").lower() != wanted:
                continue

            patched = _parse_version_safe(vuln.get("first_patched_version") or "")
            if patched and target and target >= patched:
                continue  # already on or past the fix

            vvr = (vuln.get("vulnerable_version_range") or "").strip()
            if not vvr:
                continue

            clauses = [c.strip() for c in vvr.split(",") if c.strip()]
            if clauses and all(version_is_affected(c, target_version) for c in clauses):
                return True

        return False

    @staticmethod
    def _extract_version_range(advisory: dict, package_name: str) -> tuple[str | None, str | None]:
        """Return (version_start_including, version_end_excluding) for package_name.

        Uses ``first_patched_version`` as the end-exclusive bound and parses
        ``>= X`` from ``vulnerable_version_range`` as the start-inclusive bound.
        """
        wanted = (package_name or "").lower()
        for vuln in advisory.get("vulnerabilities", []):
            pkg = vuln.get("package") or {}
            if wanted and (pkg.get("name") or "").lower() != wanted:
                continue

            end_excl = vuln.get("first_patched_version") or None
            start_incl: str | None = None
            vvr = (vuln.get("vulnerable_version_range") or "").strip()
            for clause in vvr.split(","):
                clause = clause.strip()
                if clause.startswith(">="):
                    start_incl = clause[2:].strip() or None
                    break
            return start_incl, end_excl
        return None, None

    async def query(self, cpe: str) -> list[dict]:
        parsed         = parse_cpe(cpe)
        target_version = parsed["version"]
        package_name   = await self._resolve_package(cpe)

        if not package_name:
            logger.debug(f"[GitHub] No package mapping for {cpe}")
            return []

        logger.info(f"[GitHub] Querying: ecosystem=maven package={package_name}")

        async with make_client() as client:
            try:
                
                resp = await client.get(
                    GITHUB_ADVISORY_REST,
                    params={
                        "ecosystem": "maven",
                        # ``affects`` is the actual filter — ``package`` is a
                        # documented field but the REST API silently ignores it.
                        "affects": package_name,
                        "per_page": 100,
                        "type": "reviewed",  # only human-reviewed advisories
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
                    affected = self._check_version_affected(
                        advisory, target_version, package_name
                    )

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

                    v_start, v_end = self._extract_version_range(advisory, package_name)
                    results.append({
                        "cve_ids":                cve_ids,
                        "euvd_id":                None,
                        "source":                 self.name,
                        "base_score":             base_score,
                        "base_vector":            cvss.get("vector_string"),
                        "base_version":           "3.1",
                        "description":            advisory.get("summary", ""),
                        "references":             advisory.get("references", []),
                        "affects_version":        affected,
                        "version_start_including": v_start,
                        "version_end_excluding":   v_end,
                        "raw":                    advisory,
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