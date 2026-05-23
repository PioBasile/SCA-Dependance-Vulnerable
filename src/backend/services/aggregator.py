"""Core aggregator service that orchestrates multiple vulnerability sources."""
import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from core.config import settings
from core.exceptions import SourceError
from core.logger import get_logger
from core.types import NormalizedVulnerabilityDict
from sqlalchemy import Float, cast, desc as sql_desc
from models import CpeMatch, CveItem, CvssMetric, Description, Node, Reference
from sources.base import VulnerabilitySource
from sources.euvd import EUVDSource
from sources.github import GitHubSource
from sources.nvd import NVDSource
from sources.osv import OSVSource

logger = get_logger(__name__)


class Aggregator:
    """Orchestrates querying multiple vulnerability sources in parallel.

    Primary sources run concurrently for every CPE query:
      1. EUVD    — European database, primary enrichment
      2. OSV     — Open Source Vulnerabilities
      3. NVD     — National Vulnerability Database (CPE→CVE index)
      4. GitHub  — GitHub Security Advisories

    All confirmed results are merged and written to the database. EUVD is then
    queried by CVE-ID for any records that lack EUVD metadata (euvd_id,
    base_score, description).

      5. AI      — local CVSS-prediction model — runs only when all four
                   primary sources return nothing and ``settings.ai.enabled``
                   is true. It never confirms a CVE; it emits a severity hint.
    """

    def __init__(self):
        self._euvd = EUVDSource()
        self._sources: List[VulnerabilitySource] = [
            self._euvd,
            OSVSource(),
            NVDSource(),
            GitHubSource(),
        ]
        logger.info(
            "Aggregator initialized with %d sources: %s",
            len(self._sources),
            ", ".join(s.name for s in self._sources),
        )
    
    async def fetch_and_sync(
        self, cpe_name: str, db: Session, stop_on_confirmed: bool = True,
    ) -> Tuple[bool, int, Optional[Dict[str, Any]]]:
        """Fan out to all primary sources in parallel, merge results, fall back to AI.

        Returns ``(confirmed, cves_added, ai_prediction)`` where
        ``ai_prediction`` is ``None`` (AI didn't run / not enabled / failed) or
        ``{"score": float, "vector": str | None}`` — a *severity hint*, never a
        confirmation. The frontend uses it to surface a third tier (yellow)
        between "no finding" (green) and "confirmed CVE" (red).

        ``stop_on_confirmed`` is kept for API compatibility but is no longer
        used — all primary sources always run concurrently.
        """
        confirmed = False
        total_cves_added = 0
        ai_prediction: Optional[Dict[str, Any]] = None
        confirmed_cve_ids: set[str] = set()

        # ── Step 1: fan out EUVD + OSV + NVD + GitHub concurrently ─────────
        primary_sources = self._sources

        async def _query_one(source: VulnerabilitySource):
            logger.info(f"[Aggregator] Querying source: {source.name}")
            try:
                return source.name, await source.query(cpe_name)
            except SourceError as e:
                if e.retryable:
                    logger.warning(f"Retryable error from {source.name}: {e}")
                else:
                    logger.error(f"Fatal error from {source.name}: {e}")
                return source.name, []
            except Exception as e:
                logger.exception(f"Unexpected error from {source.name}: {e}")
                return source.name, []

        source_results = await asyncio.gather(
            *[_query_one(s) for s in primary_sources]
        )

        # ── Step 2: collect confirmed (affects_version=True) results ────────
        all_confirmed: List[NormalizedVulnerabilityDict] = []
        corroborated_cves: set[str] = set()   # CVEs seen by ≥1 non-EUVD source
        for source_name, results in source_results:
            if not results:
                logger.debug(f"{source_name}: No results for {cpe_name}")
                continue
            vulnerable = [r for r in results if r.get("affects_version")]
            if not vulnerable:
                logger.info(
                    f"{source_name}: Product known, version not affected for {cpe_name}"
                )
                continue
            logger.info(
                f"[Aggregator] {source_name}: {len(vulnerable)} confirmed result(s)"
                f" for {cpe_name}"
            )
            all_confirmed.extend(vulnerable)
            for r in vulnerable:
                confirmed_cve_ids.update(r.get("cve_ids") or [])
                if source_name != "EUVD":
                    corroborated_cves.update(r.get("cve_ids") or [])

        # ── Step 2b: drop EUVD-exclusive CVEs not corroborated by any other source
        # EUVD has the lowest precision (~55%) due to broad version ranges.
        # OSV and GitHub together cover the same CVEs with near-perfect precision,
        # so a CVE found only by EUVD is far more likely to be a false positive
        # than a genuine gap. Dropping them cuts AGG FPs without hurting recall.
        filtered: List[NormalizedVulnerabilityDict] = []
        euvd_dropped = 0
        for r in all_confirmed:
            if r.get("source") == "EUVD":
                r_cves = set(r.get("cve_ids") or [])
                if r_cves and not (r_cves & corroborated_cves):
                    euvd_dropped += 1
                    continue
            filtered.append(r)
        if euvd_dropped:
            logger.info(
                f"[Aggregator] Dropped {euvd_dropped} EUVD-exclusive result(s) "
                f"not corroborated by OSV/NVD/GitHub for {cpe_name}"
            )
        all_confirmed = filtered
        # Recompute confirmed_cve_ids after filtering
        confirmed_cve_ids = {
            cve for r in all_confirmed for cve in (r.get("cve_ids") or [])
        }

        # ── Step 3: write merged results to DB ──────────────────────────────
        for result in all_confirmed:
            try:
                added = self._write_normalized(result, db, original_cpe=cpe_name)
                total_cves_added += added
                confirmed = True
            except Exception as e:
                logger.error(f"Failed to write result: {e}", exc_info=True)
                db.rollback()
                continue

        if confirmed:
            try:
                db.commit()
                logger.info(f"✓ {cpe_name} → {total_cves_added} CVEs added")
            except Exception as e:
                db.rollback()
                logger.error(f"DB commit failed: {e}")
                return False, 0, ai_prediction

            # Enrich CVEs that lack EUVD metadata (euvd_id, base_score, …).
            # _enrich_with_euvd self-filters: skips CVEs that already have euvd_id
            # (e.g. those found directly by EUVD in the parallel fan-out).
            if confirmed_cve_ids:
                await self._enrich_with_euvd(confirmed_cve_ids, db)
                await self._enrich_with_ai_scores(confirmed_cve_ids, db)

        # ── Step 4: AI — severity hint when all primary sources found nothing ──
        if not confirmed and settings.ai.enabled:
            ai_prediction = await self._predict_for_cpe(cpe_name, db)

        # ── Step 5: NOT_FOUND marker when nothing confirmed ──────────────────
        if not confirmed:
            try:
                self._store_unknown_marker(cpe_name, db)
                db.commit()
                logger.info(f"Unknown marker stored for {cpe_name}")
            except Exception as e:
                logger.warning(f"Failed to store unknown marker: {e}")
                db.rollback()

        return confirmed, total_cves_added, ai_prediction

    async def fetch_bulk(
        self,
        cpe_list: List[str],
        db: Session
    ) -> Dict[str, Tuple[bool, int, Optional[Dict[str, Any]]]]:
        """
        Query multiple CPEs concurrently.
        
        Args:
            cpe_list: List of CPE 2.3 strings
            db: Database session
        
        Returns:
            Dict mapping CPE → (found, count)
        """
        tasks = [self.fetch_and_sync(cpe, db) for cpe in cpe_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        output = {}
        for cpe, result in zip(cpe_list, results):
            if isinstance(result, tuple):
                output[cpe] = result
            else:
                logger.error(f"Error processing {cpe}: {result}")
                output[cpe] = (False, 0, None)
        
        return output
    
    async def health_check(self) -> Dict[str, Dict[str, Any]]:
        """
        Check health of all sources.

        Returns:
            Dict with health status for each source
        """
        results = {}
        for source in self._sources:
            try:
                healthy = await source.healthy()
                results[source.name] = {
                    "healthy": healthy,
                    "details": "OK" if healthy else "Unavailable",
                    "checked_at": datetime.utcnow(),
                }
            except Exception as e:
                results[source.name] = {
                    "healthy": False,
                    "details": str(e),
                    "checked_at": datetime.utcnow(),
                }

        # AI health: try importing the model (loads it if not already loaded)
        if settings.ai.enabled:
            try:
                from cvss_prediction.cvss_prediction import predict_cvss  # noqa: F401
                results["AI"] = {
                    "healthy": True,
                    "details": "Model loaded",
                    "checked_at": datetime.utcnow(),
                }
            except Exception as e:
                results["AI"] = {
                    "healthy": False,
                    "details": str(e),
                    "checked_at": datetime.utcnow(),
                }
        else:
            results["AI"] = {
                "healthy": False,
                "details": "Disabled (AI_FALLBACK_ENABLED=false)",
                "checked_at": datetime.utcnow(),
            }

        return results
    
    # ========================================================================
    # EUVD enrichment
    # ========================================================================

    async def _predict_for_cpe(self, cpe: str, db: Session) -> Optional[Dict[str, Any]]:
        """Predict a CVSS score for a CPE when no CVE was confirmed.

        Looks up the most severe stored description for vendor:product and
        runs it through the local DistilBERT model. Returns None on any failure.
        """
        parts = cpe.split(":")
        if len(parts) < 6:
            return None
        vendor, product, version = parts[3], parts[4], parts[5]
        if not version or version in ("*", "-") or "SNAPSHOT" in version.upper():
            return None
        if vendor == product:
            return None

        try:
            from cvss_prediction.cvss_prediction import predict_cvss
        except Exception as e:
            logger.debug(f"[AI] model unavailable: {e}")
            return None

        pattern = f"%:{vendor}:{product}:%"
        row = (
            db.query(Description.value)
            .join(Node, Node.cve_id == Description.cve_id)
            .join(CpeMatch, CpeMatch.node_id == Node.id)
            .outerjoin(CvssMetric, CvssMetric.cve_id == Description.cve_id)
            .filter(CpeMatch.criteria.ilike(pattern))
            .filter(Description.lang == "en")
            .filter(Description.value.isnot(None))
            .order_by(sql_desc(cast(CvssMetric.cvssData["baseScore"], Float)))
            .first()
        )
        if not row or not row[0]:
            logger.debug(f"[AI] no stored description for {vendor}:{product}, skipping")
            return None

        try:
            score = float(await asyncio.to_thread(predict_cvss, row[0]))
            logger.info(f"[AI] {cpe} → predicted CVSS {score:.1f}")
            return {"score": score, "vector": None}
        except Exception as e:
            logger.warning(f"[AI] prediction failed for {cpe}: {e}")
            return None

    async def _enrich_with_euvd(self, cve_ids: set[str], db: Session) -> None:
        """For each CVE id, fetch the matching EUVD record and back-fill any
        EUVD-only fields on the existing CveItem (``euvd_id``, base score,
        description, references). Failures are non-fatal.

        Skips CVEs that already carry an ``euvd_id`` (no work to do) and runs
        the remaining EUVD lookups concurrently with a bounded semaphore so a
        single 40-CVE advisory doesn't serialise into a minute of wall time.
        """
        # Filter out CVEs we've already enriched in a prior call — saves us
        # a network round-trip per duplicate.
        pending = [
            cve_id for cve_id in cve_ids
            if not (
                db.query(CveItem)
                  .filter(CveItem.cve_id == cve_id, CveItem.euvd_id.isnot(None))
                  .first()
            )
        ]
        if not pending:
            return

        sem = asyncio.Semaphore(8)

        async def _one(cve_id: str):
            async with sem:
                try:
                    return cve_id, await self._euvd.search_by_cve(cve_id)
                except Exception as e:
                    logger.warning(f"[Enrich] EUVD lookup failed for {cve_id}: {e}")
                    return cve_id, None

        fetched = await asyncio.gather(*[_one(c) for c in pending])

        added = 0
        for cve_id, item in fetched:
            if not item:
                continue

            cve = db.query(CveItem).filter(CveItem.cve_id == cve_id).first()
            if not cve:
                continue

            if not cve.euvd_id and item.get("id"):
                cve.euvd_id = item["id"]
                added += 1

            desc = (item.get("description") or "").strip()
            if desc and not db.query(Description).filter(
                Description.cve_id == cve_id, Description.lang == "en"
            ).first():
                db.add(Description(cve_id=cve_id, lang="en", value=desc))

            for url in (item.get("references") or "").split("\n"):
                url = url.strip()
                if not url:
                    continue
                if not db.query(Reference).filter(
                    Reference.cve_id == cve_id, Reference.url == url
                ).first():
                    db.add(Reference(cve_id=cve_id, url=url, source="EUVD", tags=[]))

            base_score = item.get("baseScore")
            if base_score is not None and not db.query(CvssMetric).filter(
                CvssMetric.cve_id == cve_id, CvssMetric.source == "EUVD"
            ).first():
                try:
                    score = float(base_score)
                except (ValueError, TypeError):
                    score = None
                if score is not None and 0 <= score <= 10:
                    db.add(CvssMetric(
                        cve_id=cve_id,
                        version=str(item.get("baseScoreVersion") or "3.1"),
                        cvssData={
                            "baseScore": score,
                            "vectorString": item.get("baseScoreVector"),
                            "version": item.get("baseScoreVersion", "3.1"),
                        },
                        source="EUVD",
                        type="Primary",
                    ))

        try:
            db.commit()
            if added:
                logger.info(f"[Enrich] EUVD enriched {added} CVE(s) with euvd_id")
        except Exception as e:
            db.rollback()
            logger.warning(f"[Enrich] commit failed: {e}")

    async def _enrich_with_ai_scores(self, cve_ids: set[str], db: Session) -> None:
        """Predict CVSS scores via local AI for CVEs that have no real score yet.

        Runs only when the AI source is enabled and the model is available.
        Predictions are stored with source="AI" so _max_score can prefer real
        scores over them and only fall back to AI when nothing else exists.
        """
        if not settings.ai.enabled:
            return

        # Find CVEs that still have no CVSS metric from a real source
        pending = [
            cve_id for cve_id in cve_ids
            if not db.query(CvssMetric).filter(
                CvssMetric.cve_id == cve_id,
                CvssMetric.source != "AI",
            ).first()
        ]
        if not pending:
            return

        try:
            from cvss_prediction.cvss_prediction import predict_cvss
        except Exception as e:
            logger.warning(f"[AI Enrich] model unavailable: {e}")
            return

        logger.info(f"[AI Enrich] {len(pending)} CVE(s) need a score: {pending}")
        added = 0
        for cve_id in pending:
            # Skip if we already stored an AI score for this CVE
            if db.query(CvssMetric).filter(
                CvssMetric.cve_id == cve_id, CvssMetric.source == "AI"
            ).first():
                logger.debug(f"[AI Enrich] {cve_id}: AI score already stored, skipping")
                continue

            desc_row = db.query(Description).filter(
                Description.cve_id == cve_id,
                Description.lang == "en",
            ).first()
            desc_text = desc_row.value if (desc_row and desc_row.value) else None

            if not desc_text:
                # Fallback: fetch description from EUVD by CVE ID
                try:
                    euvd_data = await self._euvd.search_by_cve(cve_id)
                    desc_text = (euvd_data or {}).get("description", "").strip() or None
                    if desc_text:
                        db.add(Description(cve_id=cve_id, lang="en", value=desc_text))
                        db.flush()
                        logger.debug(f"[AI Enrich] {cve_id}: got description from EUVD fallback")
                except Exception as e:
                    logger.debug(f"[AI Enrich] {cve_id}: EUVD fallback failed: {e}")

            if not desc_text:
                logger.warning(f"[AI Enrich] {cve_id}: no description anywhere, cannot predict")
                continue

            try:
                score = float(await asyncio.to_thread(predict_cvss, desc_text))
                logger.info(f"[AI Enrich] {cve_id} → predicted CVSS {score:.1f}")
                db.add(CvssMetric(
                    cve_id=cve_id,
                    version="3.1",
                    cvssData={"baseScore": score, "vectorString": None, "version": "3.1"},
                    source="AI",
                    type="Secondary",
                ))
                added += 1
            except Exception as e:
                logger.warning(f"[AI Enrich] prediction failed for {cve_id}: {e}")

        if added:
            try:
                db.commit()
                logger.info(f"[AI Enrich] predicted scores for {added} CVE(s)")
            except Exception as e:
                db.rollback()
                logger.warning(f"[AI Enrich] commit failed: {e}")

    async def _enrich_with_osv_ranges(
        self, cpe: str, cve_ids: set[str], db: Session
    ) -> None:
        """Backfill version ranges from OSV onto existing CpeMatch rows.

        EUVD never returns structured version bounds (versionStartIncluding /
        versionEndExcluding), but OSV does. Calling this after any source
        confirms a vulnerability fills that gap without running OSV on every
        single query — we only touch rows that still have NULL ranges.
        """
        osv = next((s for s in self._sources if s.name == "OSV"), None)
        if osv is None:
            return
        try:
            results = await osv.query(cpe)
        except Exception as e:
            logger.warning(f"[Enrich] OSV range lookup failed for {cpe}: {e}")
            return

        updated = 0
        for result in results:
            v_start = result.get("version_start_including")
            v_end = result.get("version_end_excluding")
            if not v_start and not v_end:
                continue
            for cve_id in result.get("cve_ids", []):
                if cve_id not in cve_ids:
                    continue
                node = db.query(Node).filter(Node.cve_id == cve_id).first()
                if not node:
                    continue
                match = db.query(CpeMatch).filter(
                    CpeMatch.node_id == node.id,
                    CpeMatch.criteria == cpe,
                ).first()
                if not match:
                    continue
                changed = False
                if v_start and not match.versionStartIncluding:
                    match.versionStartIncluding = v_start
                    changed = True
                if v_end and not match.versionEndExcluding:
                    match.versionEndExcluding = v_end
                    changed = True
                if changed:
                    updated += 1

        if updated:
            try:
                db.commit()
                logger.info(
                    "[Enrich] OSV backfilled version ranges on %d CpeMatch row(s) for %s",
                    updated, cpe,
                )
            except Exception as e:
                db.rollback()
                logger.warning(f"[Enrich] OSV range commit failed: {e}")

    # ========================================================================
    # Private Database Writing Methods
    # ========================================================================
    
    def _write_normalized(
        self,
        result: NormalizedVulnerabilityDict,
        db: Session,
        original_cpe: Optional[str] = None
    ) -> int:
        """Write normalized vulnerability data to database. Returns count of CVEs added."""
        cves_added = 0
        
        for cve_id in result.get("cve_ids", []):
            # Get or create CVE item
            cve = db.query(CveItem).filter(CveItem.cve_id == cve_id).first()
            if not cve:
                cve = CveItem(
                    cve_id=cve_id,
                    euvd_id=result.get("euvd_id"),
                    sourceIdentifier=result.get("source", "UNKNOWN"),
                    vulnStatus="PUBLISHED",
                    published=datetime.utcnow(),
                    lastModified=datetime.utcnow(),
                )
                db.add(cve)
                db.flush()
                cves_added += 1
            elif result.get("euvd_id") and not cve.euvd_id:
                cve.euvd_id = result["euvd_id"]

            # Add description if not exists
            desc = result.get("description", "").strip()
            if desc:
                if not db.query(Description).filter(
                    Description.cve_id == cve_id,
                    Description.lang == "en"
                ).first():
                    db.add(Description(cve_id=cve_id, lang="en", value=desc))

            # Add references
            for url in result.get("references", []):
                url = url.strip()
                if url and not db.query(Reference).filter(
                    Reference.cve_id == cve_id,
                    Reference.url == url
                ).first():
                    db.add(Reference(
                        cve_id=cve_id,
                        url=url,
                        source=result.get("source", ""),
                        tags=[]
                    ))

            # Add CVSS metric if valid
            base_score = result.get("base_score")
            if base_score is not None:
                try:
                    score_float = float(base_score)
                    if 0 <= score_float <= 10:
                        if not db.query(CvssMetric).filter(
                            CvssMetric.cve_id == cve_id,
                            CvssMetric.source == result.get("source")
                        ).first():
                            db.add(CvssMetric(
                                cve_id=cve_id,
                                version=str(result.get("base_version") or "3.1"),
                                cvssData={
                                    "baseScore": score_float,
                                    "vectorString": result.get("base_vector"),
                                    "version": result.get("base_version", "3.1"),
                                },
                                exploitabilityScore=None,
                                impactScore=None,
                                source=result.get("source", ""),
                                type="Primary",
                            ))
                except (ValueError, TypeError):
                    logger.warning(f"Invalid base_score for {cve_id}: {base_score}")

            # Add/update node and CPE match
            node_obj = db.query(Node).filter(Node.cve_id == cve_id).first()
            if not node_obj:
                node_obj = Node(cve_id=cve_id, operator="OR", negate=False)
                db.add(node_obj)
                db.flush()

            if original_cpe:
                existing_match = db.query(CpeMatch).filter(
                    CpeMatch.node_id == node_obj.id,
                    CpeMatch.criteria == original_cpe,
                ).first()
                if existing_match:
                    existing_match.scanned_at = datetime.utcnow()
                    if result.get("version_end_excluding") and not existing_match.versionEndExcluding:
                        existing_match.versionEndExcluding = result["version_end_excluding"]
                    if result.get("version_start_including") and not existing_match.versionStartIncluding:
                        existing_match.versionStartIncluding = result["version_start_including"]
                    if result.get("version_end_including") and not existing_match.versionEndIncluding:
                        existing_match.versionEndIncluding = result["version_end_including"]
                    if result.get("version_start_excluding") and not existing_match.versionStartExcluding:
                        existing_match.versionStartExcluding = result["version_start_excluding"]
                else:
                    db.add(CpeMatch(
                        node_id=node_obj.id,
                        vulnerable=True,
                        criteria=original_cpe,
                        versionStartIncluding=result.get("version_start_including"),
                        versionEndExcluding=result.get("version_end_excluding"),
                        versionStartExcluding=result.get("version_start_excluding"),
                        versionEndIncluding=result.get("version_end_including"),
                        scanned_at=datetime.utcnow(),
                    ))
        
        return cves_added
    
    def _store_unknown_marker(self, cpe_name: str, db: Session) -> None:
        """Store (or refresh) a NOT_FOUND marker for a CPE.

        Updating ``scanned_at`` on the existing marker resets its TTL so
        ``is_recently_not_found`` returns True and we skip re-querying sources
        on the next request within the TTL window.
        """
        marker_id = f"UNKNOWN:{cpe_name[:200]}"
        existing = db.query(CveItem).filter(CveItem.cve_id == marker_id).first()
        if existing:
            node_obj = db.query(Node).filter(Node.cve_id == marker_id).first()
            if node_obj:
                match = db.query(CpeMatch).filter(CpeMatch.node_id == node_obj.id).first()
                if match:
                    match.scanned_at = datetime.utcnow()
            return

        cve = CveItem(
            cve_id=marker_id,
            sourceIdentifier="UNKNOWN",
            vulnStatus="NOT_FOUND",
            published=datetime.utcnow(),
            lastModified=datetime.utcnow(),
        )
        db.add(cve)
        db.flush()

        node_obj = Node(cve_id=marker_id, operator="OR", negate=False)
        db.add(node_obj)
        db.flush()

        db.add(CpeMatch(
            node_id=node_obj.id,
            vulnerable=False,
            criteria=cpe_name,
            scanned_at=datetime.utcnow(),
        ))
