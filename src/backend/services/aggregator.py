"""Core aggregator service that orchestrates multiple vulnerability sources."""
import asyncio
import logging
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session

from core.logger import get_logger
from core.types import NormalizedVulnerabilityDict
from core.exceptions import SourceError
from core.config import settings
from models import CveItem, Description, Reference, CvssMetric, Node, CpeMatch
from sources.base import VulnerabilitySource
from sources.euvd import EUVDSource
from sources.osv import OSVSource
from sources.nvd import NVDSource
from sources.github import GitHubSource
from sources.jvn import JVNSource

logger = get_logger(__name__)


class Aggregator:
    """
    Orchestrates querying multiple vulnerability sources in priority order.
    
    Sources are tried in sequence:
    1. EUVD (European, primary enrichment)
    2. OSV (Open source fallback)
    3. NVD (Historical index, ID-only)
    4. GitHub (GitHub Security Advisories, if token configured)
    5. JVN (Japan Vulnerability Notes, additional data)
    
    Sources stop at first successful match with confirmed vulnerability for the version.
    """
    
    def __init__(self):
        """Initialize aggregator with vulnerability sources."""
        self._sources: List[VulnerabilitySource] = [
            EUVDSource(),
            OSVSource(),
            NVDSource(),
            GitHubSource(),
            JVNSource(),
        ]
        logger.info(f"Aggregator initialized with {len(self._sources)} sources: "
                   f"{', '.join(s.name for s in self._sources)}")
    
    @property
    def sources(self) -> List[VulnerabilitySource]:
        """Get list of sources in priority order."""
        return self._sources
    
    async def fetch_and_sync(self, cpe_name: str, db: Session, stop_on_confirmed: bool = True) -> Tuple[bool, int]:
        confirmed = False
        total_cves_added = 0

        for source in self._sources:
            logger.info(f"[Aggregator] Trying source: {source.name}")
            try:
                logger.debug(f"Querying {source.name} for {cpe_name}")
                results = await source.query(cpe_name)
            except SourceError as e:
                if e.retryable:
                    logger.warning(f"Retryable error from {source.name}: {e}")
                else:
                    logger.error(f"Fatal error from {source.name}: {e}")
                continue
            except Exception as e:
                logger.exception(f"Unexpected error from {source.name}: {e}")
                continue

            if not results:
                logger.debug(f"{source.name}: No results for {cpe_name}")
                continue

            vulnerable_results = [r for r in results if r.get("affects_version")]

            if not vulnerable_results:
                logger.info(
                    f"{source.name}: Product known, version not affected for {cpe_name}"
                )
                # Do NOT break here — other sources may have CVE data for this version
                continue

            for result in vulnerable_results:
                try:
                    added = self._write_normalized(result, db, original_cpe=cpe_name)
                    total_cves_added += added
                    confirmed = True
                except Exception as e:
                    logger.error(f"Failed to write result from {source.name}: {e}", exc_info=True)
                    db.rollback()
                    continue

            try:
                db.commit()
                logger.info(
                    f"✓ {source.name} VULNERABLE: {cpe_name} → "
                    f"{total_cves_added} CVEs added"
                )
            except Exception as e:
                db.rollback()
                logger.error(f"DB commit failed: {e}")
                return False, 0

            if stop_on_confirmed:
                break  # Only break once we've actually confirmed vulnerability

        # AI fallback: runs when no source confirmed a vulnerability
        if not confirmed:
            logger.info(f"[AI Fallback] Assessing {cpe_name}...")
            try:
                ai_results = await self._ai_assess_vulnerability(cpe_name)
                for result in ai_results:
                    try:
                        added = self._write_normalized(result, db, original_cpe=cpe_name)
                        total_cves_added += added
                        confirmed = True
                    except Exception as e:
                        logger.error(f"Failed to write AI result: {e}", exc_info=True)
                        db.rollback()
                        continue
                if confirmed:
                    try:
                        db.commit()
                        logger.info(
                            f"✓ [AI] VULNERABLE: {cpe_name} → {total_cves_added} assessments added"
                        )
                    except Exception as e:
                        db.rollback()
                        logger.error(f"DB commit failed for AI results: {e}")
            except Exception as e:
                logger.warning(f"AI assessment failed for {cpe_name}: {e}")
        elif not confirmed:
            logger.debug(f"[AI Fallback] Skipped for {cpe_name} — AI disabled in settings")

        if not confirmed:
            try:
                self._store_unknown_marker(cpe_name, db)
                logger.info(f"Unknown marker stored for {cpe_name}")
            except Exception as e:
                logger.warning(f"Failed to store unknown marker: {e}")
                db.rollback()

        return confirmed, total_cves_added
    
    async def fetch_bulk(
        self,
        cpe_list: List[str],
        db: Session
    ) -> Dict[str, Tuple[bool, int]]:
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
                output[cpe] = (False, 0)
        
        return output
    
    async def health_check(self) -> Dict[str, Dict[str, any]]:
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
                    "details": "OK" if healthy else "Connection failed",
                    "checked_at": datetime.utcnow(),
                }
            except Exception as e:
                results[source.name] = {
                    "healthy": False,
                    "details": str(e),
                    "checked_at": datetime.utcnow(),
                }
        
        return results
    
    # ========================================================================
    # AI Fallback Assessment
    # ========================================================================
    
    async def _ai_assess_vulnerability(self, cpe_name: str) -> List[NormalizedVulnerabilityDict]:
        """
        Use local DistilBERT model to predict CVSS score for a package.
        Returns synthesized vulnerability assessment if positive.
        """
        try:
            from cvss_prediction.cvss_prediction import predict_cvss
        except ImportError as e:
            logger.warning(f"[AI] Local model not installed or error loading it: {e}")
            return []
        
        try:
            # We don't have a full description anymore since Ollama is gone, 
            # so we provide a generic description based on the CPE name for the model.
            generic_description = f"Security vulnerability in {cpe_name}."
            
            logger.debug(f"[AI] Predicting CVSS for {cpe_name} using local model...")
            
            # Predict the CVSS score using our local model
            cvss_score = float(predict_cvss(generic_description))
            logger.info(f"[AI] {cpe_name}: Predicted CVSS Score: {cvss_score}")
            
            # Return synthesized result
            return [{
                "cve_ids": [f"AI-{cpe_name.replace(':', '-')}"],
                "description": f"[Local AI Assessment] Potential vulnerability in {cpe_name}. Estimated severity score: {cvss_score}",
                "affects_version": True,
                "cvss_score": cvss_score,
                "cvss_vector": None,
                "source": "Local-CVSS-Model",
                "euvd_id": None,
            }]
        
        except Exception as e:
            logger.warning(f"[AI] Assessment failed for {cpe_name}: {e}")
            return []
    
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

            if original_cpe and not db.query(CpeMatch).filter(
                CpeMatch.node_id == node_obj.id,
                CpeMatch.criteria == original_cpe
            ).first():
                db.add(CpeMatch(
                    node_id=node_obj.id,
                    vulnerable=True,
                    criteria=original_cpe,
                ))
        
        return cves_added
    
    def _store_unknown_marker(self, cpe_name: str, db: Session) -> None:
        """Store marker for unknown/not-vulnerable CPE."""
        marker_id = f"UNKNOWN:{cpe_name[:200]}"
        if db.query(CveItem).filter(CveItem.cve_id == marker_id).first():
            return
        
        try:
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
                criteria=cpe_name
            ))
            db.commit()
        except Exception as e:
            logger.error(f"Failed to store unknown marker for {cpe_name}: {e}")
            db.rollback()
            raise
