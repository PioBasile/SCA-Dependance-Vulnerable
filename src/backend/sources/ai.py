"""Local CVSS-prediction model exposed as a vulnerability source.

This is the project's *last-resort* signal: it never claims to know which CVE
applies to a CPE — it just runs a fine-tuned DistilBERT against the CPE name
and emits a synthesized advisory carrying the predicted CVSS vector/score.

The aggregator places it last so it only runs when EUVD/OSV/NVD/GitHub all
came up empty *and* ``settings.ai.enabled`` is true.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from core.config import settings
from core.logger import get_logger
from core.types import NormalizedVulnerabilityDict
from sources.base import VulnerabilitySource

from typing import Optional

logger = get_logger(__name__)

_MODEL_PATH = Path(__file__).resolve().parent.parent / "cvss_prediction" / "model" / "cvss_model.pt"


def _load_predictor():
    """Lazy import — the heavy torch/transformers stack only loads when used."""
    try:
        from cvss_prediction.cvss_prediction import predict_cvss  # noqa: WPS433
        return predict_cvss
    except Exception as e:  # ModuleNotFoundError, RuntimeError on bad weights, etc.
        logger.warning(f"[AI] CVSS model unavailable: {e}")
        return None


def _description_for_product(vendor: str, product: str) -> Optional[str]:
    """Return any English CVE description we have stored for this vendor:product.

    Looks for the most-severe CVE first (highest base score) so the model sees
    a representative description rather than a low-impact one. Walks through
    ``CpeMatch.criteria`` to find any CVE whose CPE contains ``:vendor:product:``.
    Returns ``None`` on miss or error — the caller falls back to a placeholder.
    """
    if not vendor or not product:
        return None
    try:
        from sqlalchemy import desc as sql_desc

        from models import CpeMatch, CvssMetric, Description, Node, SessionLocal

        pattern = f"%:{vendor}:{product}:%"
        with SessionLocal() as db:
            row = (
                db.query(Description.value)
                .join(Node, Node.cve_id == Description.cve_id)
                .join(CpeMatch, CpeMatch.node_id == Node.id)
                .outerjoin(CvssMetric, CvssMetric.cve_id == Description.cve_id)
                .filter(CpeMatch.criteria.ilike(pattern))
                .filter(Description.lang == "en")
                .filter(Description.value.isnot(None))
                .order_by(sql_desc(CvssMetric.id))  # most-recent metric → typically highest-severity CVE
                .first()
            )
            if row and row[0]:
                text = row[0].strip()
                logger.info(
                    f"[AI] using stored description for {vendor}:{product} "
                    f"({len(text)} chars)"
                )
                return text
    except Exception as e:
        logger.warning(f"[AI] description lookup failed for {vendor}:{product}: {e}")
    return None


class LocalAISource(VulnerabilitySource):
    """Last-resort source backed by a local DistilBERT CVSS predictor."""

    def __init__(self) -> None:
        self._predict = None  # populated on first use

    @property
    def name(self) -> str:
        return "AI"

    async def healthy(self) -> bool:
        if not _MODEL_PATH.exists() or _MODEL_PATH.stat().st_size == 0:
            return False
        if self._predict is None:
            self._predict = _load_predictor()
        return self._predict is not None

    async def query(self, cpe: str) -> List[NormalizedVulnerabilityDict]:
        if not settings.ai.enabled:
            return []

        # Skip AI for inputs where a prediction has no real meaning:
        #   - ``-SNAPSHOT`` versions (private dev builds, never published)
        #   - wildcard / blank versions (we don't know what's installed)
        #   - malformed CPEs where vendor == product (syft fallback; not a
        #     real Maven coordinate)
        # Without these guards every "unknown" component gets a yellow
        # "AI: 9.8" hint, drowning real findings in noise.
        parts = cpe.split(":")
        if len(parts) < 6:
            return []
        vendor, product, version = parts[3], parts[4], parts[5]
        if not version or version in ("*", "-") or "SNAPSHOT" in version.upper():
            return []
        if vendor == product:
            return []

        if self._predict is None:
            self._predict = _load_predictor()
        if self._predict is None:
            return []

        # Prefer a real CVE description we've already stored for the same
        # vendor:product (any version) — it gives the model a discriminating
        # input instead of the constant placeholder. Fall back to the
        # placeholder when no description is available.
        real_description = _description_for_product(vendor, product)
        if real_description:
            prompt = real_description
            prompt_origin = "stored CVE description"
        else:
            prompt = f"Security vulnerability in {cpe}."
            prompt_origin = "placeholder (no stored description)"

        try:
            score = float(self._predict(prompt))
        except Exception as e:
            logger.warning(f"[AI] prediction failed for {cpe}: {e}")
            return []
        logger.debug(f"[AI] prompt origin: {prompt_origin}")

        synthetic_id = "AI-" + cpe.replace(":", "-").strip("-")[:80]
        logger.info(f"[AI] {cpe} → predicted CVSS {score:.1f} (informational, not a confirmation)")
        return [{
            "cve_ids": [synthetic_id],
            "euvd_id": None,
            "source": self.name,
            "base_score": score,
            "base_vector": None,
            "base_version": "3.1",
            "description": f"[Local AI Assessment] Predicted CVSS {score:.1f} for {cpe}",
            "references": [],
            # IMPORTANT: AI returns ``affects_version=False`` because the model
            # only estimates severity *if* something is vulnerable — it cannot
            # confirm that a specific version has a real CVE. Setting True here
            # would mark every unknown package as vulnerable (massive false
            # positives on internal/snapshot artifacts). The score is still
            # logged and surfaced via the AI response payload for observability.
            "affects_version": False,
            "raw": {"cpe": cpe, "score": score},
        }]
