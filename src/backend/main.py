"""FastAPI entry point for the vulnerability aggregator."""
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy.orm import Session

from core.config import settings
from core.logger import get_logger
from models import get_db, init_db
from models.schemas import CPEBulkQueryRequest, CPEQueryRequest, CveQueryResponse, SyncStatusResponse
from services.aggregator import Aggregator
from services.vulnerability_service import VulnerabilityService

logger = get_logger(__name__)
aggregator = Aggregator()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting %s v%s", settings.app.title, settings.app.version)
    init_db()
    health = await aggregator.health_check()
    healthy = sum(1 for s in health.values() if s["healthy"])
    logger.info("Sources health: %d/%d", healthy, len(health))
    yield
    logger.info("Shutting down")


app = FastAPI(
    title=settings.app.title,
    version=settings.app.version,
    description="Multi-source vulnerability aggregator (EUVD, OSV, NVD, GitHub) with local AI fallback.",
    lifespan=lifespan,
)


def _max_score(cve) -> float | None:
    scores = [
        m.cvssData["baseScore"]
        for m in cve.cvss_metrics
        if m.cvssData and m.cvssData.get("baseScore") is not None
    ]
    return max(scores) if scores else None


# ---------------------------------------------------------------------------
# Health & status
# ---------------------------------------------------------------------------

@app.get("/", tags=["Health"])
async def root():
    return {
        "status": "ok",
        "title": settings.app.title,
        "version": settings.app.version,
    }


@app.get("/health", tags=["Health"])
async def health_check():
    sources_status = await aggregator.health_check()
    healthy = sum(1 for s in sources_status.values() if s["healthy"])
    return {
        "status": "healthy" if healthy == len(sources_status) else "degraded",
        "sources": sources_status,
    }


@app.get("/sync/status", response_model=SyncStatusResponse, tags=["Sync"])
async def sync_status(db: Session = Depends(get_db)):
    stats = VulnerabilityService.get_sync_status(db)
    return {
        "status": "synced" if stats["total_cves"] > 0 else "empty",
        **stats,
        "last_update": None,
    }


# ---------------------------------------------------------------------------
# Query
# ---------------------------------------------------------------------------

@app.post("/query", response_model=CveQueryResponse, tags=["Query"])
async def query_cpe(request: CPEQueryRequest, db: Session = Depends(get_db)):

    ai_prediction = None
    cves = VulnerabilityService.search_by_cpe(request.cpe, db)
    if not cves and not VulnerabilityService.is_recently_not_found(request.cpe, db):
        logger.info("CPE %s not in cache, querying sources", request.cpe)
        found, _, ai_prediction = await aggregator.fetch_and_sync(request.cpe, db)
        cves = VulnerabilityService.search_by_cpe(request.cpe, db) if found else []

    vulnerabilities = [
        {
            "cve_id": cve.cve_id,
            "euvd_id": cve.euvd_id,
            "status": cve.vulnStatus,
            "published": cve.published,
            "base_score": _max_score(cve),
        }
        for cve in cves
    ]
    return {
        "found": bool(vulnerabilities),
        "count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "ai_prediction": ai_prediction,
    }


@app.post("/query/bulk", tags=["Query"])
async def query_bulk(request: CPEBulkQueryRequest, db: Session = Depends(get_db)):
    results = await aggregator.fetch_bulk(request.cpe_list, db)
    output = {}
    for cpe in request.cpe_list:
        found, _, ai_prediction = results.get(cpe, (False, 0, None))
        cves = VulnerabilityService.search_by_cpe(cpe, db) if found else []
        output[cpe] = {
            "found": bool(cves),
            "count": len(cves),
            "cve_ids": [cve.cve_id for cve in cves[:10]],
            "ai_prediction": ai_prediction,
        }
    return {"status": "completed", "total": len(request.cpe_list), "results": output}


# ---------------------------------------------------------------------------
# CVE detail & search
# ---------------------------------------------------------------------------

@app.get("/cve/search", tags=["CVE"])
async def search_cves(
    q: str = Query(..., min_length=2),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    results = VulnerabilityService.search_cves(q, db, limit=limit)
    return {"query": q, "count": len(results), "results": results}


@app.get("/cve/{cve_id}", tags=["CVE"])
async def get_cve(cve_id: str, db: Session = Depends(get_db)):
    detail = VulnerabilityService.get_cve_detail(cve_id, db)
    if not detail:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    return detail


# ---------------------------------------------------------------------------
# Frontend compatibility — the Java desktop client calls this path.
# ---------------------------------------------------------------------------

@app.get("/config_nodes_cpe_match/", tags=["Compatibility"])
async def get_cpe_match(cpe_criteria: str = Query(...), db: Session = Depends(get_db)):
    ai_prediction = None

    cves = VulnerabilityService.search_by_cpe(cpe_criteria, db)

    if not cves and not VulnerabilityService.is_recently_not_found(cpe_criteria, db):
        found, _, ai_prediction = await aggregator.fetch_and_sync(cpe_criteria, db)
        cves = VulnerabilityService.search_by_cpe(cpe_criteria, db) if found else []

    nodes_data = []
    for cve in cves:
        for node in cve.nodes:
            nodes_data.append({
                "node_id": node.id,
                "cve_id": cve.cve_id,
                "operator": node.operator,
                "cpe_matches": [
                    {
                        "cpe_id": match.id,
                        "criteria": match.criteria,
                        "vulnerable": match.vulnerable,
                        "matchCriteriaId": match.matchCriteriaId,
                        "versionStartIncluding": match.versionStartIncluding,
                        "versionEndIncluding": match.versionEndIncluding,
                    }
                    for match in node.cpe_matches
                    if match.vulnerable
                ],
            })

    return {
        "cpe_criteria": cpe_criteria,
        "found": bool(cves),
        "vulnerabilities": [
            {
                "cve_id": cve.cve_id,
                "euvd_id": cve.euvd_id,
                "status": cve.vulnStatus,
                "published": cve.published.isoformat() if cve.published else None,
                "base_score": _max_score(cve),
            }
            for cve in cves
        ],
        "nodes": nodes_data,
        # ``ai_prediction`` is populated only when AI ran (settings.ai.enabled).
        # It is *informational* — the score is what the model would assign
        # *if* this CPE were vulnerable. The frontend uses it to surface a
        # third tier (yellow) between "no finding" (green) and "confirmed
        # CVE" (red). It is never paired with ``found=true`` from AI alone.
        "ai_prediction": ai_prediction,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.app.debug,
        workers=1 if settings.app.debug else settings.app.workers,
        log_level=settings.app.log_level.lower(),
    )
