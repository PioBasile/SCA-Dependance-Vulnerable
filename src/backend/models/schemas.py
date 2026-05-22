"""Pydantic schemas for API request/response validation."""
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

class CPEQueryRequest(BaseModel):
    cpe: str = Field(..., description="CPE 2.3 string")


class CPEBulkQueryRequest(BaseModel):
    cpe_list: List[str] = Field(..., min_length=1, max_length=1000)


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------

class VulnerabilitySummaryResponse(BaseModel):
    cve_id: str
    euvd_id: Optional[str] = None
    status: str
    published: datetime
    base_score: Optional[float] = None

    class Config:
        from_attributes = True


class HealthStatusResponse(BaseModel):
    status: str
    sources: Dict[str, Any]


class SyncStatusResponse(BaseModel):
    status: str
    total_cves: int
    euvd_mappings: int
    mapped_percentage: float
    cpe_entries: int
    unknown_cpes: int
    last_update: Optional[datetime] = None


class CveQueryResponse(BaseModel):
    found: bool
    count: int
    vulnerabilities: List[VulnerabilitySummaryResponse]
    ai_prediction: Optional[Dict[str, Any]] = None
