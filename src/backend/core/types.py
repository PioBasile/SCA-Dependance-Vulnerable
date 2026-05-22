"""Shared type definitions."""
from typing import TypedDict, Optional, List
from datetime import datetime


class NormalizedVulnerabilityDict(TypedDict, total=False):
    """Standard format for normalized vulnerability data from any source."""
    cve_ids: List[str]
    euvd_id: Optional[str]
    source: str
    base_score: Optional[float]
    base_vector: Optional[str]
    base_version: str
    description: str
    references: List[str]
    affects_version: bool
    version_start_including: Optional[str]
    version_end_excluding: Optional[str]
    version_start_excluding: Optional[str]
    version_end_including: Optional[str]
    raw: dict


class HealthCheckResult(TypedDict):
    """Health check result for a single source."""
    source: str
    healthy: bool
    details: str
    last_checked: datetime


class SyncStatusResult(TypedDict):
    """Sync status information."""
    total_cves: int
    euvd_mappings: int
    cpe_entries: int
    unknown_cpes: int
    last_sync: Optional[datetime]
