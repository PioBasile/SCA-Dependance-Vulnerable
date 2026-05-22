"""Side-by-side benchmark of every vulnerability source.

Runs each source in isolation against a fixed set of well-known vulnerable
CPEs and reports latency, hit rate, CVE count, affected-version detection,
percent-precision, percent-coverage, latency percentiles, total wall-time,
and a Jaccard agreement matrix across sources.

Usage:
    python benchmark.py            # full run (default fixture)
    python benchmark.py --runs 3   # average over N runs per (source, cpe)
"""
from __future__ import annotations

import argparse
import asyncio
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

import logging as _std_logging

import httpx

# httpx logs every HTTP response at INFO, including 404s from OSV for CVEs that
# haven't been indexed yet (many 2026 CVEs). Suppress INFO-level httpx noise so
# only actual warnings/errors surface in the benchmark console output.
_std_logging.getLogger("httpx").setLevel(_std_logging.WARNING)

from core.config import settings
from core.logger import get_logger
from core.types import NormalizedVulnerabilityDict
from cvss import CVSS3
from sources.ai import LocalAISource
from sources.base import VulnerabilitySource
from sources.euvd import EUVDSource
from sources.github import GitHubSource
from sources.nvd import NVDSource
from sources.osv import OSVSource

logger = get_logger("benchmark")

CPE_FIXTURE: List[str] = [
    # log4j (Log4Shell + follow-ups, plus a patched build)
    "cpe:2.3:a:apache:log4j-core:2.14.1:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:log4j-core:2.17.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:log4j-core:2.17.1:*:*:*:*:*:*:*",
    # Spring family (Spring4Shell era + a recent build)
    "cpe:2.3:a:org.springframework:spring-core:5.2.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:org.springframework:spring-webmvc:5.3.18:*:*:*:*:*:*:*",
    "cpe:2.3:a:org.springframework:spring-webmvc:6.0.4:*:*:*:*:*:*:*",
    "cpe:2.3:a:spring-cloud-function-context:spring-cloud-function-context:3.2.2:*:*:*:*:*:*:*",
    # Jackson
    "cpe:2.3:a:com.fasterxml.jackson.core:jackson-databind:2.9.10:*:*:*:*:*:*:*",
    "cpe:2.3:a:com.fasterxml.jackson.core:jackson-databind:2.13.4:*:*:*:*:*:*:*",
    # Struts
    "cpe:2.3:a:apache:struts2-core:2.5.16:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:struts2-core:6.0.3:*:*:*:*:*:*:*",
    # SnakeYAML
    "cpe:2.3:a:org.yaml:snakeyaml:1.26:*:*:*:*:*:*:*",
    "cpe:2.3:a:org.yaml:snakeyaml:2.0:*:*:*:*:*:*:*",
    # Commons family
    "cpe:2.3:a:apache:commons-text:1.9:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:commons-text:1.10.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:commons-collections:commons-collections:3.2.1:*:*:*:*:*:*:*",
    # Web servers / containers
    "cpe:2.3:a:org.eclipse.jetty:jetty-server:9.4.30:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:tomcat-embed-core:9.0.40:*:*:*:*:*:*:*",
    # ORM / DB
    "cpe:2.3:a:org.hibernate:hibernate-core:5.4.10:*:*:*:*:*:*:*",
    "cpe:2.3:a:com.h2database:h2:1.4.200:*:*:*:*:*:*:*",
    # Serializers
    "cpe:2.3:a:com.alibaba:fastjson:1.2.68:*:*:*:*:*:*:*",
    "cpe:2.3:a:com.thoughtworks.xstream:xstream:1.4.10:*:*:*:*:*:*:*",
    # Misc
    "cpe:2.3:a:com.google.guava:guava:24.1-jre:*:*:*:*:*:*:*",
    "cpe:2.3:a:io.netty:netty-all:4.1.50:*:*:*:*:*:*:*",
    "cpe:2.3:a:org.bouncycastle:bcprov-jdk15on:1.66:*:*:*:*:*:*:*",
    "cpe:2.3:a:com.fasterxml.woodstox:woodstox-core:6.2.4:*:*:*:*:*:*:*",
]

# Ground truth: CVE sets verified by querying OSV API on 2026-05-22.
# Spring versions use Maven qualifiers (5.2.0.RELEASE, 5.4.10.Final, …).
# netty-all returns empty because OSV tracks per-module packages (netty-codec-http,
# netty-handler, …), not the all-in-one jar — real CVEs exist but OSV can't confirm them
# via this coordinate.
GROUND_TRUTH: Dict[str, Set[str]] = {
    "cpe:2.3:a:apache:log4j-core:2.14.1:*:*:*:*:*:*:*": {
        "CVE-2021-44228", "CVE-2021-44832", "CVE-2021-45046", "CVE-2021-45105",
        "CVE-2025-68161", "CVE-2026-34477", "CVE-2026-34480",
    },
    "cpe:2.3:a:apache:log4j-core:2.17.0:*:*:*:*:*:*:*": {
        "CVE-2021-44832", "CVE-2025-68161", "CVE-2026-34477", "CVE-2026-34480",
    },
    "cpe:2.3:a:apache:log4j-core:2.17.1:*:*:*:*:*:*:*": {
        "CVE-2025-68161", "CVE-2026-34477", "CVE-2026-34480",
    },
    "cpe:2.3:a:org.springframework:spring-core:5.2.0:*:*:*:*:*:*:*": {
        "CVE-2021-22060", "CVE-2021-22096",
    },
    "cpe:2.3:a:org.springframework:spring-webmvc:5.3.18:*:*:*:*:*:*:*": {
        "CVE-2023-20860", "CVE-2024-38816", "CVE-2024-38819", "CVE-2024-38828",
        "CVE-2025-41242", "CVE-2026-22735", "CVE-2026-22737", "CVE-2026-22741",
        "CVE-2026-22745",
    },
    "cpe:2.3:a:org.springframework:spring-webmvc:6.0.4:*:*:*:*:*:*:*": {
        "CVE-2023-20860", "CVE-2023-34053", "CVE-2024-38816", "CVE-2024-38819",
        "CVE-2025-41242", "CVE-2026-22735", "CVE-2026-22737",
    },
    "cpe:2.3:a:spring-cloud-function-context:spring-cloud-function-context:3.2.2:*:*:*:*:*:*:*": {
        "CVE-2022-22963",
    },
    "cpe:2.3:a:com.fasterxml.jackson.core:jackson-databind:2.9.10:*:*:*:*:*:*:*": {
        "CVE-2019-16942", "CVE-2019-16943", "CVE-2019-17531", "CVE-2019-20330",
        "CVE-2020-10650", "CVE-2020-10672", "CVE-2020-10673", "CVE-2020-10968",
        "CVE-2020-10969", "CVE-2020-11111", "CVE-2020-11112", "CVE-2020-11113",
        "CVE-2020-11619", "CVE-2020-11620", "CVE-2020-14060", "CVE-2020-14061",
        "CVE-2020-14062", "CVE-2020-14195", "CVE-2020-24616", "CVE-2020-24750",
        "CVE-2020-25649", "CVE-2020-35490", "CVE-2020-35491", "CVE-2020-35728",
        "CVE-2020-36179", "CVE-2020-36180", "CVE-2020-36181", "CVE-2020-36182",
        "CVE-2020-36183", "CVE-2020-36184", "CVE-2020-36185", "CVE-2020-36186",
        "CVE-2020-36187", "CVE-2020-36188", "CVE-2020-36189", "CVE-2020-36518",
        "CVE-2020-8840", "CVE-2020-9546", "CVE-2020-9547", "CVE-2020-9548",
        "CVE-2021-20190", "CVE-2022-42003", "CVE-2022-42004",
    },
    "cpe:2.3:a:com.fasterxml.jackson.core:jackson-databind:2.13.4:*:*:*:*:*:*:*": {
        "CVE-2022-42003",
    },
    "cpe:2.3:a:apache:struts2-core:2.5.16:*:*:*:*:*:*:*": {
        "CVE-2012-1592", "CVE-2018-11776", "CVE-2019-0230", "CVE-2019-0233",
        "CVE-2020-17530", "CVE-2021-31805", "CVE-2023-34149", "CVE-2023-34396",
        "CVE-2023-41835", "CVE-2023-50164", "CVE-2024-53677", "CVE-2025-64775",
        "CVE-2025-66675", "CVE-2025-68493",
    },
    "cpe:2.3:a:apache:struts2-core:6.0.3:*:*:*:*:*:*:*": {
        "CVE-2023-34149", "CVE-2023-34396", "CVE-2023-41835", "CVE-2023-50164",
        "CVE-2024-53677", "CVE-2025-64775", "CVE-2025-66675", "CVE-2025-68493",
    },
    "cpe:2.3:a:org.yaml:snakeyaml:1.26:*:*:*:*:*:*:*": {
        "CVE-2022-1471", "CVE-2022-25857", "CVE-2022-38749", "CVE-2022-38750",
        "CVE-2022-38751", "CVE-2022-38752", "CVE-2022-41854",
    },
    "cpe:2.3:a:org.yaml:snakeyaml:2.0:*:*:*:*:*:*:*": set(),
    "cpe:2.3:a:apache:commons-text:1.9:*:*:*:*:*:*:*": {
        "CVE-2022-42889",
    },
    "cpe:2.3:a:apache:commons-text:1.10.0:*:*:*:*:*:*:*": set(),
    "cpe:2.3:a:commons-collections:commons-collections:3.2.1:*:*:*:*:*:*:*": {
        "CVE-2015-6420", "CVE-2015-7501",
    },
    "cpe:2.3:a:org.eclipse.jetty:jetty-server:9.4.30:*:*:*:*:*:*:*": {
        "CVE-2020-27218", "CVE-2020-27223", "CVE-2021-28165", "CVE-2021-34428",
        "CVE-2023-26048", "CVE-2023-26049", "CVE-2024-13009", "CVE-2024-8184",
    },
    "cpe:2.3:a:apache:tomcat-embed-core:9.0.40:*:*:*:*:*:*:*": {
        "CVE-2021-25122", "CVE-2021-25329", "CVE-2022-42252", "CVE-2022-45143",
        "CVE-2023-24998", "CVE-2023-41080", "CVE-2023-42795", "CVE-2023-44487",
        "CVE-2023-45648", "CVE-2023-46589", "CVE-2024-24549", "CVE-2024-34750",
        "CVE-2024-50379", "CVE-2024-56337", "CVE-2025-24813", "CVE-2025-46701",
        "CVE-2025-48988", "CVE-2025-48989", "CVE-2025-49124", "CVE-2025-49125",
        "CVE-2025-52520", "CVE-2025-53506", "CVE-2025-55752", "CVE-2025-55754",
        "CVE-2025-61795", "CVE-2025-66614", "CVE-2026-24733", "CVE-2026-24880",
        "CVE-2026-25854", "CVE-2026-34483", "CVE-2026-34487", "CVE-2026-41284",
        "CVE-2026-41293", "CVE-2026-42498", "CVE-2026-43512", "CVE-2026-43513",
        "CVE-2026-43514", "CVE-2026-43515",
    },
    "cpe:2.3:a:org.hibernate:hibernate-core:5.4.10:*:*:*:*:*:*:*": {
        "CVE-2019-14900", "CVE-2020-25638", "CVE-2026-0603",
    },
    "cpe:2.3:a:com.h2database:h2:1.4.200:*:*:*:*:*:*:*": {
        "CVE-2021-23463", "CVE-2021-42392", "CVE-2022-23221", "CVE-2022-45868",
    },
    "cpe:2.3:a:com.alibaba:fastjson:1.2.68:*:*:*:*:*:*:*": {
        "CVE-2022-25845",
    },
    "cpe:2.3:a:com.thoughtworks.xstream:xstream:1.4.10:*:*:*:*:*:*:*": {
        "CVE-2013-7285", "CVE-2019-10173", "CVE-2020-26217", "CVE-2020-26258",
        "CVE-2020-26259", "CVE-2021-21341", "CVE-2021-21342", "CVE-2021-21343",
        "CVE-2021-21344", "CVE-2021-21345", "CVE-2021-21346", "CVE-2021-21347",
        "CVE-2021-21348", "CVE-2021-21349", "CVE-2021-21350", "CVE-2021-21351",
        "CVE-2021-29505", "CVE-2021-39139", "CVE-2021-39140", "CVE-2021-39141",
        "CVE-2021-39144", "CVE-2021-39145", "CVE-2021-39146", "CVE-2021-39147",
        "CVE-2021-39148", "CVE-2021-39149", "CVE-2021-39150", "CVE-2021-39151",
        "CVE-2021-39152", "CVE-2021-39153", "CVE-2021-39154", "CVE-2021-43859",
        "CVE-2022-40151", "CVE-2022-41966", "CVE-2024-47072",
    },
    "cpe:2.3:a:com.google.guava:guava:24.1-jre:*:*:*:*:*:*:*": {
        "CVE-2018-10237", "CVE-2020-8908", "CVE-2023-2976",
    },
    # OSV tracks netty per-module (netty-codec-http, netty-handler, …), not the
    # all-in-one jar — real CVEs exist for 4.1.50 but cannot be confirmed via this coord.
    "cpe:2.3:a:io.netty:netty-all:4.1.50:*:*:*:*:*:*:*": set(),
    "cpe:2.3:a:org.bouncycastle:bcprov-jdk15on:1.66:*:*:*:*:*:*:*": {
        "CVE-2020-28052", "CVE-2023-33201", "CVE-2023-33202", "CVE-2024-29857",
        "CVE-2024-30171", "CVE-2024-34447",
    },
    "cpe:2.3:a:com.fasterxml.woodstox:woodstox-core:6.2.4:*:*:*:*:*:*:*": {
        "CVE-2022-40152",
    },
}

# Known-clean versions — OSV returns zero CVEs for each (verified 2026-05-22).
# Any source flagging CVEs here is a false positive. Used for specificity analysis.
#
# Two categories:
#   "latest clean"  — recent upstream releases with no known CVEs.
#   "boundary pair" — version immediately after the fix point for a vulnerable
#                     version that appears in CPE_FIXTURE; tests whether sources
#                     correctly stop flagging at the patch boundary.
NEGATIVE_FIXTURE: List[str] = [
    # --- latest clean ---
    "cpe:2.3:a:com.fasterxml.jackson.core:jackson-databind:2.17.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:org.hibernate:hibernate-core:6.6.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:org.yaml:snakeyaml:2.4:*:*:*:*:*:*:*",
    "cpe:2.3:a:com.h2database:h2:2.3.232:*:*:*:*:*:*:*",
    "cpe:2.3:a:com.thoughtworks.xstream:xstream:1.4.21:*:*:*:*:*:*:*",
    # --- boundary pairs (patched version adjacent to a CPE_FIXTURE entry) ---
    # commons-collections:3.2.1 (in fixture) has CVE-2015-6420 + CVE-2015-7501
    # 3.2.2 is the security release that fixed both.
    "cpe:2.3:a:commons-collections:commons-collections:3.2.2:*:*:*:*:*:*:*",
    # guava:24.1-jre (in fixture) has CVE-2018-10237 + CVE-2020-8908 + CVE-2023-2976
    # 32.0-jre contains the serialization fix and all subsequent patches.
    "cpe:2.3:a:com.google.guava:guava:32.0-jre:*:*:*:*:*:*:*",
    # woodstox-core:6.2.4 (in fixture) has CVE-2022-40152
    # 6.4.0 is the first release to remove the vulnerable XML stack.
    "cpe:2.3:a:com.fasterxml.woodstox:woodstox-core:6.4.0:*:*:*:*:*:*:*",
]

_NEGATIVE_SET: Set[str] = set(NEGATIVE_FIXTURE)


@dataclass
class Sample:
    cpe: str
    elapsed_ms: float
    error: str | None = None
    total: int = 0
    affected: int = 0
    cve_ids: List[str] = field(default_factory=list)
    base_scores: List[float] = field(default_factory=list)


@dataclass
class SourceReport:
    name: str
    health: bool = False
    samples: List[Sample] = field(default_factory=list)

    # Bulk-aggregation helpers ------------------------------------------------

    def latencies(self) -> List[float]:
        return [s.elapsed_ms for s in self.samples if not s.error]

    def affected_cpes(self) -> Set[str]:
        return {s.cpe for s in self.samples if not s.error and s.affected > 0}

    def affected_cve_set(self) -> Set[str]:
        cves: Set[str] = set()
        for s in self.samples:
            if not s.error and s.affected > 0:
                cves.update(s.cve_ids)
        return cves

    @property
    def errors(self) -> int:
        return sum(1 for s in self.samples if s.error)

    @property
    def hits(self) -> int:
        return len(self.affected_cpes())

    @property
    def total_returned(self) -> int:
        return sum(s.total for s in self.samples)

    @property
    def total_affected(self) -> int:
        return sum(s.affected for s in self.samples)

    @property
    def total_wall_time_ms(self) -> float:
        return sum(s.elapsed_ms for s in self.samples)


# --------------------------------------------------------------------------- #
# Aggregator HTTP wrapper (feature 2)
# --------------------------------------------------------------------------- #

class AggregatorHTTPSource(VulnerabilitySource):
    """Treats the running /query API endpoint as a sixth benchmark source."""

    def __init__(self, base_url: str = "http://localhost:8000") -> None:
        self._base_url = base_url.rstrip("/")

    @property
    def name(self) -> str:
        return "AGG"

    async def healthy(self) -> bool:
        try:
            async with httpx.AsyncClient() as c:
                r = await c.get(f"{self._base_url}/health", timeout=5.0)
                return r.status_code == 200
        except Exception:
            return False

    async def query(self, cpe: str) -> List[NormalizedVulnerabilityDict]:
        try:
            async with httpx.AsyncClient() as c:
                r = await c.post(
                    f"{self._base_url}/query",
                    json={"cpe": cpe},
                    timeout=120.0,
                )
                r.raise_for_status()
                data = r.json()
            results: List[NormalizedVulnerabilityDict] = []
            for v in data.get("vulnerabilities", []):
                cve_id = v.get("cve_id")
                if not cve_id:
                    continue
                results.append({
                    "cve_ids": [cve_id],
                    "euvd_id": v.get("euvd_id"),
                    "source": "AGG",
                    "base_score": v.get("base_score"),
                    "base_vector": None,
                    "base_version": "3.1",
                    "description": "",
                    "references": [],
                    "affects_version": True,
                    "version_start_including": None,
                    "version_end_excluding": None,
                    "raw": v,
                })
            return results
        except Exception as e:
            logger.warning(f"[AGG] query({cpe}) failed: {e}")
            return []


# --------------------------------------------------------------------------- #
# CVSS score fetcher (feature 1)
# --------------------------------------------------------------------------- #

async def _fetch_cvss_scores(cve_ids: List[str]) -> Dict[str, float]:
    """Fetch CVSS v3 base scores from OSV for all GT CVEs (concurrent, max 20 in flight)."""
    sem = asyncio.Semaphore(20)
    scores: Dict[str, float] = {}

    async def _one(cve_id: str) -> None:
        async with sem:
            try:
                async with httpx.AsyncClient() as c:
                    r = await c.get(
                        f"https://api.osv.dev/v1/vulns/{cve_id}",
                        timeout=8.0,
                    )
                if r.status_code != 200:
                    return
                for sev in r.json().get("severity", []):
                    if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
                        try:
                            scores[cve_id] = float(CVSS3(sev["score"]).base_score)
                        except Exception:
                            pass
                        return
            except Exception:
                pass

    await asyncio.gather(*[_one(cve) for cve in cve_ids])
    return scores


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #

async def _bench_one(source: VulnerabilitySource, cpe: str) -> Sample:
    start = time.perf_counter()
    try:
        results = await source.query(cpe)
        elapsed = (time.perf_counter() - start) * 1000
        affected = [r for r in results if r.get("affects_version")]
        cve_ids: List[str] = []
        for r in affected:
            cve_ids.extend(r.get("cve_ids") or [])
        seen: Set[str] = set()
        unique = [c for c in cve_ids if not (c in seen or seen.add(c))]
        scores = [
            float(r["base_score"])
            for r in results
            if r.get("base_score") is not None
        ]
        return Sample(
            cpe=cpe,
            elapsed_ms=elapsed,
            total=len(results),
            affected=len(affected),
            cve_ids=unique,
            base_scores=scores,
        )
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return Sample(cpe=cpe, elapsed_ms=elapsed, error=f"{type(e).__name__}: {e}")


async def _check_health(source: VulnerabilitySource) -> bool:
    try:
        return await source.healthy()
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Output formatters
# --------------------------------------------------------------------------- #

def _percentile(values: List[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * (p / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    if lo == hi:
        return s[lo]
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def _fmt(v: float, width: int = 7, decimals: int = 0) -> str:
    if v != v:  # NaN
        return f"{'-':>{width}}"
    return f"{v:{width}.{decimals}f}"


def _pct(num: float, den: float) -> str:
    if den == 0:
        return "  -  "
    return f"{(num / den) * 100:5.1f}%"


def _print_summary(reports: List[SourceReport], total_cpes: int) -> None:
    print("\n=== Summary per source =====================================================")
    print(
        f"{'source':<8}"
        f"{'health':>7}"
        f"{'coverage %':>12}"
        f"{'flagged %':>11}"
        f"{'returned':>10}"
        f"{'affected':>10}"
        f"{'CPEs hit':>10}"
        f"{'errors':>8}"
        f"{'latency p25':>13}"
        f"{'latency p50':>13}"
        f"{'latency p75':>13}"
        f"{'latency p95':>13}"
        f"{'latency max':>13}"
        f"{'total sec':>11}"
    )
    print("-" * 152)
    for r in reports:
        lat = r.latencies()
        cov = (r.hits / total_cpes) if total_cpes else 0
        flagged = (r.total_affected / r.total_returned) if r.total_returned else 0
        print(
            f"{r.name:<8}"
            f"{'UP' if r.health else 'DOWN':>7}"
            f"{cov * 100:>11.1f}%"
            f"{flagged * 100:>10.1f}%"
            f"{r.total_returned:>10}"
            f"{r.total_affected:>10}"
            f"{r.hits:>10}"
            f"{r.errors:>8}"
            f"{_fmt(_percentile(lat, 25), width=13)}"
            f"{_fmt(_percentile(lat, 50), width=13)}"
            f"{_fmt(_percentile(lat, 75), width=13)}"
            f"{_fmt(_percentile(lat, 95), width=13)}"
            f"{_fmt(max(lat) if lat else float('nan'), width=13)}"
            f"{r.total_wall_time_ms / 1000:>11.1f}"
        )
    print(
        "\n  coverage % = CPEs the source produced ≥1 affected match for, "
        "divided by total CPEs."
    )
    print(
        "  flagged %  = items the source marked affects_version=True, "
        "divided by items it returned."
    )
    print("  latency values are milliseconds (successful runs only).")


def _build_consensus_ground_truth(reports: List[SourceReport]) -> Dict[str, Set[str]]:
    """CVE is real for a CPE iff ≥2 of {EUVD, OSV, NVD, GitHub} flag it."""
    real = [r for r in reports if r.name != "AI"]
    per_cpe: Dict[str, Dict[str, Set[str]]] = {}
    for r in real:
        for s in r.samples:
            if s.error or s.affected == 0:
                continue
            cpe_map = per_cpe.setdefault(s.cpe, {})
            for cve in s.cve_ids:
                cpe_map.setdefault(cve, set()).add(r.name)
    return {
        cpe: {cve for cve, srcs in cves.items() if len(srcs) >= 2}
        for cpe, cves in per_cpe.items()
    }


def _compute_metrics(
    reports: List[SourceReport],
    ground_truth: Dict[str, Set[str]],
) -> Dict[str, Dict[str, float]]:
    """Return per-source TP/FP/FN/precision/recall/F1 against the given ground truth."""
    out: Dict[str, Dict[str, float]] = {}
    for r in reports:
        tp = fp = fn = 0
        for s in r.samples:
            if s.error or s.cpe not in ground_truth:
                continue
            truth = ground_truth[s.cpe]
            flagged = set(s.cve_ids) if s.affected > 0 else set()
            tp += len(flagged & truth)
            fp += len(flagged - truth)
            fn += len(truth - flagged)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec  = tp / (tp + fn) if (tp + fn) else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        out[r.name] = {"tp": tp, "fp": fp, "fn": fn, "prec": prec, "rec": rec, "f1": f1}
    return out


def _print_dual_metrics(reports: List[SourceReport]) -> None:
    """Side-by-side precision/recall against OSV ground truth AND soft consensus."""
    consensus_gt = _build_consensus_ground_truth(reports)
    for cpe in CPE_FIXTURE:
        consensus_gt.setdefault(cpe, set())

    gt_metrics = _compute_metrics(reports, GROUND_TRUTH)
    cs_metrics = _compute_metrics(reports, consensus_gt)

    gt_total = sum(len(v) for v in GROUND_TRUTH.values())
    cs_total = sum(len(v) for v in consensus_gt.values())

    print("\n=== Precision / Recall: OSV ground truth  vs  soft consensus ===============")
    print("  OSV GT       : CVE sets verified against OSV API on 2026-05-22.")
    print("  Soft consensus: CVE counted as real iff ≥2 of {EUVD,OSV,NVD,GitHub} flag it.")
    print("  AI excluded from consensus voting but scored against both truths.")
    print(f"  OSV GT size: {gt_total} (CVE,CPE) pairs | Consensus size: {cs_total} pairs\n")

    col = f"{'':8} {'TP':>6} {'FP':>6} {'FN':>6} {'Prec':>7} {'Rec':>7} {'F1':>7}"
    sep = "   |   "
    print(f"{'source':<8} {'--- OSV ground truth ---':^37}{sep}{'--- soft consensus (circular) ---':^37}")
    print(f"{'':8} {'TP':>6} {'FP':>6} {'FN':>6} {'Prec':>7} {'Rec':>7} {'F1':>7}"
          f"{sep}"
          f"{'TP':>6} {'FP':>6} {'FN':>6} {'Prec':>7} {'Rec':>7} {'F1':>7}")
    print("-" * 95)

    for r in reports:
        g = gt_metrics[r.name]
        c = cs_metrics[r.name]
        print(
            f"{r.name:<8}"
            f" {int(g['tp']):>6} {int(g['fp']):>6} {int(g['fn']):>6}"
            f" {g['prec']*100:>6.1f}% {g['rec']*100:>6.1f}% {g['f1']*100:>6.1f}%"
            f"{sep}"
            f"{int(c['tp']):>6} {int(c['fp']):>6} {int(c['fn']):>6}"
            f" {c['prec']*100:>6.1f}% {c['rec']*100:>6.1f}% {c['f1']*100:>6.1f}%"
        )

    print("\n  TP = flagged CVE is in the ground truth for that CPE.")
    print("  FP = flagged CVE is NOT in the ground truth (false alarm).")
    print("  FN = ground truth CVE was missed by this source.")
    print("  OSV GT FP gap vs consensus FP gap reveals circular-truth inflation.")


def _short_cpe(cpe: str) -> str:
    parts = cpe.split(":")
    product = parts[4] if len(parts) > 4 else cpe
    version = parts[5] if len(parts) > 5 else "?"
    label = f"{product[:32]}:{version}"
    return label[:36]


def _print_per_cpe(reports: List[SourceReport]) -> None:
    print("\n=== Breakdown per CPE ======================================================")
    print("  Each cell shows: affected / returned (latency in ms)")
    cpes = [s.cpe for s in reports[0].samples]
    header = f"{'CPE':<37}" + "".join(f" {r.name:>13}" for r in reports)
    print()
    print(header)
    print("-" * len(header))
    for i, cpe in enumerate(cpes):
        row = f"{_short_cpe(cpe):<37}"
        for r in reports:
            s = r.samples[i]
            cell = "ERR" if s.error else f"{s.affected}/{s.total} ({s.elapsed_ms:.0f})"
            row += f" {cell:>13}"
        print(row)


def _print_consensus(reports: List[SourceReport], total_cpes: int) -> None:
    """How concentrated are the affected-CVE sets across sources?"""
    cve_to_sources: Dict[str, Set[str]] = {}
    for r in reports:
        for cve in r.affected_cve_set():
            cve_to_sources.setdefault(cve, set()).add(r.name)

    if not cve_to_sources:
        return

    histogram: Dict[int, int] = {}
    for sources in cve_to_sources.values():
        n = len(sources)
        histogram[n] = histogram.get(n, 0) + 1

    total = len(cve_to_sources)
    print("\n=== How many sources agree on each CVE =====================================")
    print(f"  Unique affected CVEs across all sources: {total}")
    for n in sorted(histogram):
        bar = "#" * int(histogram[n] / max(histogram.values()) * 30)
        print(
            f"  flagged by {n} of {len(reports)} sources: "
            f"{histogram[n]:>4} CVEs "
            f"({histogram[n] / total * 100:5.1f}% of total) {bar}"
        )


def _print_jaccard(reports: List[SourceReport]) -> None:
    """Pairwise Jaccard agreement on the affected-CVE sets."""
    print("\n=== Pairwise CVE-set overlap (Jaccard index) ===============================")
    print("  100 % = two sources flagged exactly the same CVEs.")
    print("    0 % = no overlap.\n")
    sets = {r.name: r.affected_cve_set() for r in reports}
    cols = list(sets.keys())
    print("        " + "".join(f"{c:>10}" for c in cols))
    for r in cols:
        a = sets[r]
        row = f"{r:<8}"
        for c in cols:
            b = sets[c]
            if not a and not b:
                row += f"{'-':>10}"
            else:
                inter = len(a & b)
                union = len(a | b)
                j = (inter / union) if union else 0
                row += f"{j * 100:>9.1f}%"
        print(row)


def _print_ai_benchmark(
    reports: List[SourceReport],
    ground_truth: Dict[str, Set[str]],
    cve_severity: Dict[str, float],
) -> None:
    """Evaluate AI as a severity predictor, not a CVE detector.

    Pipeline recap (read-only, do not modify AI here):
      1. LocalAISource.query(cpe) extracts vendor + product from the CPE.
      2. _description_for_product(vendor, product) queries the DB for the
         most-severe stored CVE description for that vendor:product pair
         (any version).  Returns None when the DB has no entry yet.
      3. predict_cvss(description) tokenises the text with DistilBERT and
         runs 8 classification heads → CVSS:3.1/AV:.../... → base_score.
      4. The result is returned with affects_version=False — it is a *hint*,
         never a confirmation.

    Consequences for this benchmark:
      • AI REQUIRES a stored CVE description. Without a prior server scan that
        populated the DB, every CPE is skipped. Run the server against these
        CPEs first, then re-run the benchmark.
      • The description lookup is version-agnostic (vendor:product only). The
        SAME description is used for jackson-databind:2.9.10 AND 2.17.0, so
        FPs on NEGATIVE_FIXTURE boundary pairs are structural, not bugs.

    Metrics (only for CPEs where AI actually produced a score):
      1. CVSS MAE — predicted score vs actual max CVSS from OSV GT.
      2. Tier accuracy — Critical / High / Medium / Low bucket match.
      3. Binary classifier at threshold 7.0 — sensitivity + specificity.
         Note: FP rate on version-adjacent clean CPEs is expected to be high
         because the model is not version-aware.
    """
    ai = next((r for r in reports if r.name == "AI"), None)
    if ai is None:
        return

    print("\n=== AI severity predictor evaluation =======================================")
    print("  Model : DistilBERT → 8 CVSS heads → base_score.  affects_version=False always.")
    print("  Input : most-severe stored CVE description for vendor:product (DB lookup).")
    print("  Caveat: lookup is version-agnostic — same description for all versions of")
    print("          a product, so NEGATIVE_FIXTURE FPs on boundary pairs are expected.")
    print()

    # ── Coverage ─────────────────────────────────────────────────────────────
    ran     = [s for s in ai.samples if not s.error and s.base_scores]
    skipped = [s for s in ai.samples if not s.error and not s.base_scores]
    errors_list = [s for s in ai.samples if s.error]

    total = len(ai.samples)
    print(f"  Coverage : {len(ran)}/{total} CPEs produced a prediction")
    if errors_list:
        print(f"  Errors   : {len(errors_list)} CPEs raised an exception")
    if skipped:
        # Skips happen because _description_for_product returned None — either
        # the DB lacks entries for this product, or the CPE failed validation
        # (vendor==product syft-style, SNAPSHOT version, wildcard, etc.).
        print(f"  Skipped  : {len(skipped)} CPEs — no stored description / validation skip")
        print(f"    → populate the DB by scanning these CPEs via the server, then rerun:")
        for s in skipped:
            print(f"       {_short_cpe(s.cpe)}")
    print()

    # ── Score distribution ───────────────────────────────────────────────────
    all_scores: List[float] = [sc for s in ran for sc in s.base_scores]
    if all_scores:
        print(f"  Score distribution over {len(all_scores)} prediction(s):")
        print(f"    min={min(all_scores):.1f}  mean={statistics.mean(all_scores):.2f}"
              f"  median={statistics.median(all_scores):.1f}  max={max(all_scores):.1f}")
        tier_counts: Dict[str, int] = {}
        for sc in all_scores:
            t = _cvss_tier(sc)
            tier_counts[t] = tier_counts.get(t, 0) + 1
        for t in ["Critical ≥9.0", "High 7-9", "Medium 4-7", "Low <4"]:
            if t in tier_counts:
                bar = "#" * tier_counts[t]
                print(f"    {t:<14}: {tier_counts[t]:>3}  {bar}")
        print()

    if not ran:
        print("  No predictions available — populate the DB first (see Skipped list above).")
        return

    # ── Accuracy metrics (positive CPEs only) ────────────────────────────────
    accuracy_rows: List[tuple] = []   # (cpe, predicted, actual_max, abs_error)
    tier_correct = tier_total = 0
    THRESHOLD = 7.0
    bin_tp = bin_fn = bin_fp = bin_tn = 0
    # track boundary vs. non-boundary FPs separately
    boundary_fp = boundary_tn = 0

    for s in ai.samples:
        if s.error or not s.base_scores:
            continue
        predicted = max(s.base_scores)

        if s.cpe in _NEGATIVE_SET:
            is_boundary = s.cpe in _BOUNDARY_PAIR_CPES
            if predicted >= THRESHOLD:
                bin_fp += 1
                if is_boundary:
                    boundary_fp += 1
            else:
                bin_tn += 1
                if is_boundary:
                    boundary_tn += 1
            continue

        actual_cves = ground_truth.get(s.cpe, set())
        if not actual_cves:
            continue
        actual_scores = [cve_severity[c] for c in actual_cves if c in cve_severity]
        if not actual_scores:
            continue
        actual_max = max(actual_scores)

        err = abs(predicted - actual_max)
        accuracy_rows.append((s.cpe, predicted, actual_max, err))
        tier_total += 1
        if _cvss_tier(predicted) == _cvss_tier(actual_max):
            tier_correct += 1
        if predicted >= THRESHOLD:
            bin_tp += 1
        else:
            bin_fn += 1

    if accuracy_rows:
        mae = sum(e[3] for e in accuracy_rows) / len(accuracy_rows)
        print(f"  CVSS MAE (predicted vs actual max CVSS):  {mae:.2f}  "
              f"over {len(accuracy_rows)} CPE(s)")
        print(f"  Tier accuracy : {tier_correct}/{tier_total} = "
              f"{100*tier_correct/tier_total:.1f}%  "
              f"(Critical / High / Medium / Low bucket match)")
        print()

        worst = sorted(accuracy_rows, key=lambda x: -x[3])[:5]
        print(f"  Largest prediction errors (top {len(worst)}):")
        for cpe, pred, actual, err in worst:
            print(f"    {_short_cpe(cpe):<36}  predicted={pred:.1f}  "
                  f"actual={actual:.1f}  err={err:.1f}  [{_cvss_tier(actual)}]")
        print()
    else:
        print("  No positive CPEs with both a prediction and a scored GT CVE.")
        print()

    sens = bin_tp / (bin_tp + bin_fn) if (bin_tp + bin_fn) else 0.0
    spec = bin_tn / (bin_tn + bin_fp) if (bin_tn + bin_fp) else 0.0
    print(f"  Binary classifier at threshold ≥{THRESHOLD}  (positive=has CVEs, negative=clean):")
    print(f"    TP={bin_tp}  FN={bin_fn}  FP={bin_fp}  TN={bin_tn}")
    print(f"    Sensitivity (TPR): {sens*100:.1f}%   Specificity (TNR): {spec*100:.1f}%")
    if boundary_fp + boundary_tn > 0:
        print(f"    Boundary-pair FPs: {boundary_fp}/{boundary_fp+boundary_tn}"
              f"  (expected — model is not version-aware)")


def _cvss_tier(score: float) -> str:
    if score >= 9.0:  return "Critical ≥9.0"
    if score >= 7.0:  return "High 7-9"
    if score >= 4.0:  return "Medium 4-7"
    return "Low <4"


def _print_severity_recall(
    reports: List[SourceReport],
    ground_truth: Dict[str, Set[str]],
    cve_severity: Dict[str, float],
) -> None:
    """Recall broken down by CVSS severity tier (feature 1)."""
    tier_labels = ["Critical ≥9.0", "High 7-9", "Medium 4-7", "Low <4"]

    # (cpe, cve) pairs per tier
    tier_pairs: Dict[str, List[tuple]] = {t: [] for t in tier_labels}
    unknown = 0
    for cpe, cves in ground_truth.items():
        for cve in cves:
            score = cve_severity.get(cve)
            if score is None:
                unknown += 1
                continue
            tier_pairs[_cvss_tier(score)].append((cpe, cve))

    print("\n=== Recall by CVSS severity tier (OSV ground truth) ========================")
    print(f"  {unknown} GT CVEs have no CVSS score from OSV (skipped from tier analysis).\n")

    col_w = 20
    header = f"{'source':<8}" + "".join(f" {t:>{col_w}}" for t in tier_labels)
    print(header)
    print("-" * len(header))

    for r in reports:
        found: Dict[str, Set[str]] = {}
        for s in r.samples:
            if not s.error and s.affected > 0:
                found[s.cpe] = set(s.cve_ids)
        row = f"{r.name:<8}"
        for t in tier_labels:
            pairs = tier_pairs[t]
            if not pairs:
                row += f" {'n/a':>{col_w}}"
                continue
            tp = sum(1 for (cpe, cve) in pairs if cve in found.get(cpe, set()))
            total = len(pairs)
            pct = tp / total * 100
            cell = f"{pct:.1f}% ({tp}/{total})"
            row += f" {cell:>{col_w}}"
        print(row)

    print("\n  Each cell: recall% (found/total) within that severity bucket.")
    print("  Missing a Critical CVE is far worse than missing a Low.")


_BOUNDARY_PAIR_CPES: Set[str] = {
    "cpe:2.3:a:commons-collections:commons-collections:3.2.2:*:*:*:*:*:*:*",
    "cpe:2.3:a:com.google.guava:guava:32.0-jre:*:*:*:*:*:*:*",
    "cpe:2.3:a:com.fasterxml.woodstox:woodstox-core:6.4.0:*:*:*:*:*:*:*",
}


def _print_specificity(reports: List[SourceReport]) -> None:
    """False positive rate on the known-clean NEGATIVE_FIXTURE."""
    print("\n=== Specificity: FP rate on known-clean versions ===========================")
    print("  These versions have zero known CVEs per OSV (verified 2026-05-22).")
    print("  'boundary' = patched version directly adjacent to a vulnerable CPE_FIXTURE entry.")
    print("  Any CVE flagged here is a false positive.")
    print()
    print(f"  {'source':<8} {'FP CVEs':>8} {'FP/CPE':>9}  {'boundary FPs':>13}  sample (first 3 flagged)")
    print("  " + "-" * 80)

    for r in reports:
        fp_pairs: List[str] = []
        boundary_fp = 0
        for s in r.samples:
            if s.cpe not in _NEGATIVE_SET:
                continue
            if s.affected > 0:
                label = _short_cpe(s.cpe)
                for cve in s.cve_ids[:3]:
                    fp_pairs.append(f"{label}→{cve}")
                if s.cpe in _BOUNDARY_PAIR_CPES:
                    boundary_fp += len(s.cve_ids)
        total_neg = len(NEGATIVE_FIXTURE)
        fp_count = sum(
            1 for s in r.samples
            if s.cpe in _NEGATIVE_SET and s.affected > 0
            for _ in s.cve_ids
        )
        rate = fp_count / total_neg if total_neg else 0.0
        sample_str = ", ".join(fp_pairs[:3])
        if len(fp_pairs) > 3:
            sample_str += f" +{len(fp_pairs) - 3} more"
        boundary_str = f"{boundary_fp:>3} of {len(_BOUNDARY_PAIR_CPES)} pairs"
        print(f"  {r.name:<8} {fp_count:>8} {rate:>8.1f}x  {boundary_str:>13}  {sample_str or '(none — perfect)'}")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

async def main(runs: int, with_aggregator: bool, agg_url: str) -> None:
    settings.ai.enabled = True

    sources: List[VulnerabilitySource] = [
        EUVDSource(), OSVSource(), NVDSource(), GitHubSource(), LocalAISource(),
    ]
    if with_aggregator:
        sources.append(AggregatorHTTPSource(agg_url))

    all_cpes = CPE_FIXTURE + NEGATIVE_FIXTURE

    # --- fetch CVSS scores for severity-weighted recall ---
    all_gt_cves = sorted({cve for cves in GROUND_TRUTH.values() for cve in cves})
    print(f"Fetching CVSS scores for {len(all_gt_cves)} ground-truth CVEs from OSV …")
    cve_severity = await _fetch_cvss_scores(all_gt_cves)
    known = sum(1 for s in cve_severity.values() if s is not None)
    print(f"  Scores retrieved: {known}/{len(all_gt_cves)}\n")

    print(
        f"Benchmarking {len(sources)} sources"
        f" × {len(CPE_FIXTURE)} positive + {len(NEGATIVE_FIXTURE)} negative CPEs"
        f" × {runs} run(s)"
    )
    overall_start = time.perf_counter()

    health = await asyncio.gather(*[_check_health(s) for s in sources])
    reports: List[SourceReport] = []
    for src, ok in zip(sources, health):
        reports.append(SourceReport(name=src.name, health=ok))
        print(f"  {src.name:<8} health: {'UP' if ok else 'DOWN'}")

    print("\nRunning queries…")
    for src, report in zip(sources, reports):
        for cpe in all_cpes:
            for _ in range(runs):
                report.samples.append(await _bench_one(src, cpe))
        pos_hits = sum(
            1 for s in report.samples
            if s.cpe not in _NEGATIVE_SET and not s.error and s.affected > 0
        )
        print(f"  {src.name:<8} done — errors={report.errors:>2}, "
              f"hits={pos_hits:>2}/{len(CPE_FIXTURE)}, "
              f"CVEs={report.total_returned:>4}, "
              f"aff={report.total_affected:>4}")

    # Positive-only subset for summary / precision-recall / consensus / Jaccard
    pos_reports = [
        SourceReport(
            name=r.name,
            health=r.health,
            samples=[s for s in r.samples if s.cpe not in _NEGATIVE_SET],
        )
        for r in reports
    ]

    _print_summary(pos_reports, len(CPE_FIXTURE))
    _print_dual_metrics(pos_reports)
    _print_severity_recall(pos_reports, GROUND_TRUTH, cve_severity)
    _print_specificity(reports)
    _print_consensus(pos_reports, len(CPE_FIXTURE))
    _print_jaccard(pos_reports)
    _print_ai_benchmark(reports, GROUND_TRUTH, cve_severity)
    if runs == 1:
        _print_per_cpe(pos_reports)

    overall = time.perf_counter() - overall_start
    print(f"\nTotal wall time: {overall:.1f}s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=1,
                        help="number of runs per (source, cpe) pair")
    parser.add_argument("--with-aggregator", action="store_true",
                        help="include the running aggregator API as a source (AGG)")
    parser.add_argument("--agg-url", default="http://localhost:8000",
                        help="aggregator API base URL (default: http://localhost:8000)")
    args = parser.parse_args()
    asyncio.run(main(args.runs, args.with_aggregator, args.agg_url))
