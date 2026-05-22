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
from typing import Dict, List, Set

from core.config import settings
from core.logger import get_logger
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


def _print_consensus_metrics(reports: List[SourceReport]) -> None:
    """Build a per-CPE soft ground-truth from the four real sources (each CVE
    flagged by ≥2 of {EUVD, OSV, NVD, GitHub} for that CPE) and compute true
    precision / recall / F1 per source against it.

    AI is scored too but always gets zero — its synthesized ``AI-...`` IDs
    never appear in the consensus by construction.
    """
    real = [r for r in reports if r.name != "AI"]

    # per_cpe_sources[cpe][cve] = {source names that flagged this CVE}
    per_cpe_sources: Dict[str, Dict[str, Set[str]]] = {}
    for r in real:
        for s in r.samples:
            if s.error or s.affected == 0:
                continue
            cpe_map = per_cpe_sources.setdefault(s.cpe, {})
            for cve in s.cve_ids:
                cpe_map.setdefault(cve, set()).add(r.name)

    consensus: Dict[str, Set[str]] = {
        cpe: {cve for cve, srcs in cves.items() if len(srcs) >= 2}
        for cpe, cves in per_cpe_sources.items()
    }
    consensus_total = sum(len(v) for v in consensus.values())

    print("\n=== Consensus precision and recall against soft ground truth ===============")
    print("  Soft ground truth: a CVE counts as real for a CPE iff at least two of")
    print("  {EUVD, OSV, NVD, GitHub} flag it for that CPE. AI is scored against the")
    print("  same truth but is excluded from voting on it.")
    print(f"  Ground-truth size: {consensus_total} (CVE, CPE) pairs across "
          f"{len(consensus)} CPEs.\n")

    print(
        f"{'source':<8}"
        f"{'true positives':>17}"
        f"{'false positives':>18}"
        f"{'false negatives':>18}"
        f"{'precision':>12}"
        f"{'recall':>10}"
        f"{'F1 score':>11}"
    )
    print("-" * 96)

    for r in reports:
        tp = fp = fn = 0
        for s in r.samples:
            if s.error:
                continue
            cons = consensus.get(s.cpe, set())
            flagged = set(s.cve_ids) if s.affected > 0 else set()
            tp += len(flagged & cons)
            fp += len(flagged - cons)
            fn += len(cons - flagged)

        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        print(
            f"{r.name:<8}"
            f"{tp:>17}"
            f"{fp:>18}"
            f"{fn:>18}"
            f"{prec * 100:>11.1f}%"
            f"{rec * 100:>9.1f}%"
            f"{f1 * 100:>10.1f}%"
        )

    print(
        "\n  true positives  = source flagged a CVE that another source also flagged."
    )
    print(
        "  false positives = source flagged a CVE no other source corroborated"
        " (could be a real unique find)."
    )
    print(
        "  false negatives = the consensus contains a CVE this source missed."
    )
    print(
        "  precision = true positives / (true positives + false positives)."
    )
    print(
        "  recall    = true positives / (true positives + false negatives)."
    )
    print(
        "  F1 score  = harmonic mean of precision and recall."
    )


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


def _print_ai_scores(reports: List[SourceReport]) -> None:
    ai = next((r for r in reports if r.name == "AI" and r.health), None)
    if ai is None:
        return
    scores: List[float] = []
    for s in ai.samples:
        scores.extend(s.base_scores)
    if not scores:
        return
    print("\n=== AI source predicted CVSS distribution ==================================")
    print(
        f"  samples: {len(scores)}    minimum: {min(scores):.1f}    "
        f"mean: {statistics.mean(scores):.2f}    "
        f"median: {statistics.median(scores):.1f}    "
        f"maximum: {max(scores):.1f}"
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

async def main(runs: int) -> None:
    settings.ai.enabled = True

    sources: List[VulnerabilitySource] = [
        EUVDSource(), OSVSource(), NVDSource(), GitHubSource(), LocalAISource(),
    ]

    print(f"Benchmarking {len(sources)} sources × {len(CPE_FIXTURE)} CPEs × {runs} runs")
    overall_start = time.perf_counter()

    health = await asyncio.gather(*[_check_health(s) for s in sources])
    reports: List[SourceReport] = []
    for src, ok in zip(sources, health):
        reports.append(SourceReport(name=src.name, health=ok))
        print(f"  {src.name:<8} health: {'UP' if ok else 'DOWN'}")

    print("\nRunning queries...")
    for src, report in zip(sources, reports):
        for cpe in CPE_FIXTURE:
            for _ in range(runs):
                report.samples.append(await _bench_one(src, cpe))
        print(f"  {src.name:<8} done — errors={report.errors:>2}, "
              f"hits={report.hits:>2}/{len(CPE_FIXTURE)}, "
              f"CVEs={report.total_returned:>4}, "
              f"aff={report.total_affected:>4}")

    _print_summary(reports, len(CPE_FIXTURE))
    _print_consensus_metrics(reports)
    _print_consensus(reports, len(CPE_FIXTURE))
    _print_jaccard(reports)
    _print_ai_scores(reports)
    if runs == 1:
        _print_per_cpe(reports)

    overall = time.perf_counter() - overall_start
    print(f"\nTotal wall time: {overall:.1f}s")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=1,
                        help="number of runs per (source, cpe) pair")
    args = parser.parse_args()
    asyncio.run(main(args.runs))
