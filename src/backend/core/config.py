"""Configuration management — loads .env and exposes a singleton ``settings``."""
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

import httpx

try:
    from dotenv import load_dotenv

    env_path = Path(__file__).parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path, override=True)
except ImportError:
    pass


def _normalize_db_url(url: str) -> str:
    """Force the pymysql driver — avoids defaulting to the absent ``MySQLdb``."""
    if url.startswith("mysql://"):
        return "mysql+pymysql://" + url[len("mysql://"):]
    return url


@dataclass
class DatabaseConfig:
    url: str = field(default_factory=lambda: _normalize_db_url(os.getenv(
        "DATABASE_URL",
        "mysql+pymysql://root:password@localhost:3306/cve_database",
    )))
    echo: bool = field(default_factory=lambda: os.getenv("DB_ECHO", "false").lower() == "true")
    pool_size: int = field(default_factory=lambda: int(os.getenv("DB_POOL_SIZE", "10")))
    max_overflow: int = field(default_factory=lambda: int(os.getenv("DB_MAX_OVERFLOW", "20")))


@dataclass
class SourcesConfig:
    euvd_base_url: str = "https://euvdservices.enisa.europa.eu/api"
    osv_api_base: str = "https://api.osv.dev/v1/query"
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    github_api_url: str = "https://api.github.com/graphql"

    nvd_api_key: Optional[str] = field(default_factory=lambda: os.getenv("NVD_API_KEY"))
    github_token: Optional[str] = field(default_factory=lambda: os.getenv("GITHUB_TOKEN"))
    euvd_api_key: Optional[str] = field(default_factory=lambda: os.getenv("EUVD_API_KEY"))

    timeout: float = field(default_factory=lambda: float(os.getenv("HTTP_TIMEOUT", "30.0")))
    max_retries: int = field(default_factory=lambda: int(os.getenv("HTTP_MAX_RETRIES", "3")))
    retry_backoff: float = field(default_factory=lambda: float(os.getenv("HTTP_RETRY_BACKOFF", "0.5")))


@dataclass
class AIConfig:
    enabled: bool = field(default_factory=lambda: os.getenv("AI_FALLBACK_ENABLED", "false").lower() == "true")


@dataclass
class AppConfig:
    title: str = "Pradeo Vulnerability Aggregator"
    version: str = "2.0.0"
    debug: bool = field(default_factory=lambda: os.getenv("DEBUG", "false").lower() == "true")
    workers: int = field(default_factory=lambda: int(os.getenv("WORKERS", "4")))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))


class Settings:
    def __init__(self):
        self.database = DatabaseConfig()
        self.sources = SourcesConfig()
        self.ai = AIConfig()
        self.app = AppConfig()
        self.base_dir = Path(__file__).parent.parent


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()


# Source URL constants (used by sources/*.py)
EUVD_BASE = settings.sources.euvd_base_url
EUVD_CSV_DUMP = f"{EUVD_BASE}/dump/cve-euvd-mapping"
EUVD_SEARCH = f"{EUVD_BASE}/search"
EUVD_BY_ID = f"{EUVD_BASE}/enisaid"
EUVD_LAST = f"{EUVD_BASE}/lastvulnerabilities"
EUVD_EXPLOITED = f"{EUVD_BASE}/exploitedvulnerabilities"
EUVD_CRITICAL = f"{EUVD_BASE}/criticalvulnerabilities"

OSV_API_BASE = settings.sources.osv_api_base
NVD_API_BASE = settings.sources.nvd_api_base
NVD_API_KEY = settings.sources.nvd_api_key
GITHUB_TOKEN = settings.sources.github_token


def make_client() -> httpx.AsyncClient:
    """Create a shared async HTTP client with sane defaults."""
    return httpx.AsyncClient(
        follow_redirects=True,
        timeout=settings.sources.timeout,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    )
