"""Sources package - vulnerability source adapters."""
from .base import VulnerabilitySource
from .euvd import EUVDSource
from .github import GitHubSource
from .nvd import NVDSource
from .osv import OSVSource

__all__ = [
    "VulnerabilitySource",
    "EUVDSource",
    "OSVSource",
    "NVDSource",
    "GitHubSource",
]
