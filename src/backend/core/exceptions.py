"""Exception types raised by the aggregator."""


class VulnerabilityError(Exception):
    """Base class for aggregator errors."""


class SourceError(VulnerabilityError):
    """Raised when a vulnerability source query fails."""

    def __init__(self, source: str, message: str, retryable: bool = True):
        self.source = source
        self.message = message
        self.retryable = retryable
        super().__init__(f"[{source}] {message}")
