import re
import logging
from packaging.version import Version, InvalidVersion

logger = logging.getLogger(__name__)


def _parse_version_safe(v: str) -> Version | None:
    if not v:
        return None
    v = str(v).strip()
    v = re.sub(r'^v', '', v, flags=re.IGNORECASE)
    m = re.search(r'(\d+(?:\.\d+)*)', v)
    if not m:
        return None
    try:
        return Version(m.group(1))
    except InvalidVersion:
        return None


_PLACEHOLDER_VERSIONS = {
    "", "*", "-", "all", "all versions", "any",
    "n/a", "na", "unspecified", "unknown",
}


def version_is_affected(product_version_str: str, target_version: str) -> bool:
    """Decide whether ``target_version`` falls inside ``product_version_str``.

    A range string with multiple comma-joined clauses (e.g. ``">= 2.0, < 2.16"``)
    is interpreted as conjunction — every clause must hold.

    Placeholder ranges (empty / ``*`` / ``unknown`` / ``any`` / etc.) used to
    return ``True`` and were responsible for most of the EUVD/GitHub false
    positives. They now return ``False`` — without a real range we can't claim
    a specific version is affected.
    """
    pv = str(product_version_str).strip()
    tv = str(target_version).strip()

    if "," in pv:
        clauses = [c.strip() for c in pv.split(",") if c.strip()]
        return bool(clauses) and all(version_is_affected(c, tv) for c in clauses)

    if pv.lower() in _PLACEHOLDER_VERSIONS:
        return False

    if pv.lower().startswith("patch:"):
        fixed_str = pv.split(":", 1)[1].strip()
        if not fixed_str or fixed_str.lower() in _PLACEHOLDER_VERSIONS:
            return False
        fixed = _parse_version_safe(fixed_str)
        target = _parse_version_safe(tv)
        return bool(fixed and target and target < fixed)

    target = _parse_version_safe(tv)
    if not target:
        return False

    pv = pv.replace("≤", "<=").replace("≥", ">=")
    pv = re.sub(r'^[A-Za-z][A-Za-z0-9_.\-]*\s+', '', pv).strip()
    pv = re.sub(r'\bbefore\b\s+', '< ', pv, flags=re.IGNORECASE)
    pv = re.sub(r'\.x\s+before\s+', ' < ', pv, flags=re.IGNORECASE)
    pv = re.sub(r'\s+to\s+', ' <= ', pv, flags=re.IGNORECASE)
    pv = re.sub(r'\s+-\s+', ' <= ', pv)
    pv = re.sub(r'(?<=[\d])\s+[A-Za-z].*$', '', pv).strip()
    pv = re.sub(r'(?<![A-Za-z])v(\d)', r'\1', pv)

    series_match = re.match(r'^(\d+\.\d+)(?:\.x)?\s+series$', pv, re.IGNORECASE)
    if series_match:
        base = _parse_version_safe(series_match.group(1))
        if base:
            return target.major == base.major and target.minor == base.minor

    try:
        if "<=" in pv:
            parts = pv.split("<=")
            upper = _parse_version_safe(parts[-1])
            lower = _parse_version_safe(parts[0]) if parts[0].strip() else None
            if upper:
                return (lower <= target <= upper) if lower else (target <= upper)

        if "<" in pv:
            parts = pv.split("<")
            upper = _parse_version_safe(parts[-1])
            lower = _parse_version_safe(parts[0]) if parts[0].strip() else None
            if upper:
                return (lower <= target < upper) if lower else (target < upper)

        if ">=" in pv:
            lower = _parse_version_safe(pv.split(">=")[-1])
            if lower:
                return target >= lower

        if ">" in pv:
            lower = _parse_version_safe(pv.split(">")[-1])
            if lower:
                return target > lower

        exact = _parse_version_safe(pv)
        if exact:
            return target == exact

    except Exception as e:
        logger.debug(f"Version compare error: '{pv}' vs '{tv}' → {e}")

    return False


_GENERIC_SUFFIXES = {"core", "api", "impl", "all", "common", "commons"}
_QUALIFIERS = {"extras", "plugin", "plugins", "fips", "fja", "lts",
               "starter", "test", "client", "server", "example"}


def _product_tokens(name: str) -> list[str]:
    """Tokenize a product name into lowercase alphanumeric tokens."""
    return [t for t in re.split(r'[\s\-_./]+', name.lower()) if t]


def _token_match(name_token: str, hint_token: str) -> bool:
    """True if ``name_token`` is the same token as ``hint_token`` modulo a
    trailing version digit (so ``log4j2`` matches ``log4j``)."""
    if name_token == hint_token:
        return True
    name_base = re.sub(r'\d+$', '', name_token)
    hint_base = re.sub(r'\d+$', '', hint_token)
    return bool(name_base) and name_base == hint_base


def _product_matches(euvd_name: str, hint: str) -> bool:
    """Verify the EUVD product entry corresponds to ``hint``.

    Rules:
      * every *significant* token in ``hint`` (i.e. after dropping generic
        suffixes like ``core``/``api``) must have a corresponding token in
        ``euvd_name`` (digit-suffix variants allowed: ``log4j2`` ~ ``log4j``);
      * ``euvd_name`` must not introduce known qualifier tokens that are
        absent from ``hint`` (e.g. ``extras``, ``plugin``, ``fips``).
    """
    if not hint:
        return True
    hint_tokens = set(_product_tokens(hint))
    name_tokens = set(_product_tokens(euvd_name))
    if not hint_tokens or not name_tokens:
        return False

    significant = hint_tokens - _GENERIC_SUFFIXES or hint_tokens
    for h in significant:
        if not any(_token_match(n, h) for n in name_tokens):
            return False

    if (name_tokens - hint_tokens) & _QUALIFIERS:
        return False
    return True


def item_affects_version(euvd_item: dict, target_version: str,
                          product_hint: str = "") -> bool:
    """Return True if ``euvd_item`` lists a product matching ``product_hint``
    whose vulnerable range contains ``target_version``.

    A missing product list is treated as *not affected* — a CVSS score alone
    is not enough to claim a specific version is impacted.
    """
    products = euvd_item.get("enisaIdProduct", [])
    if not products:
        return False

    for entry in products:
        product_name = entry.get("product", {}).get("name", "")
        pv = entry.get("product_version", "")

        if not _product_matches(product_name, product_hint):
            continue
        if version_is_affected(pv, target_version):
            return True

    return False