"""Data sensitivity classification with fail-safe default (AARM R2).

AARM R2 requires that when a data classification cannot be determined, the
system defaults to the HIGHEST sensitivity level rather than treating the data
as unclassified/low. This closes the gap where an unrecognized action or input
would otherwise be handled as if it carried no sensitive data.

Sensitivity ordering (ascending): public < internal < confidential < restricted.
When classification is unavailable, callers use ``DEFAULT_SENSITIVITY`` =
"restricted" (the highest), so policy evaluation errs toward caution.
"""

# Ordered low -> high. Index = sensitivity rank.
SENSITIVITY_LEVELS = ["public", "internal", "confidential", "restricted"]

# Fail-safe default when classification cannot be determined (AARM R2):
# the HIGHEST sensitivity level.
DEFAULT_SENSITIVITY = "restricted"

# Map known data classes to a sensitivity level. Anything not listed inherits
# the fail-safe default via classify_sensitivity().
_DATA_CLASS_SENSITIVITY = {
    "pipeline_status": "internal",
    "build_results": "internal",
    "test_results": "internal",
    "deployment_config": "confidential",
    "credentials": "restricted",
    "secrets": "restricted",
    "pii": "restricted",
}


def classify_sensitivity(data_class: str) -> str:
    """Return the sensitivity level for a data class.

    Fails safe: an empty/unknown data class (classification unavailable)
    returns the highest sensitivity level (AARM R2), never "public".
    """
    if not data_class:
        return DEFAULT_SENSITIVITY
    return _DATA_CLASS_SENSITIVITY.get(data_class, DEFAULT_SENSITIVITY)


def sensitivity_rank(level: str) -> int:
    """Return the numeric rank of a sensitivity level (higher = more sensitive).

    Unknown levels rank as the maximum, so an unrecognized level is never
    treated as less sensitive than a known one.
    """
    try:
        return SENSITIVITY_LEVELS.index(level)
    except ValueError:
        return len(SENSITIVITY_LEVELS) - 1


def is_classification_available(data_class: str) -> bool:
    """True when a concrete data class was derived (not the fail-safe default)."""
    return bool(data_class)
