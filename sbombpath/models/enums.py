"""Enum types for findings and risk."""

from __future__ import annotations

from enum import Enum


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class FindingStatus(str, Enum):
    EXPLOITABLE = "EXPLOITABLE"
    MITIGATED = "MITIGATED"
    UNKNOWN = "UNKNOWN"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    AT_RISK = "AT_RISK"


class ExposureKind(str, Enum):
    """How the finding can be abused — independent of HTTP route mapping."""

    USER_FACING = "USER_FACING"
    # User-controlled input reaches a dangerous sink via a mapped HTTP route.

    INTERNAL_TAINT = "INTERNAL_TAINT"
    # Contaminated data flows to a sink inside the app, but no clear public route
    # (jobs, webhooks-without-map, internal callers, helpers).

    PACKAGE_SURFACE = "PACKAGE_SURFACE"
    # A reported-CVE / generic dangerous API is used in code. Even without a
    # proven user→sink path, a compromised or misused package call site matters.
