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
