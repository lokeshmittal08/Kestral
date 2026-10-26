"""Kestral: prompt injection firewall for AI agents."""

from kestral.engine import KestralEngine
from kestral.models import (
    Action,
    DetectionResult,
    MatchDetail,
    ScanContext,
    ScanReport,
    Severity,
    ThreatEntry,
    ThreatFeed,
    ToolProvenance,
    ToolResultAttackFamily,
)
from kestral.tool_guard import ToolResultGuard, scan_tool_result

__version__ = "0.8.1"

__all__ = [
    "Action",
    "KestralEngine",
    "DetectionResult",
    "MatchDetail",
    "ScanContext",
    "ScanReport",
    "Severity",
    "ThreatEntry",
    "ThreatFeed",
    "ToolProvenance",
    "ToolResultAttackFamily",
    "ToolResultGuard",
    "__version__",
    "scan_tool_result",
]
