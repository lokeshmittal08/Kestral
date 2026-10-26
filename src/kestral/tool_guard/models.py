"""Re-exports of tool-guard-related data models.

The models themselves live in ``kestral.models`` so that
``ScanReport.scan_context`` can reference ``ScanContext`` without a
circular import. This module exists so consumers can import the whole
tool-guard namespace from one place:

    from kestral.tool_guard.models import (
        ScanContext,
        ToolProvenance,
        ToolResultAttackFamily,
    )
"""

from __future__ import annotations

from kestral.models import (
    ScanContext,
    ToolProvenance,
    ToolResultAttackFamily,
)

__all__ = [
    "ScanContext",
    "ToolProvenance",
    "ToolResultAttackFamily",
]
