"""Django middleware for kestral HTTP request scanning."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from kestral.engine import KestralEngine
from kestral.models import Action

if TYPE_CHECKING:
    from collections.abc import Callable


class KestralMiddleware:
    """Django middleware that scans request bodies for prompt injection."""

    def __init__(self, get_response: Callable[..., Any]) -> None:
        self.get_response = get_response
        self.engine = KestralEngine()
        self.scan_fields = ["prompt", "messages.*.content"]

    def __call__(self, request: Any) -> Any:
        if request.method not in ("POST", "PUT", "PATCH"):
            return self.get_response(request)

        try:
            body = json.loads(request.body)
        except Exception:
            # A body declared as JSON (or with no declared type) that does
            # not parse is rejected: forwarding it would skip the scan.
            content_type = getattr(request, "content_type", "") or ""
            if request.body and (not content_type or "json" in content_type.lower()):
                from django.http import JsonResponse

                return JsonResponse({"error": "Unparseable request body"}, status=400)
            return self.get_response(request)

        texts = self._extract_fields(body)
        for text in texts:
            if not text or not isinstance(text, str):
                continue
            report = self.engine.scan(text, context={"gate": "http", "source": "django"})
            if report.action == Action.BLOCK:
                from django.http import JsonResponse

                return JsonResponse(
                    {"error": "Prompt injection detected", "scan_id": report.scan_id},
                    status=400,
                )

        return self.get_response(request)

    def _extract_fields(self, body: Any) -> list[str]:
        texts: list[str] = []
        for field_path in self.scan_fields:
            parts = field_path.split(".")
            texts.extend(self._resolve_path(body, parts))
        return texts

    def _resolve_path(self, obj: Any, parts: list[str]) -> list[str]:
        if not parts:
            return [str(obj)] if obj else []
        key = parts[0]
        rest = parts[1:]
        if key == "*" and isinstance(obj, list):
            results: list[str] = []
            for item in obj:
                results.extend(self._resolve_path(item, rest))
            return results
        if isinstance(obj, dict) and key in obj:
            return self._resolve_path(obj[key], rest)
        return []
