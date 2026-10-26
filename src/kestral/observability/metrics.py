"""Prometheus metrics implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from kestral.models import ScanReport


def is_available() -> bool:
    """True if prometheus_client is importable."""
    try:
        import prometheus_client  # noqa: F401

        return True
    except ImportError:
        return False


class KestralMetrics:
    """Prometheus counters and histograms for kestral scans.

    Each scan reports:
    - scans_total (counter, labelled by action: block/flag/log/pass)
    - detections_total (counter, labelled by detector_id and severity)
    - scan_duration_seconds (histogram)
    - scan_input_size_chars (histogram)
    - scan_input_size_tokens (histogram)

    Counters and histograms are registered with the default Prometheus
    registry by default. Pass a custom registry if you want isolation
    (e.g. per-tenant metrics).
    """

    def __init__(self, registry: object | None = None) -> None:
        try:
            from prometheus_client import REGISTRY, Counter, Histogram
        except ImportError as exc:
            raise ImportError(
                "prometheus_client is required for KestralMetrics. "
                "Install with: pip install kestral[observability]"
            ) from exc

        reg: Any = registry if registry is not None else REGISTRY

        self.scans_total = Counter(
            "kestral_scans_total",
            "Total scans performed, by final action.",
            labelnames=["action"],
            registry=reg,
        )
        self.detections_total = Counter(
            "kestral_detections_total",
            "Total positive detections, by detector and severity.",
            labelnames=["detector_id", "severity"],
            registry=reg,
        )
        self.scan_duration_seconds = Histogram(
            "kestral_scan_duration_seconds",
            "Wall-clock time per scan.",
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
            registry=reg,
        )
        self.scan_input_size_chars = Histogram(
            "kestral_scan_input_size_chars",
            "Distribution of scanned input sizes in characters.",
            buckets=(16, 64, 256, 1024, 4096, 16384, 65536, 262144),
            registry=reg,
        )
        self.scan_input_size_tokens = Histogram(
            "kestral_scan_input_size_tokens",
            "Distribution of scanned input sizes in whitespace tokens.",
            buckets=(4, 16, 64, 256, 1024, 4096, 16384),
            registry=reg,
        )

    def record_scan(self, report: ScanReport) -> None:
        """Update counters and histograms from a single ScanReport."""
        self.scans_total.labels(action=report.action.value).inc()
        for d in report.detections:
            self.detections_total.labels(
                detector_id=d.detector_id,
                severity=d.severity.value,
            ).inc()
        # scan_duration_ms is in milliseconds; convert to seconds.
        self.scan_duration_seconds.observe(report.scan_duration_ms / 1000.0)
        if report.char_count > 0:
            self.scan_input_size_chars.observe(report.char_count)
        if report.token_count > 0:
            self.scan_input_size_tokens.observe(report.token_count)

    def expose(self) -> tuple[bytes, str]:
        """Return (body, content_type) suitable for an HTTP /metrics handler.

        Example FastAPI route:

            from kestral.observability import KestralMetrics
            metrics = KestralMetrics()

            @app.get("/metrics")
            def metrics_endpoint():
                body, ct = metrics.expose()
                return Response(content=body, media_type=ct)
        """
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        return generate_latest(), CONTENT_TYPE_LATEST
