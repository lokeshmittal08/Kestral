"""Custom exceptions for kestral."""

from __future__ import annotations


class KestralError(Exception):
    """Base exception for all kestral errors."""


class ConfigError(KestralError):
    """Raised when configuration is invalid or cannot be loaded."""


class DetectorError(KestralError):
    """Raised when a detector fails during scanning."""


class RegistryError(KestralError):
    """Raised when detector registration or discovery fails."""


class VaultError(KestralError):
    """Raised when the attack vault encounters an error."""


class EmbedderError(KestralError):
    """Raised when embedding generation fails."""


class PersistenceError(KestralError):
    """Raised when database operations fail."""


class FeedbackError(KestralError):
    """Raised when feedback recording or processing fails."""


class ThreatFeedError(KestralError):
    """Raised when threat feed import/export/sync fails."""


class ScanError(KestralError):
    """Raised when a scan operation fails."""


class BenchmarkError(KestralError):
    """Raised when a benchmark operation fails."""
