"""Semantic ML-based prompt injection classifier."""

from __future__ import annotations

import hashlib
import logging
import threading
from collections import OrderedDict
from typing import Any, ClassVar

from kestral.detectors.base import BaseDetector
from kestral.models import DetectionResult, MatchDetail, Severity

logger = logging.getLogger("kestral.detectors.d022")

_DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
_BATCH_SIZE = 32
_PRIMED_MAX = 4096


class SemanticClassifierDetector(BaseDetector):
    """Uses a pre-trained transformer to classify prompt injection semantically.

    Requires the ``ml`` extra: ``pip install kestral[ml]``.
    If the *transformers* library is not installed, or the model cannot be
    loaded, this detector returns ``detected=False`` on every call and
    reports itself through :attr:`degraded` so the engine can say so.
    """

    detector_id: str = "d022_semantic_classifier"
    name: str = "Semantic Classifier"
    description: str = (
        "ML-based semantic prompt injection detection using a pre-trained transformer classifier"
    )
    severity: Severity = Severity.HIGH
    tags: ClassVar[list[str]] = ["ml", "semantic"]
    version: str = "1.0.0"
    author: str = "kestral"

    def __init__(self) -> None:
        self._pipeline: Any | None = None
        self._model_name: str = _DEFAULT_MODEL
        self._device: str = "cpu"
        self._available: bool | None = None  # None = not checked yet
        # Chunking defaults; setup() may override.
        self._chunk_size: int = 512
        self._chunk_stride: int = 384
        self._max_chunks: int = 8
        self._batch_size: int = _BATCH_SIZE
        # Results computed ahead of detect() by prime(), keyed by a hash of
        # the text. Each entry is used once.
        self._primed: OrderedDict[str, DetectionResult] = OrderedDict()
        self._primed_lock = threading.Lock()

    @property
    def degraded(self) -> bool:
        """True when the model could not be loaded and every call returns not-detected."""
        return self._available is False

    def setup(self, config: dict[str, object]) -> None:
        """Read model_name and device from per-detector config."""
        self._model_name = str(config.get("model_name", _DEFAULT_MODEL))
        self._device = str(config.get("device", "cpu"))
        # Long-input handling: chunk + max-pool aggregation.
        # Window = 512 chars (the model's per-call cap), stride = 384 chars
        # (75% overlap, so each token is scored in at least two windows).
        # Max chunks bounds wall-clock; the model is ~10ms per call on CPU,
        # so 8 chunks = ~80ms worst case for very long inputs.
        chunk_size = config.get("chunk_size", 512)
        chunk_stride = config.get("chunk_stride", 384)
        max_chunks = config.get("max_chunks", 8)
        self._chunk_size = int(chunk_size) if isinstance(chunk_size, (int, float, str)) else 512
        self._chunk_stride = (
            int(chunk_stride) if isinstance(chunk_stride, (int, float, str)) else 384
        )
        self._max_chunks = int(max_chunks) if isinstance(max_chunks, (int, float, str)) else 8
        batch_size = config.get("batch_size", _BATCH_SIZE)
        self._batch_size = (
            max(1, int(batch_size)) if isinstance(batch_size, (int, float, str)) else _BATCH_SIZE
        )

    def _ensure_pipeline(self) -> bool:
        """Lazy-load the classification pipeline. Returns True if available."""
        if self._available is not None:
            return self._available
        try:
            from transformers import pipeline as hf_pipeline

            device_arg = -1 if self._device == "cpu" else int(self._device.split(":")[-1])
            self._pipeline = hf_pipeline(
                "text-classification",
                model=self._model_name,
                device=device_arg,
                truncation=True,
                max_length=512,
            )
            self._available = True
            logger.info("Loaded semantic classifier: %s", self._model_name)
        except ImportError:
            logger.warning(
                "d022 semantic classifier disabled: transformers not installed. "
                "Install with `pip install kestral[ml]` to enable ML-based "
                "paraphrase detection. Without it, obfuscated attacks may bypass "
                "regex-only detection."
            )
            self._available = False
        except Exception as exc:
            logger.warning(
                "Failed to load semantic classifier %s: %s. d022 is degraded: it reports "
                "nothing detected on every input until the model can be loaded.",
                self._model_name,
                exc,
            )
            self._available = False
        return self._available

    def _unavailable(self) -> DetectionResult:
        return DetectionResult(
            detector_id=self.detector_id,
            detected=False,
            confidence=0.0,
            severity=self.severity,
            explanation=("ML classifier not available (transformers not installed)"),
        )

    def _failed(self, exc: Exception) -> DetectionResult:
        logger.warning("Semantic classification failed: %s", exc)
        return DetectionResult(
            detector_id=self.detector_id,
            detected=False,
            confidence=0.0,
            severity=self.severity,
            explanation=f"Classification failed: {exc}",
        )

    @staticmethod
    def _key(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()

    def detect(self, input_text: str, context: dict[str, object] | None = None) -> DetectionResult:
        if not self._ensure_pipeline():
            return self._unavailable()
        if self._primed:
            with self._primed_lock:
                primed = self._primed.pop(self._key(input_text), None)
            if primed is not None:
                return primed

        try:
            # Chunk long inputs with overlap; score each chunk; max-pool the
            # confidences. Previously the d022 detector truncated to 512 chars
            # and ignored anything beyond; injections placed late in a long
            # document slipped through.
            chunks = self._chunk(input_text)
            preds = []
            for _, _, chunk_text in chunks:
                pred = self._pipeline(chunk_text)
                preds.append((pred[0]["label"].upper(), float(pred[0]["score"])))
            return self._result(input_text, chunks, preds)
        except Exception as exc:
            return self._failed(exc)

    def classify_batch(self, texts: list[str]) -> list[DetectionResult]:
        """Same results as ``[detect(t) for t in texts]``, with the model run in batches.

        Batching is several times faster per text on CPU. Scores can differ
        from one-at-a-time scoring by about 1e-6 because of padding.
        """
        if not self._ensure_pipeline():
            return [self._unavailable() for _ in texts]
        try:
            return self._classify(texts)
        except Exception as exc:
            logger.warning("Batched classification failed, scoring one at a time: %s", exc)
            return [self.detect(text) for text in texts]

    def prime(self, texts: list[str]) -> None:
        """Score ``texts`` in batches now so that later detect() calls on them are cheap."""
        if not texts or not self._ensure_pipeline():
            return
        unique = list(dict.fromkeys(texts))
        try:
            results = self._classify(unique)
        except Exception as exc:
            # detect() scores each text on its own instead.
            logger.warning("Batched classification failed: %s", exc)
            return
        with self._primed_lock:
            for text, result in zip(unique, results, strict=True):
                self._primed[self._key(text)] = result
            while len(self._primed) > _PRIMED_MAX:
                self._primed.popitem(last=False)

    def _classify(self, texts: list[str]) -> list[DetectionResult]:
        """Score every chunk of every text in batches; raises if the model fails."""
        chunked = [self._chunk(text) for text in texts]
        flat = [chunk_text for chunks in chunked for _, _, chunk_text in chunks]
        # Similar lengths in a batch means less padding: faster, and closer
        # to the scores of unbatched calls.
        order = sorted(range(len(flat)), key=lambda i: len(flat[i]))
        preds: list[tuple[str, float]] = [("SAFE", 0.0)] * len(flat)
        if order:
            out = self._pipeline([flat[i] for i in order], batch_size=self._batch_size)
            for i, pred in zip(order, out, strict=True):
                if isinstance(pred, list):
                    pred = pred[0]
                preds[i] = (str(pred["label"]).upper(), float(pred["score"]))
        results = []
        offset = 0
        for text, chunks in zip(texts, chunked, strict=True):
            results.append(self._result(text, chunks, preds[offset : offset + len(chunks)]))
            offset += len(chunks)
        return results

    def _result(
        self,
        input_text: str,
        chunks: list[tuple[int, int, str]],
        preds: list[tuple[str, float]],
    ) -> DetectionResult:
        """Max-pool the chunk predictions into one result."""
        best_score = 0.0
        best_label = "SAFE"
        best_span = (0, min(len(input_text), self._chunk_size))
        for (start, end, _), (label, score) in zip(chunks, preds, strict=True):
            if label == "INJECTION" and score > best_score:
                best_score = score
                best_label = "INJECTION"
                best_span = (start, end)

        if best_label == "INJECTION" and best_score > 0.5:
            start, end = best_span
            return DetectionResult(
                detector_id=self.detector_id,
                detected=True,
                confidence=best_score,
                severity=self.severity,
                matches=[
                    MatchDetail(
                        pattern="semantic_classifier",
                        matched_text=input_text[start : start + min(120, end - start)]
                        + ("..." if end - start > 120 else ""),
                        position=best_span,
                        description=(
                            f"Classified as injection with score {best_score:.4f} "
                            f"on chunk [{start}:{end}]"
                        ),
                    )
                ],
                explanation=(
                    f"Semantic classifier detected injection "
                    f"(confidence: {best_score:.4f}, "
                    f"window [{start}:{end}] of {len(input_text)}-char input)"
                ),
            )

        return DetectionResult(
            detector_id=self.detector_id,
            detected=False,
            confidence=0.0,
            severity=self.severity,
            explanation=(
                f"Classified as safe across {len(chunks)} chunk(s) (max score: {best_score:.4f})"
            ),
        )

    def teardown(self) -> None:
        """Release model resources."""
        self._pipeline = None
        self._available = None
        with self._primed_lock:
            self._primed.clear()

    def _chunk(self, text: str) -> list[tuple[int, int, str]]:
        """Split text into overlapping windows for chunked scoring.

        Returns list of (start, end, text). For short inputs returns a single
        chunk. The max-pool aggregation in detect() takes the maximum
        injection-confidence across all chunks, so an attack in any window
        produces a detection.
        """
        if len(text) <= self._chunk_size:
            return [(0, len(text), text)]
        chunks: list[tuple[int, int, str]] = []
        start = 0
        while start < len(text) and len(chunks) < self._max_chunks:
            end = min(start + self._chunk_size, len(text))
            chunks.append((start, end, text[start:end]))
            if end >= len(text):
                break
            start += self._chunk_stride
        return chunks
