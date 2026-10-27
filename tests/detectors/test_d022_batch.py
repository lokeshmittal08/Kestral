"""d022: batched classification, priming and the degraded flag."""

from __future__ import annotations

from typing import Any

import pytest

from kestral.detectors.d022_semantic_classifier import SemanticClassifierDetector


class _Pipe:
    def __init__(self, fail_batches: bool = False) -> None:
        self.calls: list[Any] = []
        self.fail_batches = fail_batches

    @staticmethod
    def _one(text: str) -> dict[str, Any]:
        score = 0.9 if "attack" in text else 0.8
        return {"label": "INJECTION" if "attack" in text else "SAFE", "score": score}

    def __call__(self, inputs: Any, **kwargs: Any) -> Any:
        self.calls.append((inputs, kwargs))
        if isinstance(inputs, list):
            if self.fail_batches:
                raise RuntimeError("batch failed")
            return [self._one(t) for t in inputs]
        return [self._one(inputs)]


@pytest.fixture
def detector():
    det = SemanticClassifierDetector()
    det.setup({})
    det._pipeline = _Pipe()
    det._available = True
    return det


TEXTS = [
    "a plain sentence about gardening",
    "an attack placed here",
    "x" * 1500 + " attack at the end of a long text",
    "short",
]


class TestClassifyBatch:
    def test_matches_detect(self, detector):
        batched = detector.classify_batch(TEXTS)
        single = [detector.detect(t) for t in TEXTS]
        assert [r.model_dump() for r in batched] == [r.model_dump() for r in single]

    def test_one_model_call_with_batch_size(self, detector):
        detector.classify_batch(TEXTS)
        assert len(detector._pipeline.calls) == 1
        inputs, kwargs = detector._pipeline.calls[0]
        assert kwargs == {"batch_size": 32}
        # Every chunk of every text, shortest first.
        assert len(inputs) == sum(len(detector._chunk(t)) for t in TEXTS)
        assert [len(x) for x in inputs] == sorted(len(x) for x in inputs)

    def test_batch_size_is_configurable(self, detector):
        detector.setup({"batch_size": 4})
        detector._pipeline = _Pipe()
        detector.classify_batch(TEXTS)
        assert detector._pipeline.calls[0][1] == {"batch_size": 4}

    def test_batch_failure_falls_back_to_single(self, detector):
        detector._pipeline = _Pipe(fail_batches=True)
        results = detector.classify_batch(TEXTS)
        assert [r.detected for r in results] == [False, True, True, False]

    def test_unavailable(self, detector):
        detector._available = False
        assert [r.detected for r in detector.classify_batch(TEXTS)] == [False] * 4


class TestPrime:
    def test_detect_uses_primed_result_once(self, detector):
        detector.prime(TEXTS)
        assert len(detector._pipeline.calls) == 1
        results = [detector.detect(t) for t in TEXTS]
        assert len(detector._pipeline.calls) == 1
        assert [r.detected for r in results] == [False, True, True, False]
        detector.detect(TEXTS[0])  # consumed: scored again
        assert len(detector._pipeline.calls) == 2

    def test_failed_batch_primes_nothing(self, detector):
        detector._pipeline = _Pipe(fail_batches=True)
        detector.prime(TEXTS)
        assert detector._primed == {}
        assert detector.detect(TEXTS[1]).detected is True

    def test_teardown_clears_primed(self, detector):
        detector.prime(TEXTS)
        detector.teardown()
        assert detector._primed == {}


class TestDegraded:
    def test_states(self, detector):
        assert detector.degraded is False
        detector._available = None
        assert detector.degraded is False  # not loaded yet
        detector._available = False
        assert detector.degraded is True

    def test_failed_load_is_degraded(self, monkeypatch):
        import transformers

        def broken(*args: Any, **kwargs: Any) -> Any:
            raise OSError("no such model")

        monkeypatch.setattr(transformers, "pipeline", broken)
        det = SemanticClassifierDetector()
        det.setup({"model_name": "nonexistent/model"})
        assert det.detect("anything").detected is False
        assert det.degraded is True
