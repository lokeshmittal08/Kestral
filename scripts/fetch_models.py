"""Download the pinned classifier models into the Hugging Face cache.

Used by CI so tests run against the real models at the revisions the
published figures were measured with. The Dockerfile bakes the same files.
"""

from __future__ import annotations

from huggingface_hub import snapshot_download

from kestral.detectors.d022_semantic_classifier import _DEFAULT_MODEL, _DEFAULT_REVISION
from kestral.inspector import SecondOpinion

FILES = [
    "config.json",
    "*.safetensors",
    "spm.model",
    "tokenizer*.json",
    "special_tokens_map.json",
    "added_tokens.json",
]

MODELS = [
    (_DEFAULT_MODEL, _DEFAULT_REVISION),
    (SecondOpinion.DEFAULT_MODEL, SecondOpinion.DEFAULT_REVISION),
]


def main() -> None:
    for name, revision in MODELS:
        path = snapshot_download(name, revision=revision, allow_patterns=FILES)
        print(f"{name}@{revision[:8]} -> {path}")


if __name__ == "__main__":
    main()
