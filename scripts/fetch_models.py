"""Download the pinned classifier models into the Hugging Face cache.

Used by CI so tests run against the real models at the revisions the
published figures were measured with. The Dockerfile bakes the same files.
"""

from __future__ import annotations

from huggingface_hub import snapshot_download

from kestral.detectors.d022_semantic_classifier import _DEFAULT_MODEL, _DEFAULT_REVISION
from kestral.detectors.d035_perplexity_spectral import _DEFAULT_MODEL as PERPLEXITY_MODEL
from kestral.inspector import SecondOpinion

FILES = [
    "config.json",
    "*.safetensors",
    "spm.model",
    "tokenizer*.json",
    "special_tokens_map.json",
    "added_tokens.json",
]

# GPT-2 tokenizers use a vocabulary and merges file instead of spm.model.
GPT2_FILES = [*FILES, "vocab.json", "merges.txt", "generation_config.json"]

MODELS: list[tuple[str, str | None, list[str]]] = [
    (_DEFAULT_MODEL, _DEFAULT_REVISION, FILES),
    (SecondOpinion.DEFAULT_MODEL, SecondOpinion.DEFAULT_REVISION, FILES),
    # d035 (off by default) has an integration test that loads its model.
    (PERPLEXITY_MODEL, None, GPT2_FILES),
]


def main() -> None:
    for name, revision, files in MODELS:
        path = snapshot_download(name, revision=revision, allow_patterns=files)
        print(f"{name}@{(revision or 'main')[:8]} -> {path}")


if __name__ == "__main__":
    main()
