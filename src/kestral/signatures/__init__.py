"""Federated threat-intel feed client for kestral.

Fetches and verifies an ed25519-signed feed of known prompt-injection
attack patterns. No feed is configured by default: supply your own feed
URL and public key.

Quick start (verify only)::

    from kestral.signatures import SignaturesClient

    client = SignaturesClient()
    update = client.fetch()
    print(update)  # SignaturesUpdate(success=True, signature_count=56, ...)

End-to-end (verify + apply to a live engine)::

    from kestral import KestralEngine
    from kestral.signatures import MAINTAINER_PUBLIC_KEY, apply_to_engine

    engine = KestralEngine()
    result = apply_to_engine(
        engine,
        feed_url="https://feeds.example.com/v1/signatures.json",
        public_key=MAINTAINER_PUBLIC_KEY,
    )
    # {'signature_count': 56, 'verified': True, 'source_url': ..., 'loaded_rules': 56}

``apply_to_engine`` is a thin bridge that runs ``SignaturesClient.fetch()``
(which verifies the detached minisign signature) and then loads the
verified regex signatures into the engine's ``d030_custom_rules`` detector.
It never writes to the engine unless verification succeeds.
"""

from kestral.signatures.apply_to_engine import apply_to_engine
from kestral.signatures.client import (
    DEFAULT_FEED_URL,
    DEFAULT_SIG_URL,
    MAINTAINER_PUBLIC_KEY,
    SignaturesClient,
    SignaturesUpdate,
    SignatureVerificationError,
)

__all__ = [
    "DEFAULT_FEED_URL",
    "DEFAULT_SIG_URL",
    "MAINTAINER_PUBLIC_KEY",
    "SignatureVerificationError",
    "SignaturesClient",
    "SignaturesUpdate",
    "apply_to_engine",
]
