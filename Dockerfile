# =============================================================================
# Kestral service image: REST API and gateway on port 8000
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: build. Install the package and its dependencies into a prefix.
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

# Compilers for any dependency without a prebuilt wheel
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc g++ && \
    rm -rf /var/lib/apt/lists/*

# CPU-only PyTorch. The default x86-64 wheel bundles GPU libraries the
# service does not use and adds several gigabytes to the image.
RUN pip install --no-cache-dir --prefix=/install torch \
    --index-url https://download.pytorch.org/whl/cpu

COPY pyproject.toml README.md ./
COPY src/ ./src/

# The service, PDF reading and OCR for images
RUN PYTHONPATH=/install/lib/python3.12/site-packages \
    pip install --no-cache-dir --prefix=/install ".[fastapi,documents]" "uvicorn[standard]>=0.20"

# Ship the classifier in the image, at the version the published figures were
# measured with, so the running service never downloads a model.
# --build-arg WITH_SECOND_OPINION=true also ships the optional second classifier.
ARG WITH_SECOND_OPINION=false
# Only the files the classifier loads, over plain HTTPS (the Xet transfer
# service is often blocked by corporate proxies).
ENV HF_HOME=/opt/kestral/hf \
    HF_HUB_DISABLE_XET=1
RUN PYTHONPATH=/install/lib/python3.12/site-packages python -c "\
from huggingface_hub import snapshot_download; \
files = ['config.json', '*.safetensors', 'spm.model', 'tokenizer*.json', \
         'special_tokens_map.json', 'added_tokens.json']; \
snapshot_download('protectai/deberta-v3-base-prompt-injection-v2', \
                  revision='90c9989b1a342275dd0d1a95aad283c04e075671', allow_patterns=files); \
'${WITH_SECOND_OPINION}' == 'true' and snapshot_download('deepset/deberta-v3-base-injection', \
                  revision='80dda00d0b0d9a03917a7685e2ddbcd28e04dbb1', allow_patterns=files)"

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim

LABEL org.opencontainers.image.title="kestral" \
      org.opencontainers.image.description="Prompt injection firewall for AI agents" \
      org.opencontainers.image.licenses="Apache-2.0"

# curl for the health check; libgl1 and libglib2.0-0 for the OCR engine
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl libgl1 libglib2.0-0 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

# Run as a non-root user
RUN groupadd --gid 1000 kestral && \
    useradd --uid 1000 --gid kestral --create-home kestral

# The models baked in the build stage. The service runs offline: it loads
# them from here and never reaches the model hub.
COPY --from=builder --chown=kestral:kestral /opt/kestral/hf /opt/kestral/hf

# Writable directory for local state.
RUN mkdir -p /home/kestral/data /home/kestral/.cache && chown -R kestral:kestral /home/kestral

USER kestral
WORKDIR /home/kestral

ENV KESTRAL_DATA_DIR=/home/kestral/data \
    HF_HOME=/opt/kestral/hf \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Liveness only. Use /readyz to know when the ML classifier has loaded.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/livez || exit 1

EXPOSE 8000

# Default: run the REST API server.
# Override for the CLI:  docker run --entrypoint kestral kestral scan "text"
ENTRYPOINT ["python", "-m", "kestral.api"]
