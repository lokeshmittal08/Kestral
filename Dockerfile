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

# Writable directory for local state. Models are downloaded on first start
# into /home/kestral/.cache; mount a volume there to keep them across restarts.
RUN mkdir -p /home/kestral/data /home/kestral/.cache && chown -R kestral:kestral /home/kestral

USER kestral
WORKDIR /home/kestral

ENV KESTRAL_DATA_DIR=/home/kestral/data \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Liveness only. Use /readyz to know when the ML classifier has loaded.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/livez || exit 1

EXPOSE 8000

# Default: run the REST API server.
# Override for the CLI:  docker run --entrypoint kestral kestral scan "text"
ENTRYPOINT ["python", "-m", "kestral.api"]
