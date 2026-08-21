# syntax=docker/dockerfile:1.7
# Multi-stage, non-root, BuildKit secret mounts, digest-pinned base images.

FROM python:3.11.9-slim@sha256:1bfd0f2b73b5b0e1d0f1e2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7 AS builder
WORKDIR /build
COPY requirements.txt .
# Build secrets are mounted, never baked into a layer (secretMode: buildkit).
RUN --mount=type=secret,id=pip_index,required=false \
    pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11.9-slim@sha256:1bfd0f2b73b5b0e1d0f1e2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7 AS runtime
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY --from=builder /install /usr/local
COPY --chown=appuser:appuser main.py ./
USER appuser
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
