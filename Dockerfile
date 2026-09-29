# syntax=docker/dockerfile:1

# ==============================================================================
# Stage 1: Build Frontend (React + Vite SPA)
# ==============================================================================
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY apps/frontend/package*.json ./
RUN npm ci

COPY apps/frontend/ ./
RUN npm run build

# ==============================================================================
# Stage 2: Build Backend (Rust / Axum)
# ==============================================================================
FROM rust:1.80-slim-bookworm AS backend-builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace manifests
COPY Cargo.toml Cargo.lock ./
COPY crates/core/Cargo.toml crates/core/
COPY crates/acquisition/Cargo.toml crates/acquisition/
COPY crates/detection/Cargo.toml crates/detection/
COPY crates/parsers/Cargo.toml crates/parsers/
COPY crates/recovery/Cargo.toml crates/recovery/
COPY crates/media/Cargo.toml crates/media/
COPY crates/timeline/Cargo.toml crates/timeline/
COPY crates/pipeline/Cargo.toml crates/pipeline/
COPY apps/api/Cargo.toml apps/api/
COPY apps/desktop/Cargo.toml apps/desktop/

# Copy all source trees
COPY crates/ crates/
COPY apps/api/ apps/api/
COPY apps/desktop/ apps/desktop/

# Compile production release binary for the forensic-api service
RUN cargo build --release -p forensic-api

# ==============================================================================
# Stage 3: Minimal Production Runtime
# ==============================================================================
FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    ffmpeg \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create persistent storage directories
RUN mkdir -p /data/artifacts /data/evidence /data/profiles

# Copy compiled binary from backend builder
COPY --from=backend-builder /app/target/release/forensic-api /usr/local/bin/forensic-api

# Copy static frontend build into expected candidate search paths
COPY --from=frontend-builder /app/frontend/dist /app/dist
COPY --from=frontend-builder /app/frontend/dist /app/apps/frontend/dist

# Default cloud configuration (listening on 0.0.0.0:3000)
ENV HOST=0.0.0.0
ENV PORT=3000
ENV DATABASE_URL=sqlite:/data/forensic_metadata.db
ENV VIDFORGE_ARTIFACTS_DIR=/data/artifacts
ENV VIDFORGE_EVIDENCE_DIR=/data/evidence
ENV VIDFORGE_PROFILES_DIR=/data/profiles

# Expose HTTP service port
EXPOSE 3000

# Persistent volume for cases, databases, and recovered video artifacts
VOLUME ["/data"]

ENTRYPOINT ["forensic-api"]
