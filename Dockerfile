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
FROM rust:slim-bookworm AS backend-builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace configuration and all Rust source trees
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY apps/ apps/
COPY tests/ tests/
COPY profiles/ profiles/
COPY config/ config/

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
RUN mkdir -p /data/artifacts /data/evidence

# Copy compiled binary from backend builder
COPY --from=backend-builder /app/target/release/forensic-api /usr/local/bin/forensic-api

# Copy OEM profiles
COPY --from=backend-builder /app/profiles /app/profiles

# Copy static frontend build into expected candidate search paths
COPY --from=frontend-builder /app/frontend/dist /app/dist
COPY --from=frontend-builder /app/frontend/dist /app/apps/frontend/dist

# Default cloud configuration (listening on 0.0.0.0:10000 or $PORT)
ENV HOST=0.0.0.0
ENV PORT=10000
ENV DATABASE_URL=sqlite:/data/forensic_metadata.db
ENV VIDFORGE_ARTIFACTS_DIR=/data/artifacts
ENV VIDFORGE_EVIDENCE_DIR=/data/evidence
ENV VIDFORGE_PROFILES_DIR=/app/profiles

# Expose HTTP service port
EXPOSE 10000

# Persistent volume for cases, databases, and recovered video artifacts
VOLUME ["/data"]

ENTRYPOINT ["forensic-api"]
