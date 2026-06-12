# Multi-stage build for the nopwd API.
# Build from the repo root: docker build -f crates/nopass-api/Dockerfile .

FROM rust:1.93-slim AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN cargo build --release -p nopass-api

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 nopass

COPY --from=builder /build/target/release/nopass-api /usr/local/bin/nopass-api

USER nopass
EXPOSE 3001
# Migrations run automatically on startup
ENTRYPOINT ["nopass-api"]
