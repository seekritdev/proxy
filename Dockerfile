# syntax=docker/dockerfile:1
#
# seekrit-proxy — the egress proxy that swaps {{seekrit:NAME}} placeholders in a
# workload's outbound requests for decrypted secrets. Multi-stage: build a fully-
# static musl binary, ship it on `scratch`. rustls + webpki-roots (all on `ring`,
# no aws-lc/OpenSSL) means no system CA store is needed, so the runtime image is
# just the binary (no OS, no shell) — a small attack surface for a sidecar that
# holds decrypted secrets in memory.
#
# ---------------------------------------------------------------------------
# This file REPLACES the monorepo's apps/proxy/Dockerfile on every sync
# (.github/sync-templates/proxy/Dockerfile in mileszim/seekrit). It exists
# because the two repos have different shapes, not different builds: in the
# monorepo the shared crates live at ../../crates/* — outside the build context
# — so that Dockerfile has to import each one as a named build context. Here
# they are vendored into ./vendor, so everything the build needs is already in
# one context and `docker build .` just works.
#
# Keep the two in step: the stages, the toolchain pin and the runtime image are
# meant to be identical, and only the copy layout differs. The CI in this repo
# builds this file, so a drift that breaks the image is caught here.
# ---------------------------------------------------------------------------
#
#     docker build -t seekritdev/proxy .
#
# Run it (mount a config, pass the token; bind 0.0.0.0 for a standalone container):
#
#     docker run --rm -e SEEKRIT_TOKEN=skt_… \
#       -v "$PWD/seekrit-proxy.toml:/seekrit-proxy.toml" \
#       -p 8080:8080 seekritdev/proxy --listen 0.0.0.0:8080

# ---- build stage: static musl binary ----------------------------------------
FROM rust:1.97-alpine AS build

# musl-dev + a C toolchain: needed to build `ring` (rustls'/rcgen's crypto backend).
RUN apk add --no-cache musl-dev gcc make

WORKDIR /build
# Copy only what the binary build needs (tests/ + testdata/ are not compiled by
# `cargo build`). --locked pins the committed dependency set for a reproducible
# build; the lockfile is the monorepo's, unmodified — vendoring rewrites the
# dependency *paths* in Cargo.toml, which Cargo.lock does not record.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY vendor ./vendor
RUN cargo build --release --locked --bin seekrit-proxy

# ---- runtime stage: nothing but the binary ----------------------------------
FROM scratch AS runtime
COPY --from=build /build/target/release/seekrit-proxy /seekrit-proxy

# Reverse-proxy (8080) and forward-proxy (8081) default ports — documentation
# only; the effective bind comes from the config / --listen. The proxy reads its
# config from /seekrit-proxy.toml by default (override with --config) and the
# token from SEEKRIT_TOKEN.
EXPOSE 8080 8081
ENTRYPOINT ["/seekrit-proxy"]
