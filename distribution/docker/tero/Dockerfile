# Tero Vector — runtime image
#
# Receives a prebuilt `vector` binary in the build context and bakes it into
# a minimal Debian-slim runtime. Build orchestration lives in
# `.github/workflows/tero-release.yaml`, which compiles the binary natively
# on amd64 and arm64 runners and supplies the right binary per --platform.
#
# Build args:
#   TARGETARCH      Set automatically by buildx (`amd64` | `arm64`). Selects
#                   which prebuilt binary directory to copy from.
#
# Build context layout (relative to context root):
#   amd64/vector    Linux x86_64 binary
#   arm64/vector    Linux aarch64 binary
#   LICENSE         License file (copied for OCI metadata)
#   README.md       Optional, included for OCI metadata

FROM docker.io/library/debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb AS runtime

ARG TARGETARCH

# Common Vector runtime dependencies plus libstdc++ for Vectorscan.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        tzdata \
        libsasl2-2 \
        libssl3 \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

LABEL org.opencontainers.image.title="vector"
LABEL org.opencontainers.image.description="Tero distribution of Vector with the policy transform enabled."
LABEL org.opencontainers.image.source="https://github.com/usetero/vector"
LABEL org.opencontainers.image.licenses="MPL-2.0"
LABEL org.opencontainers.image.vendor="Tero"

# Pull the per-arch binary from the build context. The workflow places
# binaries under `amd64/vector` and `arm64/vector` before invoking buildx.
COPY --chmod=0755 ${TARGETARCH}/vector /usr/bin/vector
COPY LICENSE /usr/share/doc/vector/LICENSE

# Smoke test — fail the image build if the binary can't even print its version.
RUN ["vector", "--version"]

# Vector's API listens on 8686 by default.
EXPOSE 8686

ENTRYPOINT ["/usr/bin/vector"]
