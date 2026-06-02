# Tero Vector — runtime image.
#
# Mirrors `distribution/docker/debian/Dockerfile` (same base, same apt set)
# but skips upstream's two-stage `.deb` install — the binary is supplied
# directly via the build context by `.github/workflows/tero-release.yaml`.
# libssl3t64 + libstdc++6 are listed explicitly here because upstream gets
# them transitively from the .deb's Depends; we have no .deb so we install
# them by name.
#
# Build args:
#   TARGETARCH      Set automatically by buildx (`amd64` | `arm64`). Selects
#                   which prebuilt binary directory to copy from.
#
# Build context layout (relative to context root):
#   amd64/vector    Linux x86_64 binary
#   arm64/vector    Linux aarch64 binary
#   LICENSE         License file (copied for OCI metadata)

FROM docker.io/debian:trixie-slim@sha256:b6e2a152f22a40ff69d92cb397223c906017e1391a73c952b588e51af8883bf8

ARG TARGETARCH

LABEL org.opencontainers.image.url="https://vector.dev"
LABEL org.opencontainers.image.source="https://github.com/usetero/vector"
LABEL org.opencontainers.image.documentation="https://vector.dev/docs"
LABEL org.opencontainers.image.title="vector"
LABEL org.opencontainers.image.description="Tero distribution of Vector with the policy transform enabled."
LABEL org.opencontainers.image.licenses="MPL-2.0"
LABEL org.opencontainers.image.vendor="Tero"

# we want the latest versions of these
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        tzdata \
        libsasl2-2 \
        libssl3t64 \
        libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 ${TARGETARCH}/vector /usr/bin/vector
COPY LICENSE /usr/share/doc/vector/LICENSE

RUN mkdir -p /var/lib/vector

# Smoke test
RUN ["vector", "--version"]

EXPOSE 8686

ENTRYPOINT ["/usr/bin/vector"]
