# syntax=docker/dockerfile:1.7
# The Limbowatch watcher image: `limbowatch` and OSV-Scanner, nothing installed at run time.
#   docker run --rm -v "$PWD:/src" -w /src ghcr.io/limbowatch/limbowatch:<release> limbowatch scan .   (no `latest` for alphas)
# Built, attested and published by .github/workflows/image.yml for linux/amd64 and linux/arm64. The base images
# are pinned by digest (Dependabot updates them); Python dependencies come from uv.lock with hashes; OSV-Scanner is
# built from its v2.7.0 source through the Go module proxy, every module checked against sum.golang.org.

ARG PYTHON_IMAGE=python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490
ARG GO_IMAGE=golang:1.27-bookworm@sha256:dc0963f32053e4bc451d24d87e3892d42d01021b61f093e98eb95c0352bb84b0

# OSV-Scanner reads the lockfiles. Built from source rather than downloaded from GitHub's release assets, which
# returned 504 for 20 minutes and more on 2026-11-08 (F-109); cross-compiled on the build machine, so arm64 needs no emulation.
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS osv
ARG TARGETOS TARGETARCH
ENV GOFLAGS=-trimpath GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org CGO_ENABLED=0
# Go's module and build caches are cache mounts, so they stay out of the layer. It holds only the binary (about
# 55 MB, not 1.3 GB), and that's what the GitHub Actions build cache stores per architecture (FINDINGS F-122).
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go install -ldflags="-s -w" github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.0 \
 && find /go/bin -name osv-scanner -type f -exec mv {} /osv-scanner \;

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY packages packages
# The two wheels, and every dependency pinned with hashes from uv.lock
RUN uv build --package limbowatch --wheel -o /dist \
 && uv build --package limbowatch-cli --wheel -o /dist \
 && uv export --package limbowatch-cli --frozen --no-dev --no-emit-workspace --format requirements.txt -o /dist/requirements.txt

FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
RUN --mount=type=bind,from=build,source=/dist,target=/dist \
    pip install --require-hashes -r /dist/requirements.txt \
 && pip install --no-deps /dist/*.whl \
 && limbowatch --version
COPY --from=osv /osv-scanner /usr/local/bin/osv-scanner
LABEL org.opencontainers.image.title="limbowatch" \
      org.opencontainers.image.description="Find dependencies affected by security advisories in limbo: published, not yet in the databases scanners read" \
      org.opencontainers.image.source="https://github.com/limbowatch/limbowatch" \
      org.opencontainers.image.url="https://limbo.watch" \
      org.opencontainers.image.documentation="https://github.com/limbowatch/limbowatch/blob/main/docs/WATCHER.md" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Limbowatch contributors"
# No ENTRYPOINT: CI systems (GitLab, Actions) run their own shell in the image. Root, like GitLab's analyzers,
# so the job can write its reports into the checked-out project.
WORKDIR /src
CMD ["limbowatch", "--help"]
