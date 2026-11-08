# syntax=docker/dockerfile:1.7
# The Limbowatch watcher image: `limbowatch` and OSV-Scanner, nothing installed at run time.
#   docker run --rm -v "$PWD:/src" -w /src ghcr.io/limbowatch/limbowatch limbowatch scan .
# Built, attested and published by .github/workflows/image.yml for linux/amd64 and linux/arm64. The base images
# are pinned by digest (Dependabot updates them); Python dependencies come from uv.lock with hashes.

ARG PYTHON_IMAGE=python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.7@sha256:96f40d3904aad8d0bd010539001d36c8e2188b981e1334471a90c4a1d93bb490

# OSV-Scanner 2.7.0 reads the lockfiles; checksums from its release's osv-scanner_SHA256SUMS
FROM scratch AS osv-amd64
ADD --checksum=sha256:160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b --chmod=755 \
    https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_amd64 /osv-scanner
FROM scratch AS osv-arm64
ADD --checksum=sha256:4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7 --chmod=755 \
    https://github.com/google/osv-scanner/releases/download/v2.7.0/osv-scanner_linux_arm64 /osv-scanner
FROM osv-${TARGETARCH} AS osv

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
