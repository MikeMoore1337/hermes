# Build with --build-arg BRC_BASE_IMAGE=sha256:<64 hex characters>.
# The existing H-15 agent image is not changed by this source-only recipe.
ARG BRC_BASE_IMAGE
FROM ${BRC_BASE_IMAGE}

# Never change the inherited ENTRYPOINT, CMD, WORKDIR, or container mounts.
# Only the separate build stage uses uid 0; the final runtime is non-root.
USER 0:0
RUN set -eu; \
    . /etc/os-release; \
    test "$ID" = debian; \
    test "$VERSION_CODENAME" = bookworm; \
    printf '%s\n' \
      'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20261020T000000Z bookworm main' \
      'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/20261020T000000Z bookworm-security main' \
      > /etc/apt/sources.list; \
    rm -f /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      git python3 python3-pip python3-venv ca-certificates; \
    git --version; \
    python3 --version; \
    rm -rf /var/lib/apt/lists/*
USER 65534:65534
