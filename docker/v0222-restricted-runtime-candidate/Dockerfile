# Offline review candidate ONLY. Never deploy to production or claim CVE-wide GO.
# Build with --network none --pull=false, a three-file context and a SHA-pinned wheel.
FROM nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05

LABEL org.opencontainers.image.title="Hermes v0.22.2 local security derivative (NOT FOR PRODUCTION)" \
      hermes.derivative.approved="false" \
      hermes.derivative.resident-agent-allowed="false" \
      hermes.base.commit="d923a5eb487a17c0a68801bba9ef0f56c81040a8" \
      hermes.pyjwt.wheel.sha256="42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193"

WORKDIR /opt/hermes
COPY pyjwt-2.15.1-py3-none-any.whl /tmp/pyjwt-2.15.1-py3-none-any.whl
COPY hermes-v0.22.1-native-tool-policy.patch /tmp/tool-policy.patch

# Verify the exact wheel and install it without accessing a registry.
RUN echo "42d59d631f7768a1028a64c7ff581a9bf7519804daf91fc5b6c56e30eec5e193  /tmp/pyjwt-2.15.1-py3-none-any.whl" | sha256sum -c - \
    && /opt/hermes/.venv/bin/python3 -m ensurepip --upgrade \
    && /opt/hermes/.venv/bin/python3 -m pip install --no-index --no-deps --no-cache-dir --force-reinstall /tmp/pyjwt-2.15.1-py3-none-any.whl \
    && /opt/hermes/.venv/bin/python3 -m pip show PyJWT \
    && rm /tmp/pyjwt-2.15.1-py3-none-any.whl

# Reviewed synthetic-native guard patch; it is not full OS/MCP runtime enforcement.
RUN sed -i 's/\r$//' /tmp/tool-policy.patch \
    && git apply --unidiff-zero --check /tmp/tool-policy.patch \
    && git apply --unidiff-zero /tmp/tool-policy.patch \
    && rm /tmp/tool-policy.patch

# Ensure subsequent resolution does not silently re-pin vulnerable PyJWT 2.13.
RUN grep -Fq 'PyJWT[crypto]==2.13.0' pyproject.toml \
    && sed -i 's/PyJWT\[crypto\]==2\.13\.0/PyJWT[crypto]==2.15.1/' pyproject.toml \
    && grep -Fq 'PyJWT[crypto]==2.15.1' pyproject.toml

# This opt-in RESTRICTED profile deliberately disables the SSH backend.
# Exact base-digest versions and CLOSED apt simulation prevent accidental
# removal of unexpected dependencies. No sid packages, downloads or autoremove.
# Removing linux-libc-dev also removes 12 build/dev packages in this exact image.
RUN set -eu; \
    test "$(dpkg-query -W -f='${Version}' openssh-client)" = '1:10.0p1-7+deb13u4'; \
    test "$(dpkg-query -W -f='${Version}' linux-libc-dev)" = '6.12.111-1'; \
    test "$(dpkg-query -W -f='${Version}' libxml2)" = '2.12.7+dfsg+really2.9.14-2.1+deb13u3'; \
    apt-get -s purge openssh-client linux-libc-dev > /tmp/h18-purge-plan; \
    sed -n 's/^Purg \([^ ]*\) .*/\1/p' /tmp/h18-purge-plan | LC_ALL=C sort > /tmp/h18-observed-removals; \
    printf '%s\n' \
      g++ g++-14 g++-14-x86-64-linux-gnu g++-x86-64-linux-gnu \
      libc6-dev libexpat1-dev libpython3-dev libpython3.13-dev \
      libstdc++-14-dev linux-libc-dev openssh-client python3-dev \
      python3.13-dev zlib1g-dev | LC_ALL=C sort > /tmp/h18-approved-removals; \
    diff -u /tmp/h18-approved-removals /tmp/h18-observed-removals; \
    DEBIAN_FRONTEND=noninteractive apt-get --yes --no-download purge openssh-client linux-libc-dev; \
    ! command -v ssh; \
    ! dpkg-query -W openssh-client linux-libc-dev >/dev/null 2>&1; \
    dpkg-query -W libxml2; \
    /opt/hermes/.venv/bin/python3 -m pip show PyJWT; \
    rm /tmp/h18-purge-plan /tmp/h18-observed-removals /tmp/h18-approved-removals
