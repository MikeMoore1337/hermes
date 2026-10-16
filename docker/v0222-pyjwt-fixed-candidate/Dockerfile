# Offline review candidate ONLY. Never deploy to production or claim CVE-wide GO.
# Build with --network none --pull=false, a three-file context and a SHA-pinned wheel.
FROM nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05

LABEL org.opencontainers.image.title="Hermes v0.22.2 local security derivative (NOT FOR PRODUCTION)" \
      hermes.derivative.approved="false" \
      hermes.derivative.resident-agent-allowed="false" \
      hermes.base.commit="d923a5eb487a17c0a68801bba9ef0f56c81040a8" \
      hermes.pyjwt.wheel.sha256="ad0cef71c756a56e74863c2919cf0985f72decbcfcb550ee2f422e7c62b5eedc"

WORKDIR /opt/hermes
COPY pyjwt-2.14.0-py3-none-any.whl /tmp/pyjwt-2.14.0-py3-none-any.whl
COPY hermes-v0.22.1-native-tool-policy.patch /tmp/tool-policy.patch

# Verify the exact wheel and install it without accessing a registry.
RUN echo "ad0cef71c756a56e74863c2919cf0985f72decbcfcb550ee2f422e7c62b5eedc  /tmp/pyjwt-2.14.0-py3-none-any.whl" | sha256sum -c - \
    && /opt/hermes/.venv/bin/python3 -m ensurepip --upgrade \
    && /opt/hermes/.venv/bin/python3 -m pip install --no-index --no-deps --no-cache-dir --force-reinstall /tmp/pyjwt-2.14.0-py3-none-any.whl \
    && /opt/hermes/.venv/bin/python3 -m pip show PyJWT \
    && rm /tmp/pyjwt-2.14.0-py3-none-any.whl

# Reviewed synthetic-native guard patch; it is not full OS/MCP runtime enforcement.
RUN sed -i 's/\r$//' /tmp/tool-policy.patch \
    && git apply --unidiff-zero --check /tmp/tool-policy.patch \
    && git apply --unidiff-zero /tmp/tool-policy.patch \
    && rm /tmp/tool-policy.patch

# Ensure subsequent resolution does not silently re-pin vulnerable PyJWT 2.13.
RUN grep -Fq 'PyJWT[crypto]==2.13.0' pyproject.toml \
    && sed -i 's/PyJWT\[crypto\]==2\.13\.0/PyJWT[crypto]==2.14.0/' pyproject.toml \
    && grep -Fq 'PyJWT[crypto]==2.14.0' pyproject.toml
