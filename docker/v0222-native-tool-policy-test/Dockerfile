FROM nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05
# Label documents patch application, NOT approval to activate a resident agent.
LABEL hermes.base.commit="d923a5eb487a17c0a68801bba9ef0f56c81040a8" \
      hermes.native.tool.policy="bounded-v0222" \
      hermes.derivative.resident-agent-allowed="false"

WORKDIR /opt/hermes
COPY patches/upstream/hermes-v0.22.1-native-tool-policy.patch /tmp/hermes-v0222-tool-policy-candidate.patch
RUN sed -i 's/\r$//' /tmp/hermes-v0222-tool-policy-candidate.patch && git apply --unidiff-zero --check /tmp/hermes-v0222-tool-policy-candidate.patch && git apply --unidiff-zero /tmp/hermes-v0222-tool-policy-candidate.patch && rm /tmp/hermes-v0222-tool-policy-candidate.patch

# Test-only trust-boundary mitigation. Never infer read permission or retry
# safety solely from remote MCP readOnlyHint. This derivative is NOT resident.
COPY patches/upstream/hermes-v0.22.2-mcp-owner-readonly-policy.patch /tmp/hermes-mcp-readonly-policy.patch
RUN git apply --unidiff-zero --check /tmp/hermes-mcp-readonly-policy.patch && git apply --unidiff-zero /tmp/hermes-mcp-readonly-policy.patch && rm /tmp/hermes-mcp-readonly-policy.patch
