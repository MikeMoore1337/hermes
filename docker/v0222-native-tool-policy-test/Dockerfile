FROM nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05

WORKDIR /opt/hermes
COPY patches/upstream/hermes-v0.22.1-native-tool-policy.patch /tmp/hermes-v0222-tool-policy-candidate.patch
RUN sed -i 's/\r$//' /tmp/hermes-v0222-tool-policy-candidate.patch && git apply --unidiff-zero --check /tmp/hermes-v0222-tool-policy-candidate.patch && git apply --unidiff-zero /tmp/hermes-v0222-tool-policy-candidate.patch && rm /tmp/hermes-v0222-tool-policy-candidate.patch
