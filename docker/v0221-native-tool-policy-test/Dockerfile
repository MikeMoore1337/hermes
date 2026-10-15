FROM nousresearch/hermes-agent@sha256:cd9cb455576d27c9b6311de1104494ad7e221b6e68dc77e9ac2a8af661a4dc21

WORKDIR /opt/hermes
COPY patches/upstream/hermes-v0.22.1-native-tool-policy.patch /tmp/hermes-v0221-native-tool-policy.patch
RUN sed -i 's/\r$//' /tmp/hermes-v0221-native-tool-policy.patch && git apply --unidiff-zero --check /tmp/hermes-v0221-native-tool-policy.patch && git apply --unidiff-zero /tmp/hermes-v0221-native-tool-policy.patch && rm /tmp/hermes-v0221-native-tool-policy.patch
