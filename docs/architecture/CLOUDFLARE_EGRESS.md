# Independent Hermes: private Cloudflare-only network

Security design candidate. Deploy only after successful CI and operator verification.

- Dedicated internal Docker bridge: hermes-agent-isolated, subnet 172.29.250.0/28.
- Only agent address 172.29.250.2 -> host gateway 172.29.250.1:18573 allowed on INPUT.
- nft forward drops all new bridge traffic; unrelated YFC hermes_egress untouched.
- Dedicated low-privilege Python HTTP CONNECT proxy forwards solely to
  api.cloudflare.com:443, never sees TLS plaintext or credentials.
- Agent honors HTTPS_PROXY to access the provider, has no Docker socket,
  private user and one private state mount, bounded memory/pids/CPU.
- No tools other than selected todo in the first bounded one-shot test.

First run requires installing the scoped nft rules and starting host proxy manually.
After reboot the nft table vanishes while Docker bridge persists; DO NOT enable
automatic agent restart until an idempotent firewall repair and validation
mechanism is separately implemented. Fail closed if firewall is missing.

Rollback stops only hermes-cloudflare-proxy, deletes only new nft table, and
removes hermes-agent-isolated network when no agent is running. No change to YFC
news or Ops Watch units.

Caveat: relay only validates CONNECT authority, not TLS contents; client must
validate Cloudflare certificate. A compromised host/proxy is outside this model.
