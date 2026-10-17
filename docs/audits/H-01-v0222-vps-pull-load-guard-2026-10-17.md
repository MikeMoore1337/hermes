# H-01 #33 - v0.22.2 VPS staging peak-load guard (2026-10-17)

## Actual production host observation

During the owner-approved attempt to stage the **exact** official v0.22.2
Linux/AMD64 digest `sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`
on the current Hermes VPS:

- Before the attempt: 3,915 MiB RAM total, 2,176 MiB MemAvailable,
  190 MiB swap used, approximately 12 GiB free disk; existing Hermes
  Control Center and monitoring timers active. The resident Agent and
  Cloudflare proxy were inactive.
- The pinned `docker pull --platform linux/amd64` was started with
  `nice -n 19`, `ionice -c3` and a one-time timeout, no image
  alias, fallback, model or API call.
- While layers were being downloaded/extracted, `load1` first reached
  **1.50** and then **2.72**. This exceeds the explicit #33 peak-load
  threshold of **1.30**.
- The precise Docker pull CLI process was sent SIGTERM as the host peak
  threshold was observed. At the last immediate check,
  `hermes-control-center.service` and `hermes-ops-watch.timer`
  remained active. That check does **not** establish the full news
  cycle is healthy or that daemon-side unpack work finished.
- The command's terminal success, final image presence, full news
  post-check and resident agent deployment were **not established**.
  Do not label this image as installed or production verified.

**Current outcome: `BLOCKED_HOST_LOAD` - staging attempt intentionally
stopped.** This is an operational resource observation, not a CVE,
permissions or model failure. Do not increase swap or remove existing
news/other images as a workaround without a capacity plan.

## Controlled follow-up (repository candidate)

`python3 -m scripts.h01_stage_image` only shows the exact digest and
limits. The `--execute` flag must be deliberately supplied under a
reviewed operator context; it is not invoked by any timer, CI,
deployment unit or daemon.

The stage supervisor checks service availability, whether the news
worker is busy, RAM headroom, swap, free disk and **load1 <= 1.30**
before and during the pull. It sends termination signals to the pull
process group when the threshold is exceeded, allows no automatic
retry and validates full digest/architecture before reporting a
completed staging operation. Docker daemon extraction may outlive the
CLI's termination; watch host resources before any new attempt.

This script does **not** install or start Hermes, enable a model,
proxy, resident service, scheduler, network permissions or payment
provider. Its synthetic tests do not prove real host isolation.
Resident `NO-GO` remains until a pinned patched image can be staged,
isolated native/tool/network tests pass, a useful Cloudflare Free
cycle is quota-gated, peak-load/recovery burn-in passes and the
accepted scope is documented. The owner has authorized further
implementation of #33; it is not evidence that the technical checks
already passed.
