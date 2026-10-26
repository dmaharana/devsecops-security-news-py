# DevSecOps Weekly Intelligence Roll-up - Week 2026-W44

## The 3 Things That Mattered Most This Week

### 1. LiteLLM Supply Chain Hijack & Emergency Cosign Key Rotation
A leaked Agent Platform master key accidentally committed to a public repository in May 2026 allowed attackers to steal GitHub tokens and hijack the LiteLLM release pipeline, briefly publishing malicious package versions. In response, the LiteLLM maintainers revoked compromised secrets and changed the Cosign signing key for all official Docker images and Helm charts.

* **Why it matters:** LiteLLM is widely deployed as an enterprise AI proxy gateway. If your CI/CD or deployment pipelines enforce container signature verification using the old Cosign public key (`0112e53...`), deployments will fail. More critically, unverified images pulled during the compromise window may contain malicious backdoors.
* **What to verify:**
  * Update container verification workflows to use the new Cosign public key introduced in commit [`e82a3c6`](https://github.com/BerriAI/litellm/commit/e82a3c646908ba0a6ee0beddc4310d7a6cac4065).
  * Inspect CI/CD build environments and runtime containers running LiteLLM versions pulled between late May and late October 2026 for unauthorized network egress or credential exposure.
  * Audit all GitHub secrets and API keys exposed in repositories using LiteLLM integrations.

### 2. Global PHP2Shell Exploitation Wave & Follow-up Unpatched RCE
The disclosure of critical "PHP2Shell" flaws (CVE-2026-109618, CVE-2026-109619) triggered massive automated exploitation attempts globally, with threat actors deploying Mirai/Potassium botnet variants and utilizing agentic AI frameworks for post-exploitation on government targets. Adding to the emergency, the PHP core team warned of another unpatched remote code execution vector (CVE-2026-115560) affecting non-default server configurations.

* **Why it matters:** PHP powers a significant portion of web infrastructure. Automated honeypots recorded exploit attempts *before* public disclosure. Attackers are using AI agents to execute multi-stage post-exploitation within two hours of initial access.
* **What to verify:**
  * Immediately upgrade all PHP installations across staging and production environments to patched release branches.
  * Audit web server configurations (Nginx/Apache + FPM) for non-default pass-through handling to mitigate the unpatched CVE-2026-115560 vulnerability.
  * Review perimeter logs for honeypot indicators or abnormal outgoing HTTP/SMB traffic from web pods.

### 3. Cross-Ecosystem Brotli Memory Corruption RCE (CVE-2026-111497)
A critical memory-corruption flaw in Google's underlying Brotli decompression library affects multiple upstream runtimes and tools, including Node.js (versions 22.x, 24.x, 26.x), Bun, Python (`brotli` and `brotlicffi`), Envoy proxies, `curl`, and Git.

* **Why it matters:** Brotli decompression is routinely enabled by default across edge proxies, API gateways, and web application runtimes. A malicious actor can trigger Remote Code Execution (RCE) or service crashes by delivering a specifically crafted compressed payload to any service processing HTTP/3, gRPC, or compressed API inputs.
* **What to verify:**
  * Scan container images for bundled native Brotli dependencies in Node.js, Python, and Envoy.
  * Update Node.js runtime environments to the latest patched releases across all active release tracks.
  * Review edge proxy configurations (Envoy, ingress controllers) to temporarily disable Brotli request decompression where patches cannot be immediately applied.

---

## Mandatory Action Checklist

| System / Component | Target Version / Patch | Action Required | Source Link |
| :--- | :--- | :--- | :--- |
| **LiteLLM** | `v1.106.4`, `v1.105.5`, `v1.104.7`, `v1.103.9` | Upgrade images/charts and update Cosign public key to `e82a3c6`. | [Release v1.106.4](https://github.com/BerriAI/litellm/releases/tag/v1.106.4) \| [Key Advisory](https://thehackernews.com/2026/10/leaked-litellm-master-key-let-attackers.html) |
| **PHP Engine** | `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12` | Immediate engine upgrade to fix CVE-2026-109618 and CVE-2026-109619. Apply non-default config mitigations for CVE-2026-115560. | [PHP 8.3.36 Release](https://github.com/php/php-src/releases/tag/php-8.3.36) \| [Mitigation Guide](https://www.bleepingcomputer.com/news/security/php-shares-mitigation-for-new-and-unpatched-rce-vulnerability/) |
| **Node.js** | Updated 22.x, 24.x, 26.x releases | Patch underlying Brotli decoder flaw (CVE-2026-111497) causing potential RCE. | [Node.js Security Blog](https://nodejs.org/en/blog/vulnerability) |
| **GitLab (Self-Managed)** | Latest critical patch releases | Apply emergency update for CVSS 10.0 unauthenticated RCE affecting versions back to 7.0. | [Advisory Details](https://thehackernews.com/2026/10/critical-gitlab-flaw-cvss-100-could.html) |

---

## Other Notable Advisories

* **AI Agent Prompt Injection (`AGENTS.md`):** Malicious `AGENTS.md` files placed in local Download folders can trick AI coding agents into executing arbitrary terminal commands and installing rogue npm packages. ([BleepingComputer](https://www.bleepingcomputer.com/news/security/ai-coding-agents-hijacked-using-agentsmd-file-in-downloads-folder/))
* **Tailscale SSH PrivEsc Flaw:** Unpatched vulnerabilities in Tailscale SSH setups with port forwarding enabled allow a compromised tailnet node to achieve root access on neighboring servers. ([The Hacker News](https://thehackernews.com/2026/10/unpatched-tailscale-ssh-flaws-could-let.html))
* **CISA KEV Additions (Arista VeloCloud & Collabora):** CISA added Arista VeloCloud Orchestrator zero-day SQLi and Collabora CODE server RCE flaws to the Known Exploited Vulnerabilities catalog. ([CISA Alert Coverage](https://thehackernews.com/2026/10/cisa-flags-two-actively-exploited.html))
* **Linux Kernel KSMBD Pre-Auth RCEs:** Two CVSS 9.0 unauthenticated RCE flaws were disclosed affecting Linux systems running the kernel-space SMB server (`ksmbd`). ([The Hacker News](https://thehackernews.com/2026/10/7c53f743c08237d2.html))
* **AI Payment SDK Drain (x402 SDK):** A default client misconfiguration in the x402 payment SDK allowed malicious upstream APIs to drain full token balances from autonomous paying agents. ([The Hacker News](https://thehackernews.com/2026/10/critical-x402-sdk-flaw-could-let.html))
* **HTTP/3 Memory Amplification (QPACK DoS):** Unauthenticated QPACK header expansion bugs allow remote attackers to crash HTTP/3 servers via 4,000x memory amplification attacks. ([FoxIO Disclosure](https://thehackernews.com/2026/10/new-qpack-flaws-can-crash-http3-servers.html))
* **eMudhra Certificate Authority Exit:** CA provider eMudhra is shutting down its global SSL/TLS operations after private keys for 8 intermediate CAs were discovered to be easily guessable. ([The Hacker News](https://thehackernews.com/2026/10/emudhra-to-exit-global-ssltls-business.html))