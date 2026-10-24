# Signal engine profile

<!-- Written by the build-signal-engine interview. Every stage reads this file. Edit it
     freely; the engine follows it. -->

## What I keep up with

DevSecOps vulnerabilities, supply chain risks, and security patches in core tools, runtimes, and CI/CD pipelines (LiteLLM & AI proxies, PHP runtimes & web frameworks, Docker/Kubernetes, Jenkins, SonarQube, JFrog Artifactory, Atlassian Cloud, Checkmarx SaaS) so I can patch, isolate, or mitigate immediately.

## Sources

Data platform: Per-source direct (APIs, feeds, and open endpoints)

| Source | What it is | How it is pulled | Why it is here |
|---|---|---|---|
| GitHub Security Advisories | Official advisories for tracked packages (LiteLLM, PHP, Jenkins plugins, Kubernetes, etc.) | GitHub GraphQL/REST API / OSV API | R1.2: catches critical CVEs and advisories before downstream reports |
| OSV.dev Vulnerability DB | Open Source Vulnerability DB (ecosystems: PyPI/litellm, Packagist/php, Go, npm) | OSV API (`https://api.osv.dev/v1/query`) | Direct package-level CVE and fix tracking |
| CISA Known Exploited Vulnerabilities (KEV) | CISA active catalog of in-the-wild exploited vulnerabilities | CISA JSON feed (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) | Mandatory high-priority alerts for actively exploited CVEs |
| Tool GitHub Releases & Advisories | Official releases & changelogs for BerriAI/litellm, php/php-src, kubernetes, jenkinsci | GitHub Releases API | R1.2: LiteLLM and runtime security patches & fixes |
| r/netsec | Reddit community for network and application security | Reddit JSON API (`/r/netsec/top.json?t=week`) | Early exploit analyses, PoCs, and technical deep-dives |
| Hacker News Security | Hacker News discussions on vulnerabilities & security incidents | Algolia HN Search API | Real-time discussion when major incidents or supply chain attacks drop |
| BleepingComputer & The Hacker News | Curated security news feeds | RSS / Atom feeds | Broad coverage of active ransomware, zero-days, and supply chain campaigns |

## Code filters

- Max age: 7 days for official advisories/CVEs; 3 days for community news/discussions
- Engagement floor: >= 10 points for Reddit/HN (0 for official CVEs/advisories)
- Language: English only
- Deduplication: Stable ID (SHA256 of canonical URL or source-native ID)

## The decision question(s)

1. Relevance (score 1-5): Does this item report a security vulnerability, CVE, active exploit, supply chain risk, patch, or hardening alert affecting our DevSecOps stack (LiteLLM, PHP, Docker/K8s, Jenkins, SonarQube, Artifactory, Atlassian, CI/CD)?
2. Reports something new and concrete (yes/no): Does this report a specific vulnerability, security patch, PoC, advisory, or confirmed incident (as opposed to marketing, generic opinion, or high-level hype)?

Routing:
- Sure drop: Relevance <= 2 OR Reports something new and concrete == "no"
- Sure keep: Relevance >= 4 AND Reports something new and concrete == "yes"
- Unsure: Relevance == 3 -> Send to LLM reading pass (bias: better to see 2 extra than miss a critical issue)

### Keep examples
- LiteLLM SSRF / proxy authentication bypass CVE advisory with fix version
- PHP CGI argument injection RCE advisory (e.g. CVE-2024-4577) and patch release
- CI/CD secret leakage or supply chain poisoning vulnerability in GitHub Actions / Jenkins runner

### Drop examples
- AI hype, philosophical opinion essays, or general vendor thought leadership
- Vendor product promotional pitches, sponsored comparisons, and paywalled whitepapers
- Unrelated crypto/web3/NFT smart contract hacks with no infra or DevSecOps relevance

## The digest

- Where I read it: `digests/YYYY-MM-DD.md` in this repository
- Length cap: 10 items
- Format: Markdown with executive summary, grouped by severity/tool, with direct source links and suggested mitigation action
- Extras: Weekly roll-up from stored items on Mondays

## Schedule

- Full run: Daily at 06:00 local time
- Shadow week: 2026-10-24 (start date)
