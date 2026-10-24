# DevSecOps Signal Engine

An automated daily intelligence engine that monitors DevSecOps supply chain vulnerabilities, CVE advisories, and security releases across core runtimes and CI/CD tools (LiteLLM, PHP, Kubernetes, Docker, Jenkins, SonarQube, JFrog Artifactory, Atlassian).

## Architecture

```
Sources -> SQLite Store (Stable IDs & Dedupe) -> Code Filters (Age, Engagement, Language)
        -> Parallel Decision Pass (Gemini Flash Lite) -> Reading Pass & Synthesizer (Gemini Flash)
        -> Daily Markdown Digest (digests/YYYY-MM-DD.md)
```

## Running the Engine

### Execute Daily Pipeline
```bash
uv run python main.py --run
```

### Automated Scheduling (Daily at 06:00 AM)
Add to user crontab (`crontab -e`):
```cron
0 6 * * * cd /home/titu/sources/temp/devsecops-security-news && /home/titu/apps/miniconda3/bin/uv run python main.py --run >> logs/cron.log 2>&1
```

## Shadow Week Workflow (Stage 7)
During the initial week:
1. Review the generated daily digest in `digests/YYYY-MM-DD.md`.
2. Check for:
   - **Misses**: Vulnerability occurred but was not in digest -> check if source exists or widen decision question.
   - **Noise**: Low-relevance item made it through -> tighten code filter or sharpen decision prompt.
