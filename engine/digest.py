from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional
from dotenv import load_dotenv
import httpx

from engine.schema import Item
from engine.store import Store

load_dotenv()
logger = logging.getLogger(__name__)

DIGEST_SYSTEM_PROMPT = """You write an executive DevSecOps daily security intelligence digest.
The reader keeps up with DevSecOps vulnerabilities, supply chain risks, CVEs, and security patches across their stack (LiteLLM & AI proxies, PHP runtimes, Kubernetes/Docker, Jenkins CI, SonarQube, JFrog Artifactory, Atlassian, CI/CD pipelines).
They read this digest to patch, isolate, or mitigate vulnerabilities before production systems are impacted.

Rules:
- At most 10 items in the digest. Prioritize items that demand immediate mitigation or patching.
- Group items by category (e.g., "Critical Runtime & Framework Advisories", "CI/CD & Supply Chain Vulnerabilities", "Actively Exploited & Cloud Threats").
- Group related items about the same tool/release into a single consolidated entry.
- 1 to 2 plain, technical sentences per item: what the vulnerability/change is, and the concrete recommended action or patch version.
- PRESERVE EVERY SOURCE LINK. Use markdown hyperlinks `[Source](url)`.
- Never invent links or CVEs not in the data.
- Tone: Crisp, factual, zero hype, zero buzzwords, no exclamation marks.

Format template:
# DevSecOps Daily Security Digest - {date}

## Executive Summary
<2-3 sentences highlighting the most urgent patches or actively exploited issues today>

## <Category Name>
- **<Component/Tool: Vulnerability or Patch Title>** - <Details of flaw, impact, and affected versions>. **Action**: <Upgrade to version X / mitigation>. [Advisory Link](url)

## Also Monitored / Low Impact
- **<Tool/Topic>** - <Brief one-liner>. [Link](url)
"""


class DigestGenerator:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-3.5-flash",
        output_dir: str = "digests",
    ):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model = model
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        self.headers = {"x-goog-api-key": self.api_key} if self.api_key else {}

    def generate_digest(
        self,
        items: list[Item],
        date_str: Optional[str] = None,
    ) -> tuple[str, Path, list[str]]:
        """
        Generates daily digest from items.
        Returns (digest_content_markdown, output_file_path, included_item_ids).
        """
        if not date_str:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Rank items: un-digested first, then 'keep', sorted by relevance desc
        def sort_key(item: Item):
            dec = item.decision or {}
            new_to_digest = 2 if item.in_digest is None else 1
            route_priority = 2 if dec.get("route") == "keep" else 1
            rel = dec.get("relevance", 3)
            return (new_to_digest, route_priority, rel)

        sorted_items = sorted(items, key=sort_key, reverse=True)

        # Prepare items payload for the prompt
        items_payload = []
        for i in sorted_items[:30]:  # Send top candidates for synthesis
            dec = i.decision or {}
            items_payload.append({
                "id": i.id,
                "source": i.source,
                "title": i.title,
                "url": i.url,
                "summary": i.body[:350] if i.body else "",
                "route": dec.get("route", "unsure"),
                "relevance": dec.get("relevance", 3),
                "is_new_since_last_digest": i.in_digest is None,
            })

        user_prompt = f"Today is {date_str}.\nItems to evaluate for digest:\n{json.dumps(items_payload, indent=2)}"

        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": f"{DIGEST_SYSTEM_PROMPT.format(date=date_str)}\n\n{user_prompt}"}],
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
            },
        }

        # Try primary model, fallback models on transient 503/429
        fallback_models = [self.model, "gemini-3.8-flash", "gemini-3.5-flash-lite"]
        last_error = None
        result = None

        with httpx.Client(timeout=60.0, headers=self.headers) as client:
            for model_name in fallback_models:
                endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
                for attempt in range(3):
                    try:
                        resp = client.post(endpoint, json=payload)
                        if resp.status_code in (429, 503):
                            import time
                            time.sleep(3.0 * (attempt + 1))
                            continue
                        resp.raise_for_status()
                        result = resp.json()
                        break
                    except Exception as e:
                        last_error = e
                        import time
                        time.sleep(2.0)
                if result:
                    break

        if not result:
            raise RuntimeError(f"Digest generation failed after retries and fallback: {last_error}")

        digest_markdown = result["candidates"][0]["content"]["parts"][0]["text"]

        # Save to digests/YYYY-MM-DD.md
        out_path = self.output_dir / f"{date_str}.md"
        out_path.write_text(digest_markdown, encoding="utf-8")

        # Identify items actually referenced in the digest output
        included_ids = [
            i.id for i in sorted_items
            if i.url in digest_markdown or (i.title and i.title[:30] in digest_markdown)
        ]
        if not included_ids:
            included_ids = [i.id for i in sorted_items[:10]]

        return digest_markdown, out_path, included_ids

    def generate_weekly_rollup(
        self,
        items: list[Item],
        week_str: Optional[str] = None,
    ) -> tuple[str, Path]:
        """
        Generates a weekly roll-up synthesizing the week's top security items.
        Returns (rollup_markdown, output_file_path).
        """
        if not week_str:
            now = datetime.now(timezone.utc)
            week_str = f"{now.year}-W{now.isocalendar()[1]:02d}"

        # Keep items that were marked as keep or included in digests
        kept_items = [
            i for i in items
            if (i.decision or {}).get("route") == "keep" or i.in_digest is not None
        ]

        items_payload = [
            {
                "id": i.id,
                "title": i.title,
                "url": i.url,
                "summary": i.body[:300] if i.body else "",
                "in_digest": i.in_digest,
            }
            for i in kept_items[:40]
        ]

        rollup_prompt = (
            f"You write a weekly DevSecOps security intelligence roll-up for Week {week_str}.\n"
            f"Below are the week's top verified security items across LiteLLM, PHP, K8s/Docker, Jenkins, and CI/CD.\n"
            f"Synthesize this into:\n"
            f"# DevSecOps Weekly Intelligence Roll-up - Week {week_str}\n\n"
            f"## The 3 Things That Mattered Most This Week\n"
            f"<Deep dive into the 3 most consequential security events this week, why they matter, and what to verify>\n\n"
            f"## Mandatory Action Checklist\n"
            f"<Actionable list of required version upgrades / patch versions with links>\n\n"
            f"## Other Notable Advisories\n"
            f"<One-liners with links>\n\n"
            f"Items:\n{json.dumps(items_payload, indent=2)}"
        )

        payload = {
            "contents": [{"role": "user", "parts": [{"text": rollup_prompt}]}],
            "generationConfig": {"temperature": 0.2},
        }

        fallback_models = [self.model, "gemini-3.8-flash", "gemini-3.5-flash-lite"]
        result = None
        with httpx.Client(timeout=60.0, headers=self.headers) as client:
            for model_name in fallback_models:
                endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"
                try:
                    resp = client.post(endpoint, json=payload)
                    resp.raise_for_status()
                    result = resp.json()
                    break
                except Exception as e:
                    logger.warning(f"Weekly rollup generation attempt failed with {model_name}: {e}")

        if not result:
            raise RuntimeError("Weekly roll-up generation failed.")

        rollup_markdown = result["candidates"][0]["content"]["parts"][0]["text"]
        out_path = self.output_dir / f"weekly-{week_str}.md"
        out_path.write_text(rollup_markdown, encoding="utf-8")

        return rollup_markdown, out_path
