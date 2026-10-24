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
        self.endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"

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

        # Rank items: 'keep' first, sorted by relevance desc, then 'unsure'
        def sort_key(item: Item):
            dec = item.decision or {}
            route_priority = 2 if dec.get("route") == "keep" else 1
            rel = dec.get("relevance", 3)
            return (route_priority, rel)

        sorted_items = sorted(items, key=sort_key, reverse=True)

        # Prepare items payload for the prompt
        items_payload = []
        for i in sorted_items[:35]:  # Send top candidates for synthesis
            dec = i.decision or {}
            items_payload.append({
                "id": i.id,
                "source": i.source,
                "title": i.title,
                "url": i.url,
                "summary": i.body[:400] if i.body else "",
                "route": dec.get("route", "unsure"),
                "relevance": dec.get("relevance", 3),
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

        with httpx.Client(timeout=45.0) as client:
            resp = client.post(self.endpoint, json=payload)
            resp.raise_for_status()
            result = resp.json()

        digest_markdown = result["candidates"][0]["content"]["parts"][0]["text"]

        # Save to digests/YYYY-MM-DD.md
        out_path = self.output_dir / f"{date_str}.md"
        out_path.write_text(digest_markdown, encoding="utf-8")

        # Identify items mentioned
        included_ids = [i.id for i in sorted_items[:10]]

        return digest_markdown, out_path, included_ids
