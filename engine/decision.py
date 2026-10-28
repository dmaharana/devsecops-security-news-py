from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging
import os
import time
from typing import Any, Optional
from dotenv import load_dotenv
import httpx

from engine.schema import Item

load_dotenv()
logger = logging.getLogger(__name__)


DECISION_PROMPT = """You are the fast decision filter for a DevSecOps security signal engine.
Your job is to answer two specific questions with strict precision. Do NOT summarize or write prose. Return only valid JSON.

Item Title: {title}
Item Source: {source}
Item URL: {url}
Item Summary:
{body_snippet}

Questions:
1. "relevance": Integer from 1 to 5.
   - 1: Completely off-topic (crypto/NFTs, consumer gadgets, pure financial news, gaming).
   - 2: General software development/tech news, but not security-related or very tangential.
   - 3: General security or vulnerability news, but outside our immediate DevSecOps stack (e.g., Windows endpoint bootkits, mobile iOS flaws, car firmware).
   - 4: Security vulnerability, CVE, active exploit, supply chain risk, or patch in cloud-native infra, CI/CD pipelines, container runtimes, Linux, or web stacks.
   - 5: Direct security advisory, CVE, exploit PoC, or security patch specifically affecting our stack: LiteLLM / AI proxies, PHP runtimes & frameworks, Kubernetes, Docker, Jenkins, SonarQube, Artifactory, Atlassian, or GitHub Actions.
   (Note: An unfamiliar tool or dependency name is NOT a reason to score lower if it falls into application/cloud/DevSecOps security).

2. "concrete_new": Boolean (true or false).
   - true: Reports a concrete vulnerability, CVE advisory, exploit, PoC, security patch, version release, or documented incident.
   - false: High-level marketing pitch, vendor whitepaper promo, webinar announcement, opinion piece, or vague hype with no actionable technical facts.

Respond with ONLY this JSON format:
{{
  "relevance": <1 to 5>,
  "concrete_new": <true or false>,
  "reason": "<one sentence explanation>"
}}
"""


class DecisionEngine:
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-3.5-flash-lite",
        max_workers: int = 4,
    ):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model = model
        self.max_workers = max_workers
        self.endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        self.headers = {"x-goog-api-key": self.api_key} if self.api_key else {}

    def decide_item(self, item: Item, client: Optional[httpx.Client] = None) -> dict[str, Any]:
        """
        Runs the decision pass on a single item.
        Returns a dict: {"relevance": int, "concrete_new": bool, "route": "keep"|"drop"|"unsure", "reason": str}
        """
        if not self.api_key:
            # If no API key configured, fail-open to unsure
            return {
                "relevance": 3,
                "concrete_new": True,
                "route": "unsure",
                "reason": "No API key configured; fail-open to reading pass",
            }

        prompt = DECISION_PROMPT.format(
            title=item.title,
            source=item.source,
            url=item.url,
            body_snippet=item.body[:1500] if item.body else "",
        )

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "response_mime_type": "application/json",
                "temperature": 0.0,
            },
        }

        # 40s read timeout to accommodate concurrent model latency
        timeout = httpx.Timeout(connect=10.0, read=40.0, write=10.0, pool=10.0)
        own_client = False
        if client is None:
            client = httpx.Client(timeout=timeout, headers=self.headers)
            own_client = True

        try:
            # Retry logic with backoff
            for attempt in range(3):
                try:
                    resp = client.post(self.endpoint, json=payload, timeout=timeout)
                    if resp.status_code in (429, 503):
                        time.sleep(3.0 * (attempt + 1))
                        continue
                    resp.raise_for_status()
                    result_json = resp.json()

                    text = result_json["candidates"][0]["content"]["parts"][0]["text"]
                    data = json.loads(text)

                    relevance = int(data.get("relevance", 3))
                    concrete_new = bool(data.get("concrete_new", True))
                    reason = data.get("reason", "")

                    # Routing in code
                    if relevance <= 2 or not concrete_new:
                        route = "drop"
                    elif relevance >= 4 and concrete_new:
                        route = "keep"
                    else:
                        route = "unsure"

                    return {
                        "relevance": relevance,
                        "concrete_new": concrete_new,
                        "route": route,
                        "reason": reason,
                    }
                except Exception as e:
                    logger.warning(f"Decision attempt {attempt+1} failed for {item.id}: {e}")
                    time.sleep(2.0 * (attempt + 1))
        finally:
            if own_client:
                client.close()

        # Fail-open
        return {
            "relevance": 3,
            "concrete_new": True,
            "route": "unsure",
            "reason": "Decision call failed; fail-open to reading pass",
        }

    def evaluate_batch(self, items: list[Item]) -> dict[str, dict[str, Any]]:
        """
        Runs decision pass concurrently over items using a shared connection pool.
        Returns dict mapping item.id to decision dict.
        """
        results: dict[str, dict[str, Any]] = {}
        timeout = httpx.Timeout(connect=10.0, read=40.0, write=10.0, pool=10.0)
        limits = httpx.Limits(max_keepalive_connections=self.max_workers, max_connections=self.max_workers * 2)

        with httpx.Client(timeout=timeout, headers=self.headers, limits=limits) as client:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_item = {executor.submit(self.decide_item, item, client): item for item in items}
                for future in as_completed(future_to_item):
                    item = future_to_item[future]
                    try:
                        dec = future.result()
                        results[item.id] = dec
                    except Exception as e:
                        results[item.id] = {
                            "relevance": 3,
                            "concrete_new": True,
                            "route": "unsure",
                            "reason": f"Exception: {e}",
                        }
        return results
