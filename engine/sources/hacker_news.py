import logging
from typing import Any, Optional
import httpx

from engine.schema import Item

logger = logging.getLogger(__name__)


class HackerNewsCollector:
    SOURCE_NAME = "Hacker News Security"
    API_URL = "https://hn.algolia.com/api/v1/search_by_date"
    SEARCH_QUERIES = [
        "vulnerability",
        "exploit",
        "security patch",
        "CVE",
        "zero-day",
    ]

    def fetch(self, limit: int = 40) -> list[Item]:
        items: list[Item] = []
        seen_ids: set[str] = set()

        with httpx.Client(timeout=15.0) as client:
            for query in self.SEARCH_QUERIES:
                if len(items) >= limit:
                    break
                params = {
                    "query": query,
                    "tags": "story",
                    "hitsPerPage": 15,
                }
                try:
                    resp = client.get(self.API_URL, params=params)
                    resp.raise_for_status()
                    data = resp.json()
                except Exception as e:
                    logger.warning(f"Error fetching Hacker News for query '{query}': {e}")
                    continue

                for hit in data.get("hits", []):
                    oid = hit.get("objectID")
                    if not oid or oid in seen_ids:
                        continue
                    seen_ids.add(oid)

                    item = self._parse_hit(hit)
                    if item:
                        items.append(item)
                        if len(items) >= limit:
                            break

        return items

    def _parse_hit(self, hit: dict[str, Any]) -> Optional[Item]:
        object_id = hit.get("objectID")
        title = hit.get("title")
        if not object_id or not title:
            return None

        url = hit.get("url") or f"https://news.ycombinator.com/item?id={object_id}"
        points = hit.get("points") or 0
        comments = hit.get("num_comments") or 0

        body = hit.get("story_text") or (
            f"{title}\n\nHacker News Discussion: https://news.ycombinator.com/item?id={object_id} "
            f"({points} points, {comments} comments)"
        )

        return Item(
            id=f"hn:{object_id}",
            source=self.SOURCE_NAME,
            title=title,
            url=url,
            body=body,
            published_at=hit.get("created_at"),
            engagement=float(points),
            metadata={
                "hn_id": object_id,
                "points": points,
                "num_comments": comments,
                "author": hit.get("author"),
            },
        )
