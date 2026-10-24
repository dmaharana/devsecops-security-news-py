import logging
from typing import Any, Optional
import httpx

from engine.schema import Item

logger = logging.getLogger(__name__)


class HackerNewsCollector:
    SOURCE_NAME = "Hacker News Security"
    API_URL = "https://hn.algolia.com/api/v1/search"

    def fetch(self, limit: int = 30) -> list[Item]:
        items: list[Item] = []
        params = {
            "query": "vulnerability OR CVE OR exploit OR zero-day OR breach",
            "tags": "story",
            "hitsPerPage": limit,
        }

        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.get(self.API_URL, params=params)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            logger.warning(f"Error fetching Hacker News security stories: {e}")
            return items

        hits = data.get("hits", [])
        for hit in hits:
            item = self._parse_hit(hit)
            if item:
                items.append(item)

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
