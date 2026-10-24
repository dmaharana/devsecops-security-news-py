import hashlib
import logging
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any, Optional
import xml.etree.ElementTree as ET
import httpx

from engine.schema import Item

logger = logging.getLogger(__name__)

SECURITY_FEEDS = [
    {
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
    },
    {
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
    },
    {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
    },
]


class RssSecurityCollector:
    SOURCE_NAME = "Curated Security News Feeds"

    def __init__(self, feeds: Optional[list[dict[str, str]]] = None):
        self.feeds = feeds or SECURITY_FEEDS

    def fetch(self, limit_per_feed: int = 25) -> list[Item]:
        items: list[Item] = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "application/rss+xml, application/xml, text/xml",
        }

        with httpx.Client(timeout=15.0, headers=headers, follow_redirects=True) as client:
            for feed in self.feeds:
                try:
                    resp = client.get(feed["url"])
                    resp.raise_for_status()
                    feed_items = self._parse_feed_xml(resp.text, feed["name"], limit_per_feed)
                    items.extend(feed_items)
                except Exception as e:
                    logger.warning(f"Error fetching RSS feed {feed['name']}: {e}")

        return items

    def _parse_feed_xml(self, xml_text: str, feed_name: str, limit: int) -> list[Item]:
        items: list[Item] = []
        try:
            root = ET.fromstring(xml_text)
        except Exception as e:
            logger.warning(f"XML parse error for {feed_name}: {e}")
            return items

        # Look for standard RSS items
        rss_items = root.findall(".//item")
        for elem in rss_items[:limit]:
            title_el = elem.find("title")
            link_el = elem.find("link")
            desc_el = elem.find("description")
            pub_date_el = elem.find("pubDate")

            title = title_el.text.strip() if (title_el is not None and title_el.text) else ""
            link = link_el.text.strip() if (link_el is not None and link_el.text) else ""
            desc = desc_el.text.strip() if (desc_el is not None and desc_el.text) else ""

            if not title or not link:
                continue

            # Strip HTML tags from description if needed
            clean_desc = desc
            if "<" in clean_desc and ">" in clean_desc:
                import re
                clean_desc = re.sub(r"<[^>]+>", " ", clean_desc).strip()
            if len(clean_desc) > 3000:
                clean_desc = clean_desc[:2997] + "..."

            published_iso = None
            if pub_date_el is not None and pub_date_el.text:
                try:
                    dt = parsedate_to_datetime(pub_date_el.text.strip())
                    published_iso = dt.isoformat()
                except Exception:
                    pass

            # Stable ID derived from URL hash
            url_hash = hashlib.sha256(link.encode("utf-8")).hexdigest()[:16]
            stable_id = f"rss:{feed_name.lower().replace(' ', '_')}:{url_hash}"

            items.append(
                Item(
                    id=stable_id,
                    source=self.SOURCE_NAME,
                    title=f"[{feed_name}] {title}",
                    url=link,
                    body=clean_desc or title,
                    published_at=published_iso,
                    engagement=5.0,  # Curated published news
                    metadata={
                        "feed_name": feed_name,
                        "raw_title": title,
                    },
                )
            )

        return items
