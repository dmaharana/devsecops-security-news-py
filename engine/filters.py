from datetime import datetime, timezone, timedelta
from typing import Optional
import re
from engine.schema import Item


class CodeFilters:
    def __init__(
        self,
        max_age_advisories_days: int = 7,
        max_age_community_days: int = 3,
        min_engagement_community: float = 10.0,
        now: Optional[datetime] = None,
    ):
        self.max_age_advisories = timedelta(days=max_age_advisories_days)
        self.max_age_community = timedelta(days=max_age_community_days)
        self.min_engagement_community = min_engagement_community
        self.now = now or datetime.now(timezone.utc)

    def evaluate(self, item: Item) -> Optional[str]:
        """
        Evaluates code filters against the item.
        Returns the drop reason string if filtered out, or None if kept.
        """
        # 1. Title/content sanity filter
        if not item.title or len(item.title.strip()) < 5:
            return "content: title too short or empty"

        # 2. Language filter (simple non-English detection)
        # Drop if substantial CJK/Cyrillic without English words
        cjk_chars = len(re.findall(r"[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]", item.title))
        if cjk_chars > len(item.title) * 0.3:
            return "language: non-English content"

        # 3. Age filter
        if item.published_at:
            try:
                # Handle varying ISO string formats
                dt_str = item.published_at.replace("Z", "+00:00")
                pub_dt = datetime.fromisoformat(dt_str)
                if pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=timezone.utc)

                age = self.now - pub_dt

                is_official = item.source in [
                    "OSV.dev Vulnerability DB",
                    "CISA Known Exploited Vulnerabilities",
                    "Tool GitHub Releases & Advisories",
                ]

                max_allowed = self.max_age_advisories if is_official else self.max_age_community
                if age > max_allowed:
                    days_old = int(age.total_seconds() // 86400)
                    limit_days = int(max_allowed.total_seconds() // 86400)
                    return f"age: {days_old}d old exceeds {limit_days}d limit"
            except Exception:
                pass

        # 4. Engagement filter
        if item.source == "Hacker News Security":
            engagement = item.engagement or 0.0
            if engagement < self.min_engagement_community:
                return f"engagement: {int(engagement)} points below floor of {int(self.min_engagement_community)}"

        return None
