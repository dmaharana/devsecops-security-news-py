import logging
from typing import Any, Optional
import httpx

from engine.schema import Item

logger = logging.getLogger(__name__)

TRACKED_REPOS = [
    "BerriAI/litellm",
    "php/php-src",
    "kubernetes/kubernetes",
    "jenkinsci/jenkins",
]


class GitHubReleasesCollector:
    SOURCE_NAME = "Tool GitHub Releases & Advisories"

    def __init__(self, repos: Optional[list[str]] = None):
        self.repos = repos or TRACKED_REPOS

    def fetch(self, limit_per_repo: int = 15) -> list[Item]:
        items: list[Item] = []
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "signal-engine/1.0",
        }

        with httpx.Client(timeout=15.0, headers=headers) as client:
            for repo in self.repos:
                url = f"https://api.github.com/repos/{repo}/releases?per_page={limit_per_repo}"
                try:
                    resp = client.get(url)
                    if resp.status_code == 403:
                        logger.warning(f"GitHub API rate limit exceeded for {repo}")
                        continue
                    resp.raise_for_status()
                    releases = resp.json()
                except Exception as e:
                    logger.warning(f"Error fetching GitHub releases for {repo}: {e}")
                    continue

                for rel in releases:
                    item = self._parse_release(rel, repo)
                    if item:
                        items.append(item)

        return items

    def _parse_release(self, rel: dict[str, Any], repo: dict[str, str]) -> Optional[Item]:
        rel_id = rel.get("id")
        if not rel_id:
            return None

        tag = rel.get("tag_name", "")
        name = rel.get("name") or tag
        title = f"[{repo}] {name}"
        if len(title) > 200:
            title = title[:197] + "..."

        body = rel.get("body", "") or "No release notes provided."
        if len(body) > 3000:
            body = body[:2997] + "..."

        url = rel.get("html_url", f"https://github.com/{repo}/releases/tag/{tag}")
        published_at = rel.get("published_at")

        return Item(
            id=f"gh:{repo}:{rel_id}",
            source=self.SOURCE_NAME,
            title=title,
            url=url,
            body=body,
            published_at=published_at,
            engagement=float(rel.get("mentions_count") or 0.0),
            metadata={
                "repo": repo,
                "tag": tag,
                "prerelease": rel.get("prerelease", False),
            },
        )
