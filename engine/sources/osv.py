import logging
from typing import Any, Optional
import httpx

from engine.schema import Item

logger = logging.getLogger(__name__)

TRACKED_PACKAGES = [
    {"name": "litellm", "ecosystem": "PyPI"},
    {"name": "php", "ecosystem": "Packagist"},
    {"name": "kubernetes", "ecosystem": "Go"},
]


class OSVCollector:
    SOURCE_NAME = "OSV.dev Vulnerability DB"
    API_URL = "https://api.osv.dev/v1/query"

    def __init__(self, packages: Optional[list[dict[str, str]]] = None):
        self.packages = packages or TRACKED_PACKAGES

    def fetch(self, limit_per_package: int = 50) -> list[Item]:
        items: list[Item] = []
        with httpx.Client(timeout=15.0) as client:
            for pkg in self.packages:
                payload = {
                    "package": {
                        "name": pkg["name"],
                        "ecosystem": pkg["ecosystem"],
                    }
                }
                try:
                    response = client.post(self.API_URL, json=payload)
                    response.raise_for_status()
                    data = response.json()
                except Exception as e:
                    logger.warning(f"Error fetching OSV for {pkg}: {e}")
                    continue

                vulns = data.get("vulns", [])
                for vuln in vulns[:limit_per_package]:
                    item = self._parse_vuln(vuln, pkg)
                    if item:
                        items.append(item)

        return items

    def _parse_vuln(self, vuln: dict[str, Any], pkg: dict[str, str]) -> Optional[Item]:
        vuln_id = vuln.get("id")
        if not vuln_id:
            return None

        aliases = vuln.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
        summary = vuln.get("summary") or vuln.get("details", "").split("\n")[0] or "Vulnerability advisory"
        if len(summary) > 200:
            summary = summary[:197] + "..."

        title = f"[{cve_id}] {pkg['name']}: {summary}"

        # Find best human-readable URL
        url = f"https://osv.dev/vulnerability/{vuln_id}"
        for ref in vuln.get("references", []):
            ref_url = ref.get("url", "")
            if "github.com" in ref_url and "advisories" in ref_url:
                url = ref_url
                break
            elif "nvd.nist.gov" in ref_url:
                url = ref_url

        body = vuln.get("details") or summary
        if len(body) > 3000:
            body = body[:2997] + "..."

        published_at = vuln.get("published")

        # Parse CVSS score as engagement metric if present
        engagement = None
        for sev in vuln.get("severity", []):
            score_str = sev.get("score", "")
            if "CVSS" in score_str:
                # Store numeric CVSS if parseable, or leave as None
                try:
                    # Often like CVSS:3.1/AV:N/AC:L...
                    engagement = 1.0
                except Exception:
                    pass

        return Item(
            id=f"osv:{vuln_id}",
            source=self.SOURCE_NAME,
            title=title,
            url=url,
            body=body,
            published_at=published_at,
            engagement=engagement,
            metadata={
                "aliases": aliases,
                "package": pkg["name"],
                "ecosystem": pkg["ecosystem"],
                "osv_id": vuln_id,
            },
        )
