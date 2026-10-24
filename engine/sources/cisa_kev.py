import logging
from typing import Any, Optional
import httpx

from engine.schema import Item

logger = logging.getLogger(__name__)


class CisaKevCollector:
    SOURCE_NAME = "CISA Known Exploited Vulnerabilities"
    FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def fetch(self, limit: int = 50) -> list[Item]:
        items: list[Item] = []
        try:
            with httpx.Client(timeout=20.0) as client:
                resp = client.get(self.FEED_URL, headers={"User-Agent": "signal-engine/1.0"})
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            logger.warning(f"Error fetching CISA KEV feed: {e}")
            return items

        vulnerabilities = data.get("vulnerabilities", [])
        # Most recent first
        vulnerabilities.reverse()

        for vuln in vulnerabilities[:limit]:
            item = self._parse_vuln(vuln)
            if item:
                items.append(item)

        return items

    def _parse_vuln(self, vuln: dict[str, Any]) -> Optional[Item]:
        cve_id = vuln.get("cveID")
        if not cve_id:
            return None

        vendor = vuln.get("vendorProject", "Unknown")
        product = vuln.get("product", "Unknown")
        vuln_name = vuln.get("vulnerabilityName", "Exploited Vulnerability")
        title = f"[{cve_id}] {vendor} {product}: {vuln_name}"

        desc = vuln.get("shortDescription", "")
        action = vuln.get("requiredAction", "")
        due = vuln.get("dueDate", "")
        ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

        body = (
            f"{desc}\n\n"
            f"**Action Required**: {action}\n"
            f"**Due Date**: {due}\n"
            f"**Known Ransomware Campaign**: {ransomware}"
        )

        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        return Item(
            id=f"cisa:{cve_id}",
            source=self.SOURCE_NAME,
            title=title,
            url=url,
            body=body,
            published_at=vuln.get("dateAdded"),
            engagement=10.0,
            metadata={
                "vendor": vendor,
                "product": product,
                "ransomware": ransomware,
                "cve": cve_id,
            },
        )
