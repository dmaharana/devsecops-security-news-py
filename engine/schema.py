from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class Item:
    id: str
    source: str
    title: str
    url: str
    body: str
    published_at: Optional[str] = None
    engagement: Optional[float] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    filtered_by: Optional[str] = None
    decision: Optional[dict[str, Any]] = None
    in_digest: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
