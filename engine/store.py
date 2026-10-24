import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from engine.schema import Item


class Store:
    def __init__(self, db_path: str | Path = "data/signal_engine.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS items (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    title TEXT NOT NULL,
                    url TEXT NOT NULL,
                    body TEXT NOT NULL,
                    published_at TEXT,
                    engagement REAL,
                    metadata TEXT,
                    filtered_by TEXT,
                    decision TEXT,
                    in_digest TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sources (
                    name TEXT PRIMARY KEY,
                    last_fetched_at TEXT,
                    last_item_count INTEGER,
                    status TEXT
                )
                """
            )
            conn.commit()

    def item_exists(self, item_id: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT 1 FROM items WHERE id = ?", (item_id,))
            return cursor.fetchone() is not None

    def store_items(self, items: list[Item]) -> tuple[int, int]:
        """
        Stores items. Deduplicates based on item id.
        Returns (newly_inserted_count, skipped_count).
        """
        now = datetime.now(timezone.utc).isoformat()
        inserted = 0
        skipped = 0

        with self._get_connection() as conn:
            for item in items:
                cursor = conn.execute("SELECT id FROM items WHERE id = ?", (item.id,))
                if cursor.fetchone():
                    skipped += 1
                    continue

                conn.execute(
                    """
                    INSERT INTO items (
                        id, source, title, url, body, published_at,
                        engagement, metadata, filtered_by, decision,
                        in_digest, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        item.id,
                        item.source,
                        item.title,
                        item.url,
                        item.body,
                        item.published_at,
                        item.engagement,
                        json.dumps(item.metadata),
                        item.filtered_by,
                        json.dumps(item.decision) if item.decision else None,
                        item.in_digest,
                        now,
                        now,
                    ),
                )
                inserted += 1
            conn.commit()

        return inserted, skipped

    def record_source_run(self, name: str, count: int, status: str = "ok") -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO sources (name, last_fetched_at, last_item_count, status)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    last_fetched_at = excluded.last_fetched_at,
                    last_item_count = excluded.last_item_count,
                    status = excluded.status
                """,
                (name, now, count, status),
            )
            conn.commit()

    def get_items(
        self,
        source: Optional[str] = None,
        unfiltered_only: bool = False,
        limit: Optional[int] = None,
    ) -> list[Item]:
        query = "SELECT * FROM items WHERE 1=1"
        params: list[Any] = []

        if source:
            query += " AND source = ?"
            params.append(source)
        if unfiltered_only:
            query += " AND filtered_by IS NULL"

        query += " ORDER BY published_at DESC NULLS LAST"
        if limit:
            query += " LIMIT ?"
            params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

        items: list[Item] = []
        for r in rows:
            items.append(
                Item(
                    id=r["id"],
                    source=r["source"],
                    title=r["title"],
                    url=r["url"],
                    body=r["body"],
                    published_at=r["published_at"],
                    engagement=r["engagement"],
                    metadata=json.loads(r["metadata"]) if r["metadata"] else {},
                    filtered_by=r["filtered_by"],
                    decision=json.loads(r["decision"]) if r["decision"] else None,
                    in_digest=r["in_digest"],
                )
            )
        return items

    def update_item_filter(self, item_id: str, filtered_by: Optional[str]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE items SET filtered_by = ?, updated_at = ? WHERE id = ?",
                (filtered_by, now, item_id),
            )
            conn.commit()

    def update_item_decision(self, item_id: str, decision: dict[str, Any], filtered_by: Optional[str] = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE items SET decision = ?, filtered_by = ?, updated_at = ? WHERE id = ?",
                (json.dumps(decision), filtered_by, now, item_id),
            )
            conn.commit()

    def mark_in_digest(self, item_ids: list[str], digest_date: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._get_connection() as conn:
            for item_id in item_ids:
                conn.execute(
                    "UPDATE items SET in_digest = ?, updated_at = ? WHERE id = ?",
                    (digest_date, now, item_id),
                )
            conn.commit()

    def count_items(self) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM items")
            return cursor.fetchone()[0]
