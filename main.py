import argparse
from datetime import datetime, timezone
import logging
import sys
from pathlib import Path

from engine.decision import DecisionEngine
from engine.digest import DigestGenerator
from engine.filters import CodeFilters
from engine.sources import (
    CisaKevCollector,
    GitHubReleasesCollector,
    HackerNewsCollector,
    OSVCollector,
    RssSecurityCollector,
)
from engine.store import Store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logger = logging.getLogger("signal-engine")


def run_pipeline(db_path: str = "data/signal_engine.db") -> None:
    start_time = datetime.now(timezone.utc)
    logger.info("=== Starting DevSecOps Signal Engine Daily Run ===")

    store = Store(db_path)

    # 1. Fetch from all sources
    collectors = [
        ("OSV.dev Vulnerability DB", OSVCollector()),
        ("CISA Known Exploited Vulnerabilities", CisaKevCollector()),
        ("Tool GitHub Releases & Advisories", GitHubReleasesCollector()),
        ("Hacker News Security", HackerNewsCollector()),
        ("Curated Security News Feeds", RssSecurityCollector()),
    ]

    total_fetched = 0
    total_new = 0
    for name, collector in collectors:
        try:
            items = collector.fetch()
            inserted, skipped = store.store_items(items)
            store.record_source_run(name, len(items))
            total_fetched += len(items)
            total_new += inserted
            logger.info(f"Source: {name} -> {len(items)} items fetched, {inserted} new, {skipped} existing")
        except Exception as e:
            logger.error(f"Error collecting from {name}: {e}")

    logger.info(f"Ingestion complete: {total_new} new items added (Total in store: {store.count_items()})")

    # 2. Run Code Filters
    all_items = store.get_items()
    filters = CodeFilters()
    dropped_count = 0
    for item in all_items:
        reason = filters.evaluate(item)
        if reason:
            store.update_item_filter(item.id, reason)
            dropped_count += 1
        else:
            store.update_item_filter(item.id, None)

    surviving = store.get_items(unfiltered_only=True)
    logger.info(f"Code Filters complete: {dropped_count} dropped, {len(surviving)} surviving")

    # 3. Decision Pass
    logger.info(f"Running Decision Pass across {len(surviving)} candidate items...")
    decision_engine = DecisionEngine(max_workers=4)
    decisions = decision_engine.evaluate_batch(surviving)

    kept_count = 0
    drop_count = 0
    unsure_count = 0
    for item in surviving:
        dec = decisions.get(item.id, {})
        route = dec.get("route", "unsure")
        if route == "keep":
            kept_count += 1
            store.update_item_decision(item.id, dec, filtered_by=None)
        elif route == "drop":
            drop_count += 1
            store.update_item_decision(item.id, dec, filtered_by="decision: dropped")
        else:
            unsure_count += 1
            store.update_item_decision(item.id, dec, filtered_by=None)

    logger.info(f"Decision Pass complete: {kept_count} sure keep, {unsure_count} unsure, {drop_count} sure drop")

    # 4. Reading Pass & Digest Generation
    digest_candidates = store.get_items(unfiltered_only=True)
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    logger.info(f"Generating Daily Digest for {today_str} from {len(digest_candidates)} candidates...")

    digest_gen = DigestGenerator()
    content, out_path, included_ids = digest_gen.generate_digest(digest_candidates, date_str=today_str)
    store.mark_in_digest(included_ids, today_str)

    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    logger.info(f"Digest generated: {out_path} ({len(content)} chars)")
    logger.info(f"=== Signal Engine Daily Run Finished in {elapsed:.1f}s ===")


def main():
    parser = argparse.ArgumentParser(description="DevSecOps Signal Engine")
    parser.add_argument("--run", action="store_true", help="Execute daily end-to-end pipeline run")
    parser.add_argument("--db", default="data/signal_engine.db", help="Path to SQLite database")

    args = parser.parse_args()

    if args.run:
        run_pipeline(args.db)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
