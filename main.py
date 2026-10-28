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


def run_pipeline(db_path: str = "data/signal_engine.db", date_str: str | None = None) -> None:
    start_time = datetime.now(timezone.utc)
    if not date_str:
        date_str = start_time.strftime("%Y-%m-%d")

    logger.info(f"=== Starting DevSecOps Signal Engine Daily Run for {date_str} ===")

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

    # 3. Decision Pass (only evaluate new/undecided items to avoid redundant LLM calls)
    undecided = [
        item for item in surviving
        if item.decision is None or "Decision call failed" in (item.decision or {}).get("reason", "")
    ]
    if undecided:
        logger.info(f"Running Decision Pass on {len(undecided)} new candidate items (skipping {len(surviving) - len(undecided)} already decided)...")
        decision_engine = DecisionEngine(max_workers=4)
        decisions = decision_engine.evaluate_batch(undecided)

        new_kept = 0
        new_dropped = 0
        new_unsure = 0
        for item in undecided:
            dec = decisions.get(item.id, {})
            route = dec.get("route", "unsure")
            if route == "drop":
                new_dropped += 1
                store.update_item_decision(item.id, dec, filtered_by="decision: dropped")
            elif route == "keep":
                new_kept += 1
                store.update_item_decision(item.id, dec, filtered_by=None)
            else:
                new_unsure += 1
                store.update_item_decision(item.id, dec, filtered_by=None)
        logger.info(f"New decisions: {new_kept} kept, {new_unsure} unsure, {new_dropped} dropped")
    else:
        logger.info(f"Decision Pass: all {len(surviving)} candidate items already scored; skipping re-evaluation.")

    # Re-fetch surviving candidates with active decisions
    digest_candidates = store.get_items(unfiltered_only=True)
    kept_count = sum(1 for i in digest_candidates if (i.decision or {}).get("route") == "keep")
    unsure_count = sum(1 for i in digest_candidates if (i.decision or {}).get("route") == "unsure")
    logger.info(f"Candidate pool for digest: {kept_count} sure keep, {unsure_count} unsure")

    # 4. Reading Pass & Digest Generation
    logger.info(f"Generating Daily Digest for {date_str} from {len(digest_candidates)} candidates...")
    digest_gen = DigestGenerator()
    content, out_path, included_ids = digest_gen.generate_digest(digest_candidates, date_str=date_str)
    store.mark_in_digest(included_ids, date_str)

    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
    logger.info(f"Digest generated: {out_path} ({len(content)} chars)")
    logger.info(f"=== Signal Engine Daily Run Finished in {elapsed:.1f}s ===")


def print_stats(db_path: str = "data/signal_engine.db") -> None:
    store = Store(db_path)
    items = store.get_items()
    total = len(items)

    from collections import Counter
    source_counts = Counter(i.source for i in items)
    filter_counts = Counter(i.filtered_by.split(":")[0] if i.filtered_by else "survived" for i in items)
    dec_routes = Counter((i.decision or {}).get("route", "no_decision") for i in items if not i.filtered_by)

    print("=== Signal Engine Database Statistics ===")
    print(f"Total Stored Items: {total}\n")

    print("Breakdown by Source:")
    for src, cnt in source_counts.most_common():
        print(f"  - {src}: {cnt}")

    print("\nBreakdown by Filter Status:")
    for status, cnt in filter_counts.most_common():
        print(f"  - {status}: {cnt}")

    print("\nSurviving Items Decision Routes:")
    for route, cnt in dec_routes.most_common():
        print(f"  - {route}: {cnt}")

    digest_files = sorted(Path("digests").glob("*.md"))
    print(f"\nGenerated Digests ({len(digest_files)} files):")
    for df in digest_files[-5:]:
        print(f"  - {df.name} ({df.stat().st_size} bytes)")


def run_rollup(db_path: str = "data/signal_engine.db", week_str: str | None = None) -> None:
    store = Store(db_path)
    items = store.get_items()
    generator = DigestGenerator()
    content, out_path = generator.generate_weekly_rollup(items, week_str=week_str)
    print(f"Weekly roll-up generated: {out_path} ({len(content)} chars)")


def main():
    parser = argparse.ArgumentParser(description="DevSecOps Signal Engine")
    parser.add_argument("--run", action="store_true", help="Execute daily end-to-end pipeline run")
    parser.add_argument("--rollup", action="store_true", help="Generate weekly intelligence roll-up")
    parser.add_argument("--stats", action="store_true", help="Display storage and engine statistics")
    parser.add_argument("--date", help="Optional date override (YYYY-MM-DD)")
    parser.add_argument("--db", default="data/signal_engine.db", help="Path to SQLite database")

    args = parser.parse_args()

    if args.run:
        run_pipeline(args.db, date_str=args.date)
    elif args.rollup:
        run_rollup(args.db, week_str=args.date)
    elif args.stats:
        print_stats(args.db)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
