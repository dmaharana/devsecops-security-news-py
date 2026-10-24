import sys
from engine.sources import (
    CisaKevCollector,
    GitHubReleasesCollector,
    HackerNewsCollector,
    OSVCollector,
    RssSecurityCollector,
)
from engine.store import Store


def main():
    store = Store("data/signal_engine.db")

    collectors = [
        ("OSV.dev Vulnerability DB", OSVCollector(), "OSV REST API"),
        ("CISA Known Exploited Vulnerabilities", CisaKevCollector(), "CISA KEV JSON Feed"),
        ("Tool GitHub Releases & Advisories", GitHubReleasesCollector(), "GitHub Releases API"),
        ("Hacker News Security", HackerNewsCollector(), "HN Algolia API"),
        ("Curated Security News Feeds", RssSecurityCollector(), "Direct RSS/Atom Feeds"),
    ]

    print("=== Stage 2: Pulling Every Source ===")
    total_fetched = 0
    total_inserted = 0

    results = []

    for name, collector, method in collectors:
        try:
            items = collector.fetch()
            count = len(items)
            inserted, skipped = store.store_items(items)
            store.record_source_run(name, count)
            total_fetched += count
            total_inserted += inserted
            results.append((name, method, count, inserted, skipped))
            print(f"- {name} ({method}): {count} returned, {inserted} newly stored, {skipped} already known")
        except Exception as e:
            print(f"- {name} ERROR: {e}")

    print(f"\nTotal in DB: {store.count_items()}")

    print("\n=== Stage 2: Immediate Re-run Verification (Proof of Stable IDs) ===")
    total_reinserted = 0
    for name, collector, method in collectors:
        items = collector.fetch()
        inserted, skipped = store.store_items(items)
        total_reinserted += inserted
        print(f"- {name} re-run: {inserted} inserted, {skipped} skipped")

    print(f"\nImmediate re-run new items added: {total_reinserted}")
    if total_reinserted == 0:
        print("VERDICT: PASS (Stable ID deduplication confirmed across all sources: exactly 0 items added on re-run)")
    else:
        print(f"VERDICT: FAIL ({total_reinserted} items re-inserted)")
        sys.exit(1)


if __name__ == "__main__":
    main()
