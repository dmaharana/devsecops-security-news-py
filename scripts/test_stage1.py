from engine.sources.osv import OSVCollector
from engine.store import Store


def main():
    db_path = "data/signal_engine.db"
    store = Store(db_path)
    collector = OSVCollector()

    print("Fetching from OSV.dev...")
    items = collector.fetch(limit_per_package=50)
    print(f"Items fetched: {len(items)}")

    # First run
    inserted, skipped = store.store_items(items)
    store.record_source_run(collector.SOURCE_NAME, len(items))
    print(f"Run 1: {inserted} inserted, {skipped} skipped. Total in DB: {store.count_items()}")

    # Second run (immediate re-run to verify deduplication and stable IDs)
    inserted_rerun, skipped_rerun = store.store_items(items)
    print(f"Run 2 (re-run): {inserted_rerun} inserted, {skipped_rerun} skipped.")

    if inserted_rerun == 0:
        print("VERDICT: PASS (Stable ID deduplication confirmed: 0 new items on re-run)")
    else:
        print(f"VERDICT: FAIL ({inserted_rerun} duplicate items inserted)")


if __name__ == "__main__":
    main()
