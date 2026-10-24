from collections import defaultdict
from engine.filters import CodeFilters
from engine.store import Store


def main():
    store = Store("data/signal_engine.db")
    filters = CodeFilters()

    items = store.get_items()
    total = len(items)

    print(f"=== Stage 3: Running Code Filters on {total} Items ===")

    stats = defaultdict(int)
    survived = 0

    for item in items:
        reason = filters.evaluate(item)
        if reason:
            category = reason.split(":")[0]
            stats[category] += 1
            store.update_item_filter(item.id, reason)
        else:
            stats["survived"] += 1
            survived += 1
            store.update_item_filter(item.id, None)

    print(f"\nResults breakdown:")
    for cat, count in sorted(stats.items()):
        if cat != "survived":
            print(f"- Filter '{cat}': dropped {count} items")

    print(f"\nTotal dropped: {total - survived}")
    print(f"Total surviving: {survived} items ready for decision pass")

    # Sample of surviving items
    surviving_items = store.get_items(unfiltered_only=True, limit=5)
    print("\nSample surviving items:")
    for i in surviving_items:
        print(f"  [{i.source}] {i.title[:80]}")


if __name__ == "__main__":
    main()
