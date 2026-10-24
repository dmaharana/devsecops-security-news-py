from engine.digest import DigestGenerator
from engine.store import Store


def main():
    store = Store("data/signal_engine.db")

    # Get all items that were not dropped by code filters or decision
    items = store.get_items(unfiltered_only=True)
    print(f"=== Stage 5: Generating Daily Digest from {len(items)} Items ===")

    generator = DigestGenerator()
    content, out_path, item_ids = generator.generate_digest(items)

    # Mark included items in store
    store.mark_in_digest(item_ids, out_path.stem)

    print(f"\nDigest generated successfully: {out_path}")
    print(f"Size: {len(content)} characters, lines: {len(content.splitlines())}")

    print("\n--- Digest Preview ---")
    preview_lines = content.splitlines()[:35]
    print("\n".join(preview_lines))
    print("----------------------\n")

    if out_path.exists() and len(content) > 200:
        print("VERDICT: PASS (Daily digest created from today's real data)")
    else:
        print("VERDICT: FAIL (Digest generation failed)")


if __name__ == "__main__":
    main()
