from engine.decision import DecisionEngine
from engine.schema import Item
from engine.store import Store


def test_profile_examples():
    engine = DecisionEngine()

    keep_examples = [
        Item(
            id="test:keep:1",
            source="OSV.dev Vulnerability DB",
            title="[CVE-2024-34359] LiteLLM: SSRF and Proxy Authentication Bypass in Routing Handler",
            url="https://github.com/BerriAI/litellm/security/advisories/GHSA-1234",
            body="A critical vulnerability in LiteLLM allows remote attackers to bypass proxy auth and trigger internal SSRF. Patched in v1.35.0.",
        ),
        Item(
            id="test:keep:2",
            source="Curated Security News Feeds",
            title="[The Hacker News] PHP CGI Argument Injection RCE Advisory (CVE-2024-4577) Patched",
            url="https://thehackernews.com/php-cve-2024-4577",
            body="PHP maintainers released emergency patches for CVE-2024-4577, an argument injection vulnerability leading to remote code execution on Windows and Apache CGI setups.",
        ),
        Item(
            id="test:keep:3",
            source="Tool GitHub Releases & Advisories",
            title="[jenkinsci/jenkins] Critical Security Advisory: Secret Leakage in Pipeline Runner",
            url="https://jenkins.io/security/advisory/2026-10-24",
            body="Jenkins project has released version 2.479 addressing a vulnerability that exposes pipeline runner credentials to unprivileged jobs.",
        ),
    ]

    drop_examples = [
        Item(
            id="test:drop:1",
            source="Hacker News Security",
            title="Why AGI is 5 Years Away and What It Means for Humanity's Future",
            url="https://news.ycombinator.com/item?id=99991",
            body="A philosophical essay discussing the long-term societal implications of superintelligence and existential risk.",
        ),
        Item(
            id="test:drop:2",
            source="Curated Security News Feeds",
            title="[Vendor Spotlight] Why Our New AI Security Platform Outperforms All Competitors (Sponsored)",
            url="https://vendor.example.com/whitepaper",
            body="Download our new whitepaper to learn how our proprietary zero-trust enterprise engine redefines cybersecurity for Fortune 500 companies.",
        ),
        Item(
            id="test:drop:3",
            source="Hacker News Security",
            title="DeFi Protocol FluffyCoin Drained of $1.2M in Reentrancy Exploit on Solana",
            url="https://news.ycombinator.com/item?id=99992",
            body="Attackers drained a decentralized liquidity pool using a flash loan reentrancy vulnerability in a meme token smart contract.",
        ),
    ]

    print("=== Testing PROFILE.md Keep Examples ===")
    keep_passes = 0
    for ex in keep_examples:
        res = engine.decide_item(ex)
        print(f"[{res['route'].upper()}] (Rel: {res['relevance']}, New: {res['concrete_new']}) {ex.title}")
        print(f"  Reason: {res['reason']}")
        if res["route"] == "keep":
            keep_passes += 1

    print("\n=== Testing PROFILE.md Drop Examples ===")
    drop_passes = 0
    for ex in drop_examples:
        res = engine.decide_item(ex)
        print(f"[{res['route'].upper()}] (Rel: {res['relevance']}, New: {res['concrete_new']}) {ex.title}")
        print(f"  Reason: {res['reason']}")
        if res["route"] == "drop":
            drop_passes += 1

    print(f"\nProfile examples evaluation: Keep {keep_passes}/{len(keep_examples)}, Drop {drop_passes}/{len(drop_examples)}")
    if keep_passes == len(keep_examples) and drop_passes == len(drop_examples):
        print("VERDICT: PASS (All PROFILE.md keep/drop examples routed exactly as specified)")
    else:
        print("VERDICT: FAIL (Some examples misrouted)")


def test_real_items():
    store = Store("data/signal_engine.db")
    engine = DecisionEngine(max_workers=8)

    # Get items that survived code filters
    surviving_items = store.get_items(unfiltered_only=True)
    print(f"\n=== Scoring {len(surviving_items)} Real Items Surviving Code Filters ===")

    decisions = engine.evaluate_batch(surviving_items)

    counts = {"keep": 0, "drop": 0, "unsure": 0}
    for item in surviving_items:
        dec = decisions.get(item.id, {})
        route = dec.get("route", "unsure")
        counts[route] += 1
        # Update in DB
        filter_status = "decision: dropped (not relevant or not new)" if route == "drop" else None
        store.update_item_decision(item.id, dec, filtered_by=filter_status)

    print(f"Decision breakdown on real items:")
    print(f"- Kept (sure keep): {counts['keep']}")
    print(f"- Unsure (sent to reading pass): {counts['unsure']}")
    print(f"- Dropped (sure drop): {counts['drop']}")
    print(f"Total passed to LLM reader: {counts['keep'] + counts['unsure']}")

    print("\nSample Kept Items:")
    for item in surviving_items:
        if decisions.get(item.id, {}).get("route") == "keep":
            d = decisions[item.id]
            print(f"  * [Rel {d['relevance']}] {item.title[:85]}")

    print("\nSample Dropped Items:")
    for item in surviving_items:
        if decisions.get(item.id, {}).get("route") == "drop":
            d = decisions[item.id]
            print(f"  * [Rel {d['relevance']}] {item.title[:85]}")


def main():
    test_profile_examples()
    test_real_items()


if __name__ == "__main__":
    main()
