"""
Synthetic benchmark for ACL rules engine throughput.

Measures how many broadcast packets the BBMD can evaluate against
its ACL rules per second, isolating the rule-matching hot path from
network I/O and BACnet protocol decoding.

Compares Python and Rust implementations side-by-side.

Usage:
    python -m benchmarks.bench_acl_engine [--rules 100] [--iterations 100000]
"""

import argparse
import random
import time
import statistics
from ipaddress import IPv4Network

from bacpypes3.pdu import IPv4Address

from ace_acl_bbmd.models.acl import (
    ACLConfig,
    ACLRule,
    RuleAction,
    MessageType,
    TimeRange,
)
from ace_acl_bbmd.acl_engine import ACLEngine
from ace_acl_engine import RustACLEngine, RustACLRule


# ---------------------------------------------------------------------------
# Helpers to generate synthetic rules and packets
# ---------------------------------------------------------------------------

SUBNETS = [f"10.{i}.0.0/16" for i in range(256)]
MESSAGE_TYPES_LIST = [mt for mt in MessageType if mt != MessageType.ALL]

def make_rules(n: int, deny_pct: float = 0.20) -> list[ACLRule]:
    """Generate n synthetic ACL rules with ~deny_pct fraction being DENY rules.

    Args:
        n: Number of rules to generate.
        deny_pct: Fraction of rules that should be DENY (default 0.20 = 20%).
    """
    rules: list[ACLRule] = []
    rng = random.Random(42)  # deterministic for reproducibility

    for i in range(n):
        subnet = rng.choice(SUBNETS)
        # 20% deny, 80% allow/allow_log
        if rng.random() < deny_pct:
            action = RuleAction.DENY
        else:
            action = rng.choice([RuleAction.ALLOW, RuleAction.ALLOW_LOG])
        msg_types = rng.sample(MESSAGE_TYPES_LIST, k=rng.randint(1, 4))

        rule_kwargs: dict = dict(
            name=f"rule_{i:04d}",
            action=action,
            priority=i,
            source_network=subnet,
            message_types=msg_types,
            log_matches=False,
            enabled=True,
        )

        # ~30% of rules also have a dest_network filter
        if rng.random() < 0.3:
            rule_kwargs["dest_network"] = rng.choice(SUBNETS)

        # ~10% have a time_range (always active for benchmark purposes)
        if rng.random() < 0.1:
            rule_kwargs["time_range"] = TimeRange(
                start="00:00", end="23:59"
            )

        rules.append(ACLRule(**rule_kwargs))

    return rules


def make_source_addrs(n: int) -> list[IPv4Address]:
    """Generate n random source IPv4Addresses across the 10.x.x.x space."""
    rng = random.Random(99)
    addrs = []
    for _ in range(n):
        ip = f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
        addrs.append(IPv4Address(f"{ip}:47808"))
    return addrs


def make_rust_engine(rules: list[ACLRule], default_action: RuleAction = RuleAction.DENY) -> RustACLEngine:
    """Convert Python ACLRules to RustACLRules and build a RustACLEngine."""
    rust_rules = []
    for r in rules:
        rust_rules.append(RustACLRule(
            name=r.name,
            action=r.action.value,
            priority=r.priority,
            source_network=str(r.source_network) if r.source_network else None,
            dest_network=str(r.dest_network) if r.dest_network else None,
            source_device=r.source_device,
            dest_device=r.dest_device,
            message_types=[mt.value for mt in r.message_types],
            enabled=r.enabled,
        ))
    return RustACLEngine(rust_rules, default_action=default_action.value)


def make_source_strs(n: int) -> list[str]:
    """Generate n random source IP strings (for Rust engine which takes str)."""
    rng = random.Random(99)  # same seed as make_source_addrs
    return [
        f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}:47808"
        for _ in range(n)
    ]


# ---------------------------------------------------------------------------
# Benchmark scenarios
# ---------------------------------------------------------------------------

def bench_find_matching_rule(config: ACLConfig, sources: list[IPv4Address],
                              iterations: int) -> dict:
    """Benchmark ACLConfig.find_matching_rule() — the pure rule-match hot path."""
    msg_types = [mt.value for mt in MESSAGE_TYPES_LIST]
    rng = random.Random(7)

    # Pre-build the call args to exclude RNG from timing
    call_args = []
    for _ in range(iterations):
        src = rng.choice(sources)
        msg = rng.choice(msg_types)
        call_args.append((src, None, msg))

    # Warm up (populate any internal caches / JIT)
    for src, dest, msg in call_args[:1000]:
        config.find_matching_rule(src, dest, msg)

    # Timed run
    start = time.perf_counter()
    for src, dest, msg in call_args:
        config.find_matching_rule(src, dest, msg)
    elapsed = time.perf_counter() - start

    return {
        "name": "find_matching_rule",
        "iterations": iterations,
        "total_seconds": elapsed,
        "ops_per_sec": iterations / elapsed,
    }


def bench_check_packet(engine: ACLEngine, sources: list[IPv4Address],
                        iterations: int) -> dict:
    """Benchmark ACLEngine.check_packet() — includes packet inspection overhead."""
    # Minimal NPDU-like payload (version=1, no DNET/SNET, data-expecting-reply=0)
    sample_pdu = bytes([0x01, 0x04, 0x00, 0x00, 0x00])
    msg_types = [mt.value for mt in MESSAGE_TYPES_LIST]
    rng = random.Random(7)

    call_args = []
    for _ in range(iterations):
        src = rng.choice(sources)
        bvll = rng.choice(msg_types)
        call_args.append((src, bvll))

    # Warm up
    for src, bvll in call_args[:1000]:
        engine.check_packet(sample_pdu, src, dest=None, bvll_type=bvll)

    start = time.perf_counter()
    for src, bvll in call_args:
        engine.check_packet(sample_pdu, src, dest=None, bvll_type=bvll)
    elapsed = time.perf_counter() - start

    return {
        "name": "check_packet",
        "iterations": iterations,
        "total_seconds": elapsed,
        "ops_per_sec": iterations / elapsed,
    }


def bench_worst_case(config: ACLConfig, iterations: int) -> dict:
    """Worst case: source that matches NO rule, forcing full rule list scan."""
    # Use an address outside all 10.x.x.x subnets
    miss_src = IPv4Address("172.16.99.99:47808")

    start = time.perf_counter()
    for _ in range(iterations):
        config.find_matching_rule(miss_src, None, "original_broadcast")
    elapsed = time.perf_counter() - start

    return {
        "name": "worst_case_no_match",
        "iterations": iterations,
        "total_seconds": elapsed,
        "ops_per_sec": iterations / elapsed,
    }


def bench_best_case(config: ACLConfig, sources: list[IPv4Address],
                     iterations: int) -> dict:
    """Best case: packet matches the very first rule."""
    # Find the first rule's source network and craft an address inside it
    first_rule = config.get_sorted_rules()[0]
    net = first_rule.source_network
    if net:
        # Pick the first usable host in the network
        host = str(list(net.hosts())[0])
    else:
        host = "10.0.0.1"
    best_src = IPv4Address(f"{host}:47808")
    # Use a message type the first rule accepts
    msg = first_rule.message_types[0].value

    start = time.perf_counter()
    for _ in range(iterations):
        config.find_matching_rule(best_src, None, msg)
    elapsed = time.perf_counter() - start

    return {
        "name": "best_case_first_match",
        "iterations": iterations,
        "total_seconds": elapsed,
        "ops_per_sec": iterations / elapsed,
    }


def bench_rust_check(rust_engine: RustACLEngine, source_strs: list[str],
                      iterations: int) -> dict:
    """Benchmark RustACLEngine.check() — single packet at a time via Python call."""
    msg_types = [mt.value for mt in MESSAGE_TYPES_LIST]
    rng = random.Random(7)

    call_args = []
    for _ in range(iterations):
        src = rng.choice(source_strs)
        msg = rng.choice(msg_types)
        call_args.append((src, msg))

    # Warm up
    for src, msg in call_args[:1000]:
        rust_engine.check(src, message_type=msg)

    start = time.perf_counter()
    for src, msg in call_args:
        rust_engine.check(src, message_type=msg)
    elapsed = time.perf_counter() - start

    return {
        "name": "rust_check (per-call)",
        "iterations": iterations,
        "total_seconds": elapsed,
        "ops_per_sec": iterations / elapsed,
    }


def bench_rust_batch(rust_engine: RustACLEngine, source_strs: list[str],
                      iterations: int) -> dict:
    """Benchmark RustACLEngine.check_batch() — batched calls staying in Rust."""
    msg_types = [mt.value for mt in MESSAGE_TYPES_LIST]
    rng = random.Random(7)

    packets = []
    for _ in range(iterations):
        src = rng.choice(source_strs)
        msg = rng.choice(msg_types)
        packets.append((src, None, msg))

    # Warm up
    rust_engine.check_batch(packets[:1000])

    start = time.perf_counter()
    rust_engine.check_batch(packets)
    elapsed = time.perf_counter() - start

    return {
        "name": "rust_check_batch",
        "iterations": iterations,
        "total_seconds": elapsed,
        "ops_per_sec": iterations / elapsed,
    }


def bench_rust_check_packet(rust_engine: RustACLEngine, source_strs: list[str],
                             iterations: int) -> dict:
    """Benchmark RustACLEngine.check_packet() — full pipeline: NPDU decode + rule match in Rust."""
    msg_types = [mt.value for mt in MESSAGE_TYPES_LIST]
    rng = random.Random(7)

    # Sample NPDU packets: local WhoIs and global broadcast WhoIs
    sample_pdus = [
        bytes([0x01, 0x00, 0x10, 0x08]),                              # local WhoIs
        bytes([0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08]),      # global broadcast WhoIs
        bytes([0x01, 0x00, 0x10, 0x00]),                              # local IAm
        bytes([0x01, 0x00, 0x00, 0x05, 0x01, 0x0C]),                  # ConfirmedRequest ReadProperty
    ]

    call_args = []
    for _ in range(iterations):
        src = rng.choice(source_strs)
        pdu = rng.choice(sample_pdus)
        call_args.append((pdu, src))

    # Warm up
    for pdu, src in call_args[:1000]:
        rust_engine.check_packet(pdu, src)

    start = time.perf_counter()
    for pdu, src in call_args:
        rust_engine.check_packet(pdu, src)
    elapsed = time.perf_counter() - start

    return {
        "name": "rust_check_packet (full)",
        "iterations": iterations,
        "total_seconds": elapsed,
        "ops_per_sec": iterations / elapsed,
    }


def bench_rust_worst_case(rust_engine: RustACLEngine, iterations: int) -> dict:
    """Worst case for Rust engine: no rule matches."""
    miss_src = "172.16.99.99:47808"

    start = time.perf_counter()
    for _ in range(iterations):
        rust_engine.check(miss_src, message_type="original_broadcast")
    elapsed = time.perf_counter() - start

    return {
        "name": "rust_worst_case_no_match",
        "iterations": iterations,
        "total_seconds": elapsed,
        "ops_per_sec": iterations / elapsed,
    }


def bench_rust_best_case(rust_engine: RustACLEngine, rules: list[ACLRule],
                          iterations: int) -> dict:
    """Best case for Rust engine: first rule matches."""
    first_rule = sorted([r for r in rules if r.enabled], key=lambda r: r.priority)[0]
    net = first_rule.source_network
    if net:
        host = str(list(net.hosts())[0])
    else:
        host = "10.0.0.1"
    best_src = f"{host}:47808"
    msg = first_rule.message_types[0].value

    start = time.perf_counter()
    for _ in range(iterations):
        rust_engine.check(best_src, message_type=msg)
    elapsed = time.perf_counter() - start

    return {
        "name": "rust_best_case_first_match",
        "iterations": iterations,
        "total_seconds": elapsed,
        "ops_per_sec": iterations / elapsed,
    }


def bench_rust_scaling(iterations: int) -> list[dict]:
    """Measure Rust engine throughput as rule count scales."""
    rule_counts = [10, 50, 100, 250, 500, 1000]
    results = []
    miss_src = "172.16.99.99:47808"

    for n in rule_counts:
        rules = make_rules(n)
        rust_engine = make_rust_engine(rules)

        start = time.perf_counter()
        for _ in range(iterations):
            rust_engine.check(miss_src, message_type="original_broadcast")
        elapsed = time.perf_counter() - start

        results.append({
            "rules": n,
            "iterations": iterations,
            "total_seconds": elapsed,
            "ops_per_sec": iterations / elapsed,
        })

    return results


def bench_scaling(iterations: int) -> list[dict]:
    """Measure throughput as rule count scales: 10, 50, 100, 250, 500, 1000."""
    rule_counts = [10, 50, 100, 250, 500, 1000]
    results = []
    sources = make_source_addrs(200)
    miss_src = IPv4Address("172.16.99.99:47808")

    for n in rule_counts:
        rules = make_rules(n)
        config = ACLConfig(rules=rules, default_action=RuleAction.DENY)

        # Worst-case (full scan)
        start = time.perf_counter()
        for _ in range(iterations):
            config.find_matching_rule(miss_src, None, "original_broadcast")
        elapsed = time.perf_counter() - start

        results.append({
            "rules": n,
            "iterations": iterations,
            "total_seconds": elapsed,
            "ops_per_sec": iterations / elapsed,
        })

    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_result(result: dict):
    print(f"  {result['name']:30s}  "
          f"{result['ops_per_sec']:>12,.0f} ops/sec  "
          f"({result['total_seconds']:.3f}s / {result['iterations']:,} iterations)")


def print_scaling(results: list[dict]):
    print(f"\n{'Rules':>8s}  {'ops/sec':>14s}  {'us/op':>10s}")
    print(f"{'─'*8}  {'─'*14}  {'─'*10}")
    for r in results:
        us_per_op = 1_000_000 / r["ops_per_sec"]
        print(f"{r['rules']:>8d}  {r['ops_per_sec']:>14,.0f}  {us_per_op:>10.2f}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="ACL engine benchmark")
    parser.add_argument("--rules", type=int, default=100,
                        help="Number of ACL rules (default: 100)")
    parser.add_argument("--iterations", type=int, default=100_000,
                        help="Iterations per benchmark (default: 100000)")
    parser.add_argument("--deny-pct", type=float, default=0.20,
                        help="Fraction of rules that are DENY (default: 0.20)")
    parser.add_argument("--scaling", action="store_true",
                        help="Run scaling benchmark across rule counts")
    args = parser.parse_args()

    print(f"ACL Engine Benchmark")
    print(f"====================")
    print(f"Rules: {args.rules}  |  Deny: {args.deny_pct:.0%}  |  Iterations: {args.iterations:,}\n")

    # Setup
    rules = make_rules(args.rules, deny_pct=args.deny_pct)
    config = ACLConfig(rules=rules, default_action=RuleAction.DENY)
    engine = ACLEngine(config)
    sources = make_source_addrs(200)
    source_strs = make_source_strs(200)
    rust_engine = make_rust_engine(rules)

    deny_count = sum(1 for r in rules if r.action == RuleAction.DENY)
    allow_count = len(rules) - deny_count
    print(f"Generated {len(rules)} rules ({allow_count} allow, {deny_count} deny), "
          f"{len(sources)} source addresses\n")

    # --- Python benchmarks ---
    print("Python engine:")

    r1 = bench_find_matching_rule(config, sources, args.iterations)
    print_result(r1)

    r2 = bench_check_packet(engine, sources, args.iterations)
    print_result(r2)

    r3 = bench_worst_case(config, args.iterations)
    print_result(r3)

    r4 = bench_best_case(config, sources, args.iterations)
    print_result(r4)

    # --- Rust benchmarks ---
    print("\nRust engine:")

    r5 = bench_rust_check(rust_engine, source_strs, args.iterations)
    print_result(r5)

    r5b = bench_rust_check_packet(rust_engine, source_strs, args.iterations)
    print_result(r5b)

    r6 = bench_rust_batch(rust_engine, source_strs, args.iterations)
    print_result(r6)

    r7 = bench_rust_worst_case(rust_engine, args.iterations)
    print_result(r7)

    r8 = bench_rust_best_case(rust_engine, rules, args.iterations)
    print_result(r8)

    # --- Speedup summary ---
    print("\nSpeedup (Rust vs Python):")
    comparisons = [
        ("rule match only", r1, r5),
        ("full pipeline (decode+match)", r2, r5b),
        ("worst case", r3, r7),
        ("best case", r4, r8),
        ("batch vs python random", r1, r6),
    ]
    for label, py_r, rs_r in comparisons:
        speedup = rs_r["ops_per_sec"] / py_r["ops_per_sec"]
        print(f"  {label:35s}  {speedup:>7.1f}x")

    if args.scaling:
        print("\nScaling — Python (worst-case full scan):")
        py_scaling = bench_scaling(args.iterations)
        print_scaling(py_scaling)

        print("\nScaling — Rust (worst-case full scan):")
        rs_scaling = bench_rust_scaling(args.iterations)
        print_scaling(rs_scaling)

        print(f"\n{'Rules':>8s}  {'Speedup':>10s}")
        print(f"{'─'*8}  {'─'*10}")
        for py_r, rs_r in zip(py_scaling, rs_scaling):
            speedup = rs_r["ops_per_sec"] / py_r["ops_per_sec"]
            print(f"{py_r['rules']:>8d}  {speedup:>10.1f}x")

    print()


if __name__ == "__main__":
    main()
