"""Quickstart: a minimal end-to-end exfiltration run with no external dataset.

This script wires every framework component once with reasonable defaults
and prints the first few attack queries. It uses the bundled
``fixtures/benign_sample.jsonl`` as the benign stream so it runs anywhere
the package is installed.

Run from the repo root::

    uv run python examples/01_quickstart.py
"""

from collections import Counter

from dnsexf.encoders import HexEncoder
from dnsexf.injector import AttackInjector
from dnsexf.interfaces import VictimProfile
from dnsexf.loaders import JSONLLoader
from dnsexf.payload import DefaultPayloadGenerator
from dnsexf.timing import JitteredTiming
from dnsexf.victim_selector import RoundRobinSelector, filter_workstation_range


def main() -> None:
    benign = list(JSONLLoader("fixtures/benign_sample.jsonl").dns_queries())
    if not benign:
        raise SystemExit("benign fixture is empty: run from the repo root")

    profiles = filter_workstation_range(
        [
            VictimProfile(client_ip=ip, query_count=n)
            for ip, n in Counter(r.src_ip for r in benign).items()
        ],
        min_queries=1,
    )

    payload = DefaultPayloadGenerator(seed=42, compress=True).generate(
        size_bytes=200, payload_type="credit_card"
    )

    injector = AttackInjector(
        encoder=HexEncoder(),
        victim_selector=RoundRobinSelector(profiles, seed=1),
        timing=JitteredTiming(base_rate_qph=720.0, seed=1),
        parent_domain="exfil.example.com",
    )

    merged = list(
        injector.merge_with_benign(iter(benign), benign[0].timestamp, payload)
    )
    attacks = [r for r in merged if "exfil.example.com" in r.qname]

    print(f"benign records:   {len(benign)}")
    print(f"attack records:   {len(attacks)}")
    print(f"merged total:     {len(merged)}")
    print(f"injector stats:   {injector.stats}")
    print()
    print("first 3 attack queries:")
    for r in attacks[:3]:
        print(f"  {r.timestamp.isoformat()}  {r.src_ip:>15}  {r.qtype}  {r.qname}")


if __name__ == "__main__":
    main()
