"""How to write a custom ``DNSRecordLoader``.

The loader interface is a ``Protocol``: any object with ``records()`` and
``dns_queries()`` methods that yield ``DNSRecord`` instances satisfies it.
This example wraps a hard-coded in-memory list to keep the example
self-contained, but the same shape works for PCAP readers, vendor JSON
dumps, or any other source.

Run from the repo root::

    uv run python examples/03_custom_loader.py
"""

from datetime import datetime, timezone, timedelta
from typing import Iterator

from dnsexf.interfaces import DNSRecord


class InMemoryLoader:
    """Trivial loader that wraps a pre-built list of ``DNSRecord`` objects."""

    def __init__(self, records: list[DNSRecord]) -> None:
        self._records = list(records)

    def records(self) -> Iterator[DNSRecord]:
        return iter(self._records)

    def dns_queries(self) -> Iterator[DNSRecord]:
        return (r for r in self._records if r.event_type == "query")


def main() -> None:
    base = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    samples = [
        DNSRecord(
            timestamp=base + timedelta(seconds=i * 5),
            src_ip=f"10.0.0.{i % 4 + 2}",
            qname=name,
            qtype=qtype,
        )
        for i, (name, qtype) in enumerate(
            [
                ("cdn.example.com", "A"),
                ("api.example.com", "AAAA"),
                ("static.example.com", "A"),
                ("mail.example.com", "MX"),
                ("auth.example.com", "A"),
            ]
        )
    ]
    loader = InMemoryLoader(samples)

    print(f"records:     {sum(1 for _ in loader.records())}")
    print(f"queries:     {sum(1 for _ in loader.dns_queries())}")
    print()
    for r in loader.records():
        print(f"  {r.timestamp.isoformat()}  {r.src_ip:>10}  {r.qtype:>4}  {r.qname}")


if __name__ == "__main__":
    main()
