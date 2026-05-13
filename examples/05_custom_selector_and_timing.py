"""How to write a custom ``VictimSelector`` and a custom ``TimingController``.

Both interfaces are small. The selector returns the next source IP; the
timing controller returns the next inter-arrival delay. This example
implements a stealth selector that always picks the least-active host and
a working-hours timing controller that injects only between 09:00 and 17:00
local time.

Run from the repo root::

    uv run python examples/05_custom_selector_and_timing.py
"""

from datetime import datetime, time, timezone
from typing import Any, Mapping, Sequence

from dnsexf.encoders import HexEncoder
from dnsexf.injector import AttackInjector
from dnsexf.interfaces import TimingController, VictimProfile, VictimSelector


class StealthSelector(VictimSelector):
    """Always select the victim with the lowest query count."""

    def __init__(self, victims: Sequence[VictimProfile], seed: int = 0) -> None:
        super().__init__(victims=victims, seed=seed, mode="custom")
        self._counts: dict[str, int] = {v.client_ip: 0 for v in self._victims}

    def select(self, timestamp: datetime | None = None) -> str:
        chosen = min(self._victims, key=lambda v: v.query_count)
        self._counts[chosen.client_ip] += 1
        return chosen.client_ip

    def stats(self) -> Mapping[str, Any]:
        return {"mode": self.mode, "selection_counts": dict(self._counts)}


class WorkingHoursTiming(TimingController):
    """One query every ``base_interval`` seconds, but only 09:00 to 17:00.

    Outside business hours the controller returns a long delay that skips
    forward into the next business window.
    """

    BUSINESS_START = time(9, 0)
    BUSINESS_END = time(17, 0)

    def __init__(self, base_rate_qph: float, seed: int = 0) -> None:
        super().__init__(base_rate_qph=base_rate_qph, seed=seed, mode="custom")
        self._interval = 3600.0 / base_rate_qph

    def next_interval(self, now: datetime) -> float:
        if self.BUSINESS_START <= now.time() < self.BUSINESS_END:
            return self._interval
        if now.time() >= self.BUSINESS_END:
            # past close: skip ahead to tomorrow's open (~16h away).
            return 16 * 3600.0
        # before open: skip ahead to today's open.
        return (self.BUSINESS_START.hour - now.hour) * 3600.0

    def record_injection(self, now: datetime) -> None:
        return None


def main() -> None:
    victims = (
        VictimProfile(client_ip="10.0.0.5", query_count=42),
        VictimProfile(client_ip="10.0.0.6", query_count=11),
        VictimProfile(client_ip="10.0.0.7", query_count=910),
    )
    selector = StealthSelector(victims)
    injector = AttackInjector(
        encoder=HexEncoder(),
        victim_selector=selector,
        timing=WorkingHoursTiming(base_rate_qph=360.0),
    )
    payload = b"working-hours exfiltration demo " * 8
    start = datetime(2025, 1, 1, 8, 30, 0, tzinfo=timezone.utc)
    records = list(injector.stream(start, payload))
    print(f"emitted {len(records)} records starting at {start.isoformat()}")
    for r in records[:5]:
        print(f"  {r.timestamp.isoformat()}  {r.src_ip}  {r.qname}")
    print(f"selector stats: {selector.stats()}")


if __name__ == "__main__":
    main()
