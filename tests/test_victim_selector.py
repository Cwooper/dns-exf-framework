"""Victim selector behavior and determinism."""

from datetime import datetime, timezone

import pytest

from dnsexf.interfaces import VictimProfile
from dnsexf.victim_selector import (
    AdaptiveSelector,
    RoundRobinSelector,
    WeightedSelector,
    filter_workstation_range,
)


def _profiles():
    return [
        VictimProfile(client_ip="10.0.0.1", query_count=5),
        VictimProfile(client_ip="10.0.0.2", query_count=50),
        VictimProfile(client_ip="10.0.0.3", query_count=2000),
    ]


def test_filter_workstation_range_defaults():
    keep = filter_workstation_range(_profiles())
    ips = {p.client_ip for p in keep}
    assert ips == {"10.0.0.2"}


def test_filter_workstation_range_widened():
    keep = filter_workstation_range(_profiles(), min_queries=1, max_queries=5000)
    assert len(keep) == 3


def test_round_robin_cycles_in_order():
    sel = RoundRobinSelector(_profiles())
    seq = [sel.select() for _ in range(7)]
    assert seq == [
        "10.0.0.1", "10.0.0.2", "10.0.0.3",
        "10.0.0.1", "10.0.0.2", "10.0.0.3",
        "10.0.0.1",
    ]
    stats = sel.stats()
    assert stats["total_selections"] == 7
    assert stats["unique_victims_used"] == 3


def test_weighted_is_deterministic_for_seed():
    a = WeightedSelector(_profiles(), seed=42)
    b = WeightedSelector(_profiles(), seed=42)
    sa = [a.select() for _ in range(50)]
    sb = [b.select() for _ in range(50)]
    assert sa == sb


def test_weighted_biases_toward_active():
    sel = WeightedSelector(_profiles(), seed=42)
    picks = [sel.select() for _ in range(2000)]
    counts = {ip: picks.count(ip) for ip in {p.client_ip for p in _profiles()}}
    # 10.0.0.3 (count 2000) should outpick 10.0.0.1 (count 5).
    assert counts["10.0.0.3"] > counts["10.0.0.1"]


def test_adaptive_uses_hour_overlay():
    profiles = [
        VictimProfile(
            client_ip="10.0.0.1",
            query_count=100,
            hourly_activity={9: 5.0},
        ),
        VictimProfile(
            client_ip="10.0.0.2",
            query_count=100,
            hourly_activity={9: 0.1},
        ),
    ]
    sel = AdaptiveSelector(profiles, seed=0)
    morning = datetime(2025, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
    picks = [sel.select(morning) for _ in range(2000)]
    a = picks.count("10.0.0.1")
    b = picks.count("10.0.0.2")
    assert a > b * 5  # heavy bias toward the high-multiplier host


def test_empty_pool_rejected():
    with pytest.raises(ValueError):
        RoundRobinSelector([])
