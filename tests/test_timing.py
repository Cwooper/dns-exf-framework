"""Timing controllers: rate math, jitter bound, determinism."""

import statistics
from datetime import datetime, timezone

import pytest

from dnsexf.timing import AdaptiveTiming, FixedTiming, JitteredTiming


_NOW = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_fixed_returns_exact_interval():
    t = FixedTiming(base_rate_qph=3600.0)
    assert t.next_interval(_NOW) == pytest.approx(1.0)


def test_fixed_is_constant():
    t = FixedTiming(base_rate_qph=720.0)
    intervals = [t.next_interval(_NOW) for _ in range(10)]
    assert all(i == pytest.approx(5.0) for i in intervals)


def test_jittered_within_bounds():
    t = JitteredTiming(base_rate_qph=720.0, seed=1)
    base = 5.0
    intervals = [t.next_interval(_NOW) for _ in range(500)]
    assert all(base * 0.9 <= i <= base * 1.1 for i in intervals)
    # The mean should be near the base interval.
    assert statistics.mean(intervals) == pytest.approx(base, abs=0.05)


def test_jittered_determinism():
    a = JitteredTiming(base_rate_qph=1200.0, seed=7)
    b = JitteredTiming(base_rate_qph=1200.0, seed=7)
    seq_a = [a.next_interval(_NOW) for _ in range(100)]
    seq_b = [b.next_interval(_NOW) for _ in range(100)]
    assert seq_a == seq_b


def test_adaptive_hour_scaling():
    t = AdaptiveTiming(
        base_rate_qph=720.0,
        hourly_rate_multipliers={9: 2.0, 22: 0.5},
        seed=0,
    )
    morning = datetime(2025, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
    night = datetime(2025, 1, 1, 22, 0, 0, tzinfo=timezone.utc)
    # 2x rate => shorter interval; 0.5x rate => longer interval.
    fast = t.next_interval(morning)
    slow = t.next_interval(night)
    assert fast < 5.0 < slow


def test_zero_rate_rejected():
    with pytest.raises(ValueError):
        FixedTiming(base_rate_qph=0.0)
    with pytest.raises(ValueError):
        JitteredTiming(base_rate_qph=0.0)
    with pytest.raises(ValueError):
        AdaptiveTiming(base_rate_qph=0.0)
