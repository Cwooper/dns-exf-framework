"""Reference timing controllers (paper Section 5.5, Component 3).

Three deterministic strategies are provided. All accept a ``base_rate_qph``
(queries per hour, matching the paper's rate notation) and an integer
``seed``; the same inputs reproduce the same interval sequence.

  * ``FixedTiming``: exact ``3600 / base_rate_qph`` between queries.
  * ``JitteredTiming``: as fixed, plus a uniform +/-10% jitter.
  * ``AdaptiveTiming``: interval is scaled by a caller-supplied hour-of-day
    multiplier map. Pure scale; no jitter.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Mapping

from dnsexf.interfaces import TimingController


class _BaseTiming(TimingController):
    """Shared validation and base-interval calculation for the three modes."""

    def __init__(self, base_rate_qph: float, seed: int, mode: str) -> None:
        if base_rate_qph <= 0:
            raise ValueError("base_rate_qph must be positive")
        super().__init__(base_rate_qph=base_rate_qph, seed=seed, mode=mode)
        self._base_interval = 3600.0 / base_rate_qph


class FixedTiming(_BaseTiming):
    """Constant inter-arrival interval."""

    def __init__(self, base_rate_qph: float, seed: int = 0) -> None:
        super().__init__(base_rate_qph=base_rate_qph, seed=seed, mode="fixed")

    def next_interval(self, now: datetime) -> float:
        return self._base_interval

    def record_injection(self, now: datetime) -> None:
        pass


class JitteredTiming(_BaseTiming):
    """Fixed interval with +/-10% uniform jitter.

    The jitter sequence is seeded; replaying the same seed produces the
    same noise pattern.
    """

    JITTER_FRACTION: float = 0.10

    def __init__(self, base_rate_qph: float, seed: int = 0) -> None:
        super().__init__(base_rate_qph=base_rate_qph, seed=seed, mode="jittered")
        self._rng = random.Random(seed)

    def next_interval(self, now: datetime) -> float:
        jitter = self._rng.uniform(-self.JITTER_FRACTION, self.JITTER_FRACTION)
        return max(self._base_interval * (1.0 + jitter), 0.0)

    def record_injection(self, now: datetime) -> None:
        pass


class AdaptiveTiming(_BaseTiming):
    """Hour-of-day scaled interval.

    ``hourly_rate_multipliers`` maps ``hour (0..23) -> multiplier`` where a
    multiplier of 1.0 leaves the base rate unchanged, >1 increases the rate
    (shortens the interval), and <1 decreases the rate (lengthens the
    interval). Hours absent from the map default to multiplier 1.0.

    The multiplier map is the caller's summary of the benign traffic
    distribution. The typical pattern is to derive it from a
    ``DNSRecordLoader`` before constructing the controller: bucket benign
    queries by hour-of-day, normalize against the overall mean, pass the
    resulting dict in. The controller does not consume the benign stream
    directly so that it remains a pure timing strategy with no I/O.
    """

    def __init__(
        self,
        base_rate_qph: float,
        hourly_rate_multipliers: Mapping[int, float] | None = None,
        seed: int = 0,
    ) -> None:
        super().__init__(base_rate_qph=base_rate_qph, seed=seed, mode="adaptive")
        self._multipliers: dict[int, float] = dict(hourly_rate_multipliers or {})

    def next_interval(self, now: datetime) -> float:
        multiplier = self._multipliers.get(now.hour, 1.0)
        if multiplier <= 0:
            multiplier = 1.0
        return self._base_interval / multiplier

    def record_injection(self, now: datetime) -> None:
        pass


__all__ = ("FixedTiming", "JitteredTiming", "AdaptiveTiming")
