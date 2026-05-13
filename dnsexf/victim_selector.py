"""Reference victim selectors (paper Section 5.4, Component 2).

Three deterministic modes are provided. All three honor the
``VictimSelector`` interface contract: same seed, same victim ordering,
same select-call sequence => same return sequence.

  * ``RoundRobinSelector``: activity-blind; cycles through victims in the
    order they were provided.
  * ``WeightedSelector``: biases selection toward more-active hosts using
    log-scaled query counts.
  * ``AdaptiveSelector``: as weighted, plus an hour-of-day multiplier drawn
    from each profile's ``hourly_activity``.

The paper also mentions a "custom" extension point. The framework treats
``mode`` as an opaque string, so any subclass with its own scoring logic
fills that role. See ``docs/extending.md`` and
``examples/05_custom_selector_and_timing.py`` for a worked example.

The query-count filter described in Section 5.4 (``>=10``, ``<=1000``) is
the caller's responsibility: selectors operate over whatever profile pool
they are given. ``filter_workstation_range`` is provided as a convenience
helper for that pre-step.
"""

from __future__ import annotations

import math
import random
from datetime import datetime
from typing import Any, Iterable, Mapping, Sequence

from dnsexf.interfaces import VictimProfile, VictimSelector


def filter_workstation_range(
    profiles: Iterable[VictimProfile],
    min_queries: int = 10,
    max_queries: int = 1000,
) -> tuple[VictimProfile, ...]:
    """Return profiles whose ``query_count`` falls in [min, max].

    Defaults match Section 5.4. Hosts below ``min_queries`` are too inactive
    to be plausible workstation infection targets; hosts above ``max_queries``
    are typically servers or other infrastructure that fall outside the
    user-level threat model.
    """
    return tuple(
        p for p in profiles if min_queries <= p.query_count <= max_queries
    )


def _log_weights(victims: Sequence[VictimProfile]) -> list[float]:
    # log1p keeps the dynamic range modest and avoids div-by-zero for
    # zero-query hosts. Callers that want to exclude those should use
    # filter_workstation_range first. Weights are returned unnormalized;
    # random.choices normalizes internally.
    return [math.log1p(max(v.query_count, 0)) for v in victims]


class _BaseSelector(VictimSelector):
    """Internal base bundling shared seed and counter bookkeeping."""

    def __init__(
        self,
        victims: Sequence[VictimProfile],
        seed: int,
        mode: str,
    ) -> None:
        if not victims:
            raise ValueError("victim pool must be non-empty")
        super().__init__(victims=victims, seed=seed, mode=mode)
        self._counts: dict[str, int] = {v.client_ip: 0 for v in self._victims}
        self._rng = random.Random(seed)

    def _record(self, ip: str) -> str:
        self._counts[ip] += 1
        return ip

    def stats(self) -> Mapping[str, Any]:
        return {
            "mode": self.mode,
            "total_selections": sum(self._counts.values()),
            "unique_victims_used": sum(1 for c in self._counts.values() if c),
            "selection_counts": dict(self._counts),
        }


class RoundRobinSelector(_BaseSelector):
    """Deterministically cycle through ``victims`` in supplied order."""

    def __init__(self, victims: Sequence[VictimProfile], seed: int = 0) -> None:
        super().__init__(victims=victims, seed=seed, mode="round_robin")
        self._idx = 0

    def select(self, timestamp: datetime | None = None) -> str:
        victim = self._victims[self._idx % len(self._victims)]
        self._idx += 1
        return self._record(victim.client_ip)


class WeightedSelector(_BaseSelector):
    """Weighted-random selection over ``victims``.

    Weights are a log-scaled function of ``query_count``: ``log(1 + n)``.
    Normalization is handled by ``random.choices``.
    """

    def __init__(self, victims: Sequence[VictimProfile], seed: int = 0) -> None:
        super().__init__(victims=victims, seed=seed, mode="weighted")
        self._weights = _log_weights(self._victims)

    def select(self, timestamp: datetime | None = None) -> str:
        victim = self._rng.choices(self._victims, weights=self._weights, k=1)[0]
        return self._record(victim.client_ip)


class AdaptiveSelector(_BaseSelector):
    """Weighted selection with an hour-of-day overlay.

    For each ``select(timestamp)`` call, each victim's base weight is
    multiplied by ``hourly_activity.get(timestamp.hour, 1.0)`` before the
    weighted draw. Victims without ``hourly_activity`` data fall back to
    their base weight unchanged.

    Calling ``select(None)`` is permitted and degrades to ``WeightedSelector``
    behavior.
    """

    def __init__(self, victims: Sequence[VictimProfile], seed: int = 0) -> None:
        super().__init__(victims=victims, seed=seed, mode="adaptive")
        self._base_weights = _log_weights(self._victims)

    def select(self, timestamp: datetime | None = None) -> str:
        if timestamp is None:
            weights = self._base_weights
        else:
            hour = timestamp.hour
            weights = [
                b * v.hourly_activity.get(hour, 1.0)
                for b, v in zip(self._base_weights, self._victims)
            ]
            if sum(weights) <= 0:
                weights = self._base_weights
        victim = self._rng.choices(self._victims, weights=weights, k=1)[0]
        return self._record(victim.client_ip)


__all__ = (
    "filter_workstation_range",
    "RoundRobinSelector",
    "WeightedSelector",
    "AdaptiveSelector",
)
