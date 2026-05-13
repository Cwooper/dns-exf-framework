"""Attack injector pipeline: orchestrates the four components.

The injector is the framework's user-facing entry point. It wires together
a ``PayloadGenerator``, a ``QueryEncoder``, a ``VictimSelector``, a
``TimingController``, and a ``QueryValidator`` to emit a chronologically
ordered stream of attack ``DNSRecord`` events.

``AttackInjector.stream`` produces attack queries only; ``merge_with_benign``
interleaves them with a benign ``DNSRecord`` stream from a ``DNSRecordLoader``
and yields the merged sequence in non-decreasing timestamp order.

All randomness is contained inside the components the injector composes:
encoder behavior depends on the encoder implementation, victim ordering on
the selector's seed, jitter on the timing controller's seed. The injector
itself is deterministic given those.
"""

from __future__ import annotations

import heapq
from collections import deque
from datetime import datetime, timedelta
from typing import Iterable, Iterator

from dnsexf.interfaces import (
    DNSRecord,
    QueryEncoder,
    QueryValidator,
    TimingController,
    VictimSelector,
)


class AttackInjector:
    """Compose framework components into an attack query stream.

    Parameters:
        encoder:
            ``QueryEncoder`` providing ``encode_chunk`` and chunk size.
        victim_selector:
            ``VictimSelector`` providing source IPs for each attack query.
        timing:
            ``TimingController`` providing inter-arrival delays.
        validator:
            ``QueryValidator``. If omitted, a default validator is used.
            Queries that fail validation are dropped from the output stream
            and counted in ``stats``; the most recent failure reasons are
            available via ``last_drop_reasons``.
        parent_domain:
            The attacker-controlled second-level domain. The encoder's
            label output is joined to this domain with a single dot to form
            the FQDN. No validation is performed on ``parent_domain`` here;
            the surrounding validator pass catches any RFC issues with the
            full FQDN.
    """

    DROP_LOG_MAXLEN: int = 256

    def __init__(
        self,
        encoder: QueryEncoder,
        victim_selector: VictimSelector,
        timing: TimingController,
        *,
        validator: QueryValidator | None = None,
        parent_domain: str = "exfil.example.com",
    ) -> None:
        self._encoder = encoder
        self._victim_selector = victim_selector
        self._timing = timing
        self._validator = validator or QueryValidator()
        self._parent_domain = parent_domain.strip(".")
        self._stats = {
            "emitted": 0,
            "dropped_invalid": 0,
            "chunks_consumed": 0,
        }
        self._last_drop_reasons: deque[tuple[str, tuple[str, ...]]] = deque(
            maxlen=self.DROP_LOG_MAXLEN
        )

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    @property
    def last_drop_reasons(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        """Most recent invalid-query drops, as ``(fqdn, reasons)`` pairs.

        Bounded by ``DROP_LOG_MAXLEN`` so the buffer cannot grow without
        limit on long runs.
        """
        return tuple(self._last_drop_reasons)

    def _build_fqdn(self, label: str) -> str:
        return f"{label}.{self._parent_domain}" if label else self._parent_domain

    def stream(
        self,
        start_time: datetime,
        payload: bytes,
    ) -> Iterator[DNSRecord]:
        """Yield attack ``DNSRecord`` events starting at ``start_time``.

        The payload is chunked according to the encoder's ``chunk_size``;
        each chunk produces one attack query timestamped at the running
        clock advanced by ``timing.next_interval``. Records whose FQDN
        fails ``validator.validate`` are dropped (and counted) instead of
        yielded.
        """
        chunk_size = self._encoder.chunk_size()
        if chunk_size <= 0:
            raise ValueError(
                f"encoder {self._encoder.name()!r} reports non-positive chunk_size"
            )
        record_type = self._encoder.record_type()
        encode = self._encoder.encode_chunk
        validate = self._validator.validate
        next_interval = self._timing.next_interval
        select = self._victim_selector.select
        record_injection = self._timing.record_injection
        stats = self._stats
        clock = start_time

        for seq_id, offset in enumerate(range(0, len(payload), chunk_size)):
            chunk = payload[offset : offset + chunk_size]
            stats["chunks_consumed"] += 1

            delay = max(float(next_interval(clock)), 0.0)
            clock = clock + timedelta(seconds=delay)

            fqdn = self._build_fqdn(encode(chunk, seq_id))
            result = validate(fqdn)
            if not result.valid:
                stats["dropped_invalid"] += 1
                self._last_drop_reasons.append((fqdn, result.reasons))
                continue

            src_ip = select(clock)
            record_injection(clock)
            stats["emitted"] += 1
            yield DNSRecord(
                timestamp=clock,
                src_ip=src_ip,
                qname=fqdn,
                qtype=record_type,
                event_type="query",
            )

    def merge_with_benign(
        self,
        benign: Iterable[DNSRecord],
        start_time: datetime,
        payload: bytes,
    ) -> Iterator[DNSRecord]:
        """Yield benign and attack records interleaved by timestamp.

        ``benign`` must yield records in non-decreasing timestamp order.
        Ties favor the benign record. The merge is a single-pass linear
        interleave via ``heapq.merge``.
        """
        return heapq.merge(
            benign,
            self.stream(start_time, payload),
            key=lambda r: r.timestamp,
        )


__all__ = ("AttackInjector",)
