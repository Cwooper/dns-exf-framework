"""Public interface specification for the DNS exfiltration research framework.

This module defines the abstract types that constitute the framework's public
surface. The framework is organized around the four components described in
Section 5 of the paper, plus a format-agnostic data loader and an external
detector adapter:

    Component 1, PayloadGenerator: produces raw exfiltration payloads.
    Component 2, VictimSelector: chooses source IPs from benign traffic to
        act as compromised hosts.
    Component 3, TimingController: decides when each attack query fires.
    Component 4, QueryValidator: enforces RFC 1035 compliance and,
        optionally, round-trip decodability.

    Supporting types:

      QueryEncoder: pluggable subdomain encoding strategy used by the
        generator-to-injector path.
      DNSRecordLoader: yields normalized DNSRecord events from an arbitrary
        upstream source.
      Detector: thin adapter over an external NIDS used for defense
        evaluation.

Design principles (paper Section 5.1):

  * Semantic validity by construction. The QueryValidator is a defensive
    backstop; encoders are expected to emit RFC-valid labels in the first
    place.
  * Temporal realism. The TimingController operates in real timestamps drawn
    from the benign stream provided by a DNSRecordLoader.
  * Reproducibility. Every component that randomizes accepts an integer
    ``seed`` and, given the same seed and inputs, produces the same outputs.
  * Extensibility. All four components are abstract and intended to be
    subclassed; the framework's core injection pipeline depends only on the
    method signatures defined here.

The interface vocabulary is small. A DNS event is described by
``timestamp``, ``src_ip``, ``qname``, ``qtype``, and ``event_type``; everything
else is opaque adapter-private state living in ``DNSRecord.raw``. This is a
hard rule: framework components must not read ``raw``. Adapter authors may
thread additional context through ``raw`` for their own use (e.g. to round-trip
a record back into their upstream format), but no framework method will inspect
it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import (
    Any,
    Iterable,
    Iterator,
    Mapping,
    Protocol,
    Sequence,
    runtime_checkable,
)


# ---------------------------------------------------------------------------
# Core record type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DNSRecord:
    """A single normalized DNS event.

    This is the *only* shape in which DNS traffic crosses the framework
    boundary. Loaders convert their native format into ``DNSRecord`` instances;
    every other component (selector, injector, validator, detector) consumes
    them.

    Fields:
        timestamp:  Wall-clock time of the event. Loaders must populate this
                    with a timezone-aware ``datetime`` when the source provides
                    one; mixing naive and aware datetimes within a single
                    stream is undefined behavior.
        src_ip:     Client IP that issued the query (or that the response was
                    sent to). Stringly typed: IPv4 dotted-quad or IPv6 hex.
        qname:      The queried name (FQDN), lowercased by convention. Loaders
                    are responsible for stripping any trailing dot.
        qtype:      The DNS RR type as a string mnemonic, e.g. "A", "AAAA",
                    "TXT", "CNAME". Numeric types should be resolved to their
                    mnemonic where possible.
        event_type: Either "query" or "response". Defaults to "query".
        raw:        An opaque mapping reserved for adapter authors. Framework
                    components MUST NOT read from this field. It exists solely
                    so that loader implementations can carry private context
                    (e.g. a flow ID, a source line number) that they may need
                    when emitting derived outputs back into their own format.

    A third party should rarely instantiate ``DNSRecord`` directly outside of
    a custom loader; the typical consumption pattern is to receive them from
    a ``DNSRecordLoader.records()`` iterator.
    """

    timestamp: datetime
    src_ip: str
    qname: str
    qtype: str
    event_type: str = "query"
    raw: Mapping[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


@runtime_checkable
class DNSRecordLoader(Protocol):
    """Format-agnostic source of DNS events.

    A loader is anything that can yield ``DNSRecord`` instances in
    chronological order. The framework does not specify a file format,
    schema, on-disk layout, or transport: adapters bridge whatever upstream
    representation is available (PCAP, packet logger JSON lines, flow-record
    exports, live capture) into the ``DNSRecord`` shape.

    Implementations are responsible for:
      * Producing records in non-decreasing ``timestamp`` order. Downstream
        components (most notably ``TimingController`` and time-aware victim
        selection) assume chronological iteration.
      * Normalizing ``qname`` (typically lowercase, trailing-dot stripped) and
        ``qtype`` (string mnemonic) so consumers do not need to special-case
        per-source quirks.
      * Setting ``event_type`` correctly so that ``dns_queries()`` can filter
        without re-parsing.

    A loader is a ``Protocol`` rather than an ABC so that researchers can
    adapt an existing iterator-yielding object (e.g. a generator function or a
    third-party reader) without inheriting from a framework base class. A
    minimal example::

        class MyJSONLLoader:
            def __init__(self, path):
                self.path = path

            def records(self):
                for line in open(self.path):
                    obj = json.loads(line)
                    yield DNSRecord(
                        timestamp=datetime.fromisoformat(obj["ts"]),
                        src_ip=obj["client"],
                        qname=obj["name"].lower().rstrip("."),
                        qtype=obj["type"],
                        event_type="query" if obj["is_query"] else "response",
                    )

            def dns_queries(self):
                return (r for r in self.records() if r.event_type == "query")
    """

    def records(self) -> Iterator[DNSRecord]:
        """Yield every DNS event in the source, in chronological order."""
        ...

    def dns_queries(self) -> Iterator[DNSRecord]:
        """Yield only ``event_type == "query"`` records."""
        ...


# ---------------------------------------------------------------------------
# Component 1: payload generation and encoding
# ---------------------------------------------------------------------------


class PayloadGenerator(ABC):
    """Component 1: produces realistic exfiltration payloads.

    A ``PayloadGenerator`` is responsible for the *content* being exfiltrated,
    not the wire form. It returns raw ``bytes`` of a requested size and
    payload class; a separate ``QueryEncoder`` then turns those bytes into
    DNS subdomain labels.

    The four payload classes ("credit_card", "log", "image", "text")
    correspond to the common APT objectives enumerated in Section 5.3. They
    span structured (credit_card, log) and unstructured (image, text) data
    so that detectors are exercised across the entropy spectrum.

    Compression is a constructor flag. When ``compress=True``, the generator
    applies a zlib pass to its output before returning. This is exposed
    explicitly because compression flattens entropy differences across
    payload classes, which is itself a useful experimental knob.

    Researchers extend this class to add new payload types::

        class DocumentExfilGenerator(PayloadGenerator):
            def __init__(self, corpus, compress=False):
                super().__init__(compress=compress)
                self._corpus = corpus

            def generate(self, size_bytes, payload_type):
                if payload_type == "document":
                    raw = self._corpus.sample(size_bytes)
                    return self._maybe_compress(raw)
                return super().generate(size_bytes, payload_type)
    """

    #: Canonical payload class strings recognised by the reference generator.
    SUPPORTED_TYPES: tuple[str, ...] = ("credit_card", "log", "image", "text")

    def __init__(self, compress: bool = False) -> None:
        self.compress = compress

    @abstractmethod
    def generate(self, size_bytes: int, payload_type: str) -> bytes:
        """Return ``size_bytes`` of payload data of class ``payload_type``.

        ``size_bytes`` is the *post-compression* target when ``compress`` is
        True; implementations may overshoot slightly for payload classes
        whose underlying generator is not byte-addressable (e.g. images).
        ``payload_type`` should be one of ``SUPPORTED_TYPES`` or an extension
        string recognised by the subclass.
        """


class QueryEncoder(ABC):
    """Encoding strategy used to turn payload bytes into DNS subdomain labels.

    The encoder is the pluggable strategy that distinguishes one DNS-exfil
    technique from another. The paper's Table 2 baselines (Base64, Hex,
    Alphabetic Base32, short subdomain, long subdomain, TXT record) are each
    implementable as a separate ``QueryEncoder``; adversarial techniques
    (e.g. learned encoders, codebook-driven encoders) plug in here as well.

    Composition: the generator produces payload bytes; the encoder chunks
    those bytes and returns one subdomain label per call; the injector prefixes
    the label onto a controlled second-level domain, then hands the resulting
    FQDN to the validator. A third-party encoder only needs to honor
    ``chunk_size()`` for the chunking caller and to emit labels that pass
    ``QueryValidator`` checks.

    ``decode`` is optional and present only on invertible encoders. The
    validator's round-trip decodability check uses it; if absent, callers
    fall back to syntactic-only validation.

    Example: a minimal hex encoder::

        class HexEncoder(QueryEncoder):
            def chunk_size(self):  return 25
            def record_type(self): return "A"
            def name(self):        return "hex"
            def encode_chunk(self, data, seq_id):
                return data.hex()
            def decode(self, label):
                return bytes.fromhex(label)
    """

    @abstractmethod
    def encode_chunk(self, data: bytes, seq_id: int) -> str:
        """Encode one chunk into a subdomain label payload.

        Returns only the label portion (one or more dot-separated DNS labels
        that will become the leftmost components of the FQDN); the injector
        is responsible for joining with the controlled parent domain.
        ``seq_id`` is a monotonically increasing per-flow counter that
        stateful encoders may use to disambiguate chunks.
        """

    @abstractmethod
    def chunk_size(self) -> int:
        """Return the number of payload bytes consumed per ``encode_chunk``."""

    @abstractmethod
    def record_type(self) -> str:
        """Return the DNS RR type string this encoder targets, e.g. ``"A"``."""

    @abstractmethod
    def name(self) -> str:
        """Return a short stable identifier for logging and result tables."""

    def decode(self, label: str) -> bytes:
        """Inverse of ``encode_chunk`` for invertible encoders.

        The default implementation raises ``NotImplementedError``. Override on
        encoders that are round-trippable; the ``QueryValidator``'s
        decodability check will then exercise this method.
        """
        raise NotImplementedError(
            f"encoder {self.name()!r} does not implement decode()"
        )


# ---------------------------------------------------------------------------
# Component 2: victim selection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VictimProfile:
    """A candidate source IP that the selector may pick as a compromised host.

    Profiles are produced upstream of the framework: typically by scanning a
    benign DNS trace and tallying per-client behavior: then passed to a
    ``VictimSelector`` constructor.

    Fields:
        client_ip:        Source IP. Stringly typed; matches ``DNSRecord.src_ip``.
        query_count:      Total benign queries observed from this client.
                          Used by the >=10 / <=1000 filter described in
                          Section 5.4.
        hourly_activity:  Optional mapping ``hour-of-day (0..23) -> rate``.
                          Populated when known; consumed by adaptive mode.
        extra:            Opaque passthrough. As with ``DNSRecord.raw``, the
                          framework does not inspect this; custom scoring
                          functions may.
    """

    client_ip: str
    query_count: int
    hourly_activity: Mapping[int, float] = field(default_factory=dict)
    extra: Mapping[str, Any] = field(default_factory=dict)


class VictimSelector(ABC):
    """Component 2: chooses which benign client to impersonate next.

    The selector receives a fixed pool of ``VictimProfile`` candidates at
    construction time and, on each ``select()`` call, returns the IP of the
    profile that should source the next attack query.

    Three reference modes ship with the framework: ``"round_robin"``,
    ``"weighted"``, and ``"adaptive"``. Paper Section 5.4 also calls out
    ``"custom"`` as an extension point; implementations are free to set
    any string they like for ``mode`` and the framework will treat it as
    opaque.

    Reproducibility: given the same ``seed``, the same ``victims`` list (in
    the same order), and the same sequence of ``select`` calls, an
    implementation must return the same sequence of IPs. ``adaptive`` mode is
    further conditioned on the ``timestamp`` argument.

    The ``stats()`` method exposes selection counts (and any other audit
    counters the implementation wishes to expose) for reporting and for
    paper-style fairness checks.

    Example: a custom mode that prefers low-volume hosts::

        class StealthSelector(VictimSelector):
            def __init__(self, victims, seed):
                super().__init__(victims=victims, seed=seed, mode="custom")
                self._counts = {v.client_ip: 0 for v in victims}

            def select(self, timestamp=None):
                v = min(self._victims, key=lambda v: v.query_count)
                self._counts[v.client_ip] += 1
                return v.client_ip

            def stats(self):
                return {"selections": dict(self._counts)}
    """

    def __init__(
        self,
        victims: Sequence[VictimProfile],
        seed: int,
        mode: str,
    ) -> None:
        self._victims = tuple(victims)
        self._seed = seed
        self._mode = mode

    @property
    def mode(self) -> str:
        """The selection mode this selector was configured for."""
        return self._mode

    @abstractmethod
    def select(self, timestamp: datetime | None = None) -> str:
        """Return the client IP of the next victim.

        ``timestamp`` is required for ``adaptive`` mode (so that hour-of-day
        weighting can apply) and ignored by deterministic modes. Callers
        SHOULD pass it whenever it is known; the contract for adaptive mode
        when ``timestamp is None`` is implementation-defined.
        """

    @abstractmethod
    def stats(self) -> Mapping[str, Any]:
        """Return a snapshot of selection-count audit data."""


# ---------------------------------------------------------------------------
# Component 3: timing
# ---------------------------------------------------------------------------


class TimingController(ABC):
    """Component 3: controls when each injected query fires.

    The timing controller is queried by the injector before each attack
    query. It does not produce timestamps directly; it produces *inter-arrival
    delays*, expressed as a number of seconds until the next query, given the
    current notional clock. This indirection lets the injector compose timing
    with whatever benign-stream replay strategy it uses without the
    controller needing to know about the benign data.

    The three reference modes from Section 5.5:

      * ``"fixed"``: ``next_interval`` returns ``3600 / base_rate_qph``.
      * ``"jittered"``: as ``"fixed"``, plus a +/-10% uniform jitter.
      * ``"adaptive"``: the returned interval shrinks during high-traffic
                          hours and grows during low-traffic hours, scaled
                          off ``base_rate_qph``.

    Reproducibility: given the same ``seed`` and the same sequence of
    ``record_injection`` calls (which feed the controller's internal clock /
    history), the sequence of ``next_interval`` return values must be
    deterministic.

    Researchers add new timing strategies by subclassing::

        class BurstyTiming(TimingController):
            def __init__(self, base_rate_qph, seed, burst_size=8):
                super().__init__(base_rate_qph=base_rate_qph,
                                 seed=seed, mode="custom")
                self._burst = burst_size
                self._in_burst = 0

            def next_interval(self, now):
                if self._in_burst:
                    self._in_burst -= 1
                    return 0.05
                self._in_burst = self._burst
                return 600.0

            def record_injection(self, now):
                pass
    """

    def __init__(
        self,
        base_rate_qph: float,
        seed: int,
        mode: str,
    ) -> None:
        self._base_rate_qph = base_rate_qph
        self._seed = seed
        self._mode = mode

    @property
    def base_rate_qph(self) -> float:
        """Configured baseline rate in queries per hour."""
        return self._base_rate_qph

    @property
    def mode(self) -> str:
        """The timing mode this controller was configured for."""
        return self._mode

    @abstractmethod
    def next_interval(self, now: datetime) -> float:
        """Return the delay, in seconds, until the next attack query.

        Must always return a non-negative float. ``now`` is the current
        notional clock as the injector understands it; the controller may
        use it (e.g. for hour-of-day scaling) or ignore it.
        """

    @abstractmethod
    def record_injection(self, now: datetime) -> None:
        """Notify the controller that an attack query was just injected.

        Stateful controllers (history-aware, rate-limited, adaptive) update
        their internal state here. Stateless controllers may treat this as a
        no-op.
        """


# ---------------------------------------------------------------------------
# Component 4: validation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of a ``QueryValidator`` check.

    ``valid`` is the boolean verdict. ``reasons`` enumerates every rule the
    candidate failed, as short stable strings (e.g. ``"label_too_long"``,
    ``"leading_hyphen"``, ``"fqdn_too_long"``, ``"invalid_character"``,
    ``"decode_mismatch"``). For valid inputs ``reasons`` is empty.

    Tuple typing keeps results hashable and trivially pickleable for
    storage in result tables.
    """

    valid: bool
    reasons: tuple[str, ...] = ()


class QueryValidator:
    """Component 4: RFC 1035 backstop plus optional decodability check.

    Unlike the other three components this class is concrete, not abstract.
    The rules it enforces are fixed by the DNS specification:

      * Total FQDN length <= 253 octets.
      * Each label <= 63 octets.
      * Labels consist of ASCII alphanumerics and hyphen only.
      * No leading or trailing hyphen on any label.

    Subclassing is allowed for researchers who want to bolt on additional
    constraints (e.g. require a particular suffix, reject internationalized
    domain names), but the default ``validate`` is sufficient for the
    framework's reference pipeline.

    The optional ``validate_decodable`` round-trips a candidate FQDN through
    a ``QueryEncoder.decode`` and checks that the decoded bytes equal the
    original payload. This is the "round-trip via the encoder" check
    referenced in Section 5.6 and is the primary tool researchers should use
    when developing a new lossy or stateful encoder.
    """

    MAX_FQDN_LEN: int = 253
    MAX_LABEL_LEN: int = 63

    def validate(self, fqdn: str) -> ValidationResult:
        """Apply RFC 1035 syntactic checks to ``fqdn``."""
        reasons: list[str] = []
        if not fqdn:
            return ValidationResult(False, ("empty",))
        trimmed = fqdn.rstrip(".")
        if len(trimmed) > self.MAX_FQDN_LEN:
            reasons.append("fqdn_too_long")
        for label in trimmed.split("."):
            if not label:
                reasons.append("empty_label")
                continue
            if len(label) > self.MAX_LABEL_LEN:
                reasons.append("label_too_long")
            if label.startswith("-"):
                reasons.append("leading_hyphen")
            if label.endswith("-"):
                reasons.append("trailing_hyphen")
            for ch in label:
                if not (ch.isascii() and (ch.isalnum() or ch == "-")):
                    reasons.append("invalid_character")
                    break
        return ValidationResult(not reasons, tuple(reasons))

    def validate_decodable(
        self,
        fqdn: str,
        encoder: QueryEncoder,
        original: bytes,
    ) -> ValidationResult:
        """Validate ``fqdn`` syntactically, then verify it round-trips.

        Calls ``validate`` first; if that fails, those reasons are returned
        unchanged. Otherwise the leftmost label is decoded via
        ``encoder.decode`` and compared to ``original``. Possible failure
        codes:

          * ``"encoder_not_invertible"`` if ``encoder.decode`` raises
            ``NotImplementedError``.
          * ``"decode_error"`` if ``encoder.decode`` raises any other
            exception.
          * ``"decode_mismatch"`` if the decoded bytes differ from
            ``original``.
        """
        syntactic = self.validate(fqdn)
        if not syntactic.valid:
            return syntactic
        label = fqdn.split(".", 1)[0]
        try:
            decoded = encoder.decode(label)
        except NotImplementedError:
            return ValidationResult(False, ("encoder_not_invertible",))
        except Exception:
            return ValidationResult(False, ("decode_error",))
        if decoded != original:
            return ValidationResult(False, ("decode_mismatch",))
        return ValidationResult(True, ())


# ---------------------------------------------------------------------------
# Detector adapter
# ---------------------------------------------------------------------------


class Detector(ABC):
    """Thin adapter over an external network intrusion detection system.

    The detector interface is the integration point for defense evaluation.
    It is minimal: a detector can be fit on benign queries (a no-op for
    rule-based systems), scores a candidate FQDN, and produces a binary
    predict.

    Why FQDN-only and not full ``DNSRecord``: detectors in the literature
    vary in whether they consume timing, batch, or stateful context. The
    minimum common contract is "given a name, judge it." Detectors that need
    more context can accept it via their constructor or via the upstream
    pipeline (e.g. by being fit on a windowed history) and still expose this
    interface.

    Example: wrapping a hypothetical third-party detector::

        class ThirdPartyAdapter(Detector):
            def __init__(self, model):
                self._model = model

            def fit(self, benign_queries):
                self._model.fit(list(benign_queries))

            def score(self, fqdn):
                return float(self._model.proba(fqdn))

            def predict(self, fqdn):
                return self.score(fqdn) >= 0.5

            def name(self):
                return "thirdparty-v1"
    """

    @abstractmethod
    def fit(self, benign_queries: Iterable[str]) -> None:
        """Train or calibrate on a stream of benign FQDNs.

        Implementations that do not need fitting (rule-based, signature-based,
        or pre-trained detectors) should make this a no-op.
        """

    @abstractmethod
    def score(self, fqdn: str) -> float:
        """Return a real-valued maliciousness score for ``fqdn``.

        Higher values indicate higher confidence that ``fqdn`` is exfiltration.
        Scales are not normalized across detectors; cross-detector comparison
        should go through ``predict`` or per-detector threshold sweeps.
        """

    @abstractmethod
    def predict(self, fqdn: str) -> bool:
        """Return the detector's binary verdict for ``fqdn``.

        ``True`` means "flag as exfiltration."
        """

    @abstractmethod
    def name(self) -> str:
        """Return a short stable identifier for the detector."""


__all__ = (
    "DNSRecord",
    "DNSRecordLoader",
    "PayloadGenerator",
    "QueryEncoder",
    "VictimProfile",
    "VictimSelector",
    "TimingController",
    "ValidationResult",
    "QueryValidator",
    "Detector",
)
