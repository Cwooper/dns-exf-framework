"""End-to-end pipeline behavior."""

from datetime import datetime, timezone, timedelta

from dnsexf.encoders import HexEncoder, AlphabeticBase32Encoder
from dnsexf.injector import AttackInjector
from dnsexf.interfaces import DNSRecord, QueryEncoder, QueryValidator, VictimProfile
from dnsexf.timing import FixedTiming
from dnsexf.victim_selector import RoundRobinSelector


_VICTIMS = (
    VictimProfile(client_ip="10.0.0.1", query_count=50),
    VictimProfile(client_ip="10.0.0.2", query_count=200),
)
_START = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _basic_injector():
    return AttackInjector(
        encoder=HexEncoder(),
        victim_selector=RoundRobinSelector(_VICTIMS, seed=0),
        timing=FixedTiming(base_rate_qph=3600.0),
        parent_domain="exfil.example.com",
    )


def test_stream_emits_one_record_per_chunk():
    inj = _basic_injector()
    payload = b"x" * (HexEncoder().chunk_size() * 5)
    records = list(inj.stream(_START, payload))
    assert len(records) == 5
    assert inj.stats["chunks_consumed"] == 5
    assert inj.stats["emitted"] == 5
    assert inj.stats["dropped_invalid"] == 0


def test_timestamps_monotonic():
    inj = _basic_injector()
    payload = b"x" * 250
    records = list(inj.stream(_START, payload))
    for prev, nxt in zip(records, records[1:]):
        assert prev.timestamp <= nxt.timestamp


def test_fqdn_within_rfc_limits():
    inj = _basic_injector()
    payload = b"x" * 250
    records = list(inj.stream(_START, payload))
    for r in records:
        assert len(r.qname) <= 253
        for label in r.qname.split("."):
            assert len(label) <= 63


def test_invalid_queries_are_dropped():
    class BadEncoder(QueryEncoder):
        def encode_chunk(self, data, seq_id):
            # Underscore is invalid per RFC 1035.
            return "bad_label"

        def chunk_size(self):
            return 8

        def record_type(self):
            return "A"

        def name(self):
            return "bad"

    inj = AttackInjector(
        encoder=BadEncoder(),
        victim_selector=RoundRobinSelector(_VICTIMS, seed=0),
        timing=FixedTiming(base_rate_qph=3600.0),
    )
    payload = b"x" * 32
    records = list(inj.stream(_START, payload))
    assert records == []
    assert inj.stats["dropped_invalid"] == 4
    assert inj.stats["emitted"] == 0
    assert all("invalid_character" in reasons for _, reasons in inj.last_drop_reasons)


def test_merge_with_benign_chronological():
    inj = _basic_injector()
    benign = [
        DNSRecord(
            timestamp=_START + timedelta(seconds=i * 0.5),
            src_ip="10.0.0.99",
            qname="benign.example.com",
            qtype="A",
        )
        for i in range(20)
    ]
    payload = b"x" * 100
    merged = list(inj.merge_with_benign(iter(benign), _START, payload))
    for prev, nxt in zip(merged, merged[1:]):
        assert prev.timestamp <= nxt.timestamp
    assert len(merged) == len(benign) + inj.stats["emitted"]


def test_round_robin_victim_assignment():
    inj = _basic_injector()
    payload = b"x" * (HexEncoder().chunk_size() * 4)
    records = list(inj.stream(_START, payload))
    assigned = [r.src_ip for r in records]
    assert assigned == ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.2"]


def test_two_runs_with_same_seed_produce_same_stream():
    def build():
        return AttackInjector(
            encoder=HexEncoder(),
            victim_selector=RoundRobinSelector(_VICTIMS, seed=11),
            timing=FixedTiming(base_rate_qph=3600.0),
            parent_domain="exfil.example.com",
        )

    payload = b"x" * 300
    a = [(r.timestamp, r.src_ip, r.qname, r.qtype) for r in build().stream(_START, payload)]
    b = [(r.timestamp, r.src_ip, r.qname, r.qtype) for r in build().stream(_START, payload)]
    assert a == b


def test_alpha_encoder_still_produces_valid_fqdns():
    inj = AttackInjector(
        encoder=AlphabeticBase32Encoder(),
        victim_selector=RoundRobinSelector(_VICTIMS, seed=0),
        timing=FixedTiming(base_rate_qph=3600.0),
    )
    payload = b"x" * 80
    records = list(inj.stream(_START, payload))
    v = QueryValidator()
    for r in records:
        assert v.validate(r.qname).valid
