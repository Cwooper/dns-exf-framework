"""RFC 1035 compliance and round-trip decodability."""

from dnsexf.encoders import HexEncoder
from dnsexf.interfaces import QueryEncoder, QueryValidator, ValidationResult


def v_ok(r: ValidationResult) -> bool:
    return r.valid and not r.reasons


def test_empty_fqdn_is_invalid():
    v = QueryValidator()
    assert v.validate("").valid is False


def test_label_at_limit_passes():
    label = "a" * 63
    assert v_ok(QueryValidator().validate(f"{label}.example.com"))


def test_label_over_limit_fails():
    label = "a" * 64
    res = QueryValidator().validate(f"{label}.example.com")
    assert res.valid is False
    assert "label_too_long" in res.reasons


def test_fqdn_over_limit_fails():
    fqdn = ".".join(["a" * 60] * 5 + ["example.com"])
    assert len(fqdn) > 253
    res = QueryValidator().validate(fqdn)
    assert res.valid is False
    assert "fqdn_too_long" in res.reasons


def test_leading_and_trailing_hyphen_rejected():
    res1 = QueryValidator().validate("-bad.example.com")
    assert "leading_hyphen" in res1.reasons

    res2 = QueryValidator().validate("bad-.example.com")
    assert "trailing_hyphen" in res2.reasons


def test_non_alnum_rejected():
    res = QueryValidator().validate("ba_d.example.com")
    assert res.valid is False
    assert "invalid_character" in res.reasons


def test_unicode_rejected():
    res = QueryValidator().validate("héllo.example.com")
    assert res.valid is False
    assert "invalid_character" in res.reasons


def test_trailing_dot_stripped():
    res = QueryValidator().validate("example.com.")
    assert res.valid is True


def test_round_trip_decodable_ok():
    enc = HexEncoder()
    payload = b"hello"
    label = enc.encode_chunk(payload, seq_id=0)
    fqdn = f"{label}.example.com"
    res = QueryValidator().validate_decodable(fqdn, enc, payload)
    assert res.valid is True


def test_round_trip_decode_mismatch():
    enc = HexEncoder()
    payload = b"hello"
    label = enc.encode_chunk(payload, seq_id=0)
    fqdn = f"{label}.example.com"
    res = QueryValidator().validate_decodable(fqdn, enc, b"world")
    assert res.valid is False
    assert "decode_mismatch" in res.reasons


def test_non_invertible_encoder_marked():
    class NoDecode(QueryEncoder):
        def encode_chunk(self, data, seq_id):
            return "abc"

        def chunk_size(self):
            return 8

        def record_type(self):
            return "A"

        def name(self):
            return "nodecode"

    enc = NoDecode()
    res = QueryValidator().validate_decodable("abc.example.com", enc, b"x")
    assert res.valid is False
    assert "encoder_not_invertible" in res.reasons
