"""Baseline encoder behavior and round-trip checks."""

import pytest

from dnsexf.encoders import (
    AlphabeticBase32Encoder,
    Base64Encoder,
    HexEncoder,
    LongSubdomainEncoder,
    ShortSubdomainEncoder,
    TXTRecordEncoder,
    all_baseline_encoders,
)


@pytest.mark.parametrize(
    "encoder_cls,expected_chunk_size,expected_record_type",
    [
        (Base64Encoder, 30, "A"),
        (HexEncoder, 25, "A"),
        (AlphabeticBase32Encoder, 20, "A"),
        (ShortSubdomainEncoder, 8, "A"),
        (LongSubdomainEncoder, 35, "A"),
        (TXTRecordEncoder, 40, "TXT"),
    ],
)
def test_encoder_metadata(encoder_cls, expected_chunk_size, expected_record_type):
    enc = encoder_cls()
    assert enc.chunk_size() == expected_chunk_size
    assert enc.record_type() == expected_record_type
    assert isinstance(enc.name(), str) and enc.name()


def test_all_baseline_encoders_count():
    encs = all_baseline_encoders()
    names = {e.name() for e in encs}
    assert len(encs) == 6 == len(names)


def test_base64_round_trip():
    enc = Base64Encoder()
    payload = b"\x00\x01\x02hello\xff"
    label = enc.encode_chunk(payload, seq_id=0)
    assert enc.decode(label) == payload


def test_hex_round_trip():
    enc = HexEncoder()
    payload = bytes(range(20))
    label = enc.encode_chunk(payload, seq_id=0)
    assert enc.decode(label) == payload


def test_txt_round_trip():
    enc = TXTRecordEncoder()
    payload = b"longer-text-payload-of-arbitrary-bytes" + bytes(range(10))
    label = enc.encode_chunk(payload, seq_id=0)
    assert enc.decode(label) == payload


def test_short_under_threshold():
    enc = ShortSubdomainEncoder()
    label = enc.encode_chunk(b"x" * enc.chunk_size(), seq_id=0)
    assert len(label) <= 12


def test_long_over_threshold():
    enc = LongSubdomainEncoder()
    label = enc.encode_chunk(b"x" * enc.chunk_size(), seq_id=0)
    assert len(label) >= 55


def test_alpha_is_alphabetic_only():
    enc = AlphabeticBase32Encoder()
    label = enc.encode_chunk(b"\x00\x01\x02\x03\x04", seq_id=0)
    assert label.isalpha()


def test_alpha_round_trip():
    enc = AlphabeticBase32Encoder()
    payload = bytes(range(20))
    label = enc.encode_chunk(payload, seq_id=0)
    assert label.isalpha()
    assert enc.decode(label) == payload
