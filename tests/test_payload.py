"""Payload generator: type coverage, determinism, compression effect."""

import pytest

from dnsexf.payload import DefaultPayloadGenerator


@pytest.mark.parametrize("ptype", ["credit_card", "log", "image", "text"])
def test_each_type_produces_bytes(ptype):
    gen = DefaultPayloadGenerator(seed=0, compress=False)
    out = gen.generate(size_bytes=512, payload_type=ptype)
    assert isinstance(out, bytes)
    assert len(out) > 0


def test_uncompressed_respects_size_cap():
    gen = DefaultPayloadGenerator(seed=0, compress=False)
    out = gen.generate(size_bytes=300, payload_type="log")
    assert len(out) == 300


def test_compression_changes_output():
    raw_gen = DefaultPayloadGenerator(seed=0, compress=False)
    z_gen = DefaultPayloadGenerator(seed=0, compress=True)
    raw = raw_gen.generate(size_bytes=4096, payload_type="text")
    z = z_gen.generate(size_bytes=4096, payload_type="text")
    assert raw != z
    # text repeats vocab so compression should shrink it
    assert len(z) < len(raw)


def test_determinism_same_seed():
    a = DefaultPayloadGenerator(seed=123, compress=False).generate(500, "credit_card")
    b = DefaultPayloadGenerator(seed=123, compress=False).generate(500, "credit_card")
    assert a == b


def test_independence_across_types():
    gen = DefaultPayloadGenerator(seed=7, compress=False)
    a = gen.generate(200, "log")
    b = gen.generate(200, "text")
    assert a != b


def test_unknown_type_rejected():
    gen = DefaultPayloadGenerator(seed=0)
    with pytest.raises(ValueError):
        gen.generate(100, "unknown")


def test_negative_size_rejected():
    gen = DefaultPayloadGenerator(seed=0)
    with pytest.raises(ValueError):
        gen.generate(-1, "text")
