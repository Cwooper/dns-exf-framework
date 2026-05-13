"""Baseline subdomain encoders (paper Section 5.3, Table 2).

Each encoder is a strategy for turning payload bytes into one or more DNS
labels. The encoder is responsible only for the label portion; the injector
prepends the result onto the attacker-controlled parent domain to form the
full FQDN.

The encoders here span the feature space that detectors target: entropy,
character distribution, length, and record type. They give adversarial
generators built on top of the framework a set of baselines to improve
against.
"""

from __future__ import annotations

import base64

from dnsexf.interfaces import QueryEncoder


def _b64_label(data: bytes) -> str:
    """Encode bytes as unpadded base64, DNS-label safe."""
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _b64_unlabel(label: str) -> bytes:
    """Inverse of ``_b64_label``: restore padding, then decode."""
    return base64.b64decode(label + "=" * (-len(label) % 4))


class Base64Encoder(QueryEncoder):
    """High-entropy base64 encoding. One label per chunk."""

    def encode_chunk(self, data: bytes, seq_id: int) -> str:
        return _b64_label(data)

    def chunk_size(self) -> int:
        return 30

    def record_type(self) -> str:
        return "A"

    def name(self) -> str:
        return "base64"

    def decode(self, label: str) -> bytes:
        return _b64_unlabel(label)


class HexEncoder(QueryEncoder):
    """Hex encoding. High numeric ratio, high entropy."""

    def encode_chunk(self, data: bytes, seq_id: int) -> str:
        return data.hex()

    def chunk_size(self) -> int:
        return 25

    def record_type(self) -> str:
        return "A"

    def name(self) -> str:
        return "hex"

    def decode(self, label: str) -> bytes:
        return bytes.fromhex(label)


class AlphabeticBase32Encoder(QueryEncoder):
    """Alphabet-only encoding: each byte becomes two letters in ``a``..``p``.

    Targets the character-distribution and numeric-ratio feature space: the
    output contains no digits. The class name preserves the paper's
    "Base32" label for Table 2 cross-reference, but the underlying scheme
    is letter-coded hex (4 bits per character), which avoids the lossy
    digit-collapsing that a strict case-insensitive 26-letter alphabet
    would force.
    """

    _ALPHABET = "abcdefghijklmnop"

    def encode_chunk(self, data: bytes, seq_id: int) -> str:
        out = []
        for byte in data:
            out.append(self._ALPHABET[byte >> 4])
            out.append(self._ALPHABET[byte & 0x0F])
        return "".join(out)

    def chunk_size(self) -> int:
        return 20

    def record_type(self) -> str:
        return "A"

    def name(self) -> str:
        return "alpha"

    def decode(self, label: str) -> bytes:
        idx = {ch: i for i, ch in enumerate(self._ALPHABET)}
        return bytes(
            (idx[label[i]] << 4) | idx[label[i + 1]]
            for i in range(0, len(label), 2)
        )


class ShortSubdomainEncoder(QueryEncoder):
    """Short subdomain: under 12 characters, below typical length thresholds."""

    _MAX_LEN = 12

    def encode_chunk(self, data: bytes, seq_id: int) -> str:
        return _b64_label(data)[: self._MAX_LEN]

    def chunk_size(self) -> int:
        return 8

    def record_type(self) -> str:
        return "A"

    def name(self) -> str:
        return "short"


class LongSubdomainEncoder(QueryEncoder):
    """Long subdomain: padded to 55+ characters, above length thresholds."""

    _MIN_LEN = 55

    def encode_chunk(self, data: bytes, seq_id: int) -> str:
        encoded = _b64_label(data)
        if len(encoded) < self._MIN_LEN:
            encoded = encoded.ljust(self._MIN_LEN, "a")
        return encoded

    def chunk_size(self) -> int:
        return 35

    def record_type(self) -> str:
        return "A"

    def name(self) -> str:
        return "long"


class TXTRecordEncoder(QueryEncoder):
    """TXT-record-targeted encoder. Higher per-query capacity."""

    def encode_chunk(self, data: bytes, seq_id: int) -> str:
        return _b64_label(data)

    def chunk_size(self) -> int:
        return 40

    def record_type(self) -> str:
        return "TXT"

    def name(self) -> str:
        return "txt"

    def decode(self, label: str) -> bytes:
        return _b64_unlabel(label)


def all_baseline_encoders() -> tuple[QueryEncoder, ...]:
    """Return one instance of each Table-2 baseline encoder."""
    return (
        Base64Encoder(),
        HexEncoder(),
        AlphabeticBase32Encoder(),
        ShortSubdomainEncoder(),
        LongSubdomainEncoder(),
        TXTRecordEncoder(),
    )


__all__ = (
    "Base64Encoder",
    "HexEncoder",
    "AlphabeticBase32Encoder",
    "ShortSubdomainEncoder",
    "LongSubdomainEncoder",
    "TXTRecordEncoder",
    "all_baseline_encoders",
)
