"""How to write a custom ``QueryEncoder``.

This example defines a toy ``Base36Encoder`` that maps each byte to two
base-36 characters. It exercises the full encoder contract: ``encode_chunk``,
``chunk_size``, ``record_type``, ``name``, and the optional ``decode``.

Run from the repo root::

    uv run python examples/02_custom_encoder.py
"""

from datetime import datetime, timezone

from dnsexf.interfaces import QueryEncoder, QueryValidator, VictimProfile
from dnsexf.injector import AttackInjector
from dnsexf.timing import FixedTiming
from dnsexf.victim_selector import RoundRobinSelector


_ALPHA = "0123456789abcdefghijklmnopqrstuvwxyz"


class Base36Encoder(QueryEncoder):
    """Two base-36 characters per payload byte. Round-trippable."""

    def encode_chunk(self, data: bytes, seq_id: int) -> str:
        out = []
        for b in data:
            hi, lo = divmod(b, 36)
            out.append(_ALPHA[hi])
            out.append(_ALPHA[lo])
        return "".join(out)

    def chunk_size(self) -> int:
        return 24

    def record_type(self) -> str:
        return "A"

    def name(self) -> str:
        return "base36"

    def decode(self, label: str) -> bytes:
        if len(label) % 2 != 0:
            raise ValueError("label length must be even")
        out = bytearray()
        for i in range(0, len(label), 2):
            hi = _ALPHA.index(label[i])
            lo = _ALPHA.index(label[i + 1])
            out.append(hi * 36 + lo)
        return bytes(out)


def main() -> None:
    encoder = Base36Encoder()

    # Round-trip the encoder on a small payload to confirm it inverts.
    raw = b"hello, framework!"
    label = encoder.encode_chunk(raw, seq_id=0)
    recovered = encoder.decode(label)
    print(f"label:     {label}")
    print(f"recovered: {recovered!r}")
    assert recovered == raw

    # Validator confirms RFC 1035 compliance and the decode round-trip.
    validator = QueryValidator()
    fqdn = f"{label}.exfil.example.com"
    result = validator.validate_decodable(fqdn, encoder, raw)
    print(f"validate:  {result}")

    # Plug the encoder into the injector pipeline. Two synthetic victims
    # are enough to demonstrate selection.
    injector = AttackInjector(
        encoder=encoder,
        victim_selector=RoundRobinSelector(
            (
                VictimProfile(client_ip="10.0.0.10", query_count=42),
                VictimProfile(client_ip="10.0.0.11", query_count=87),
            ),
        ),
        timing=FixedTiming(base_rate_qph=1800.0),
    )
    payload = b"DNS exfiltration framework custom encoder demo." * 4
    records = list(
        injector.stream(datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc), payload)
    )
    print(f"emitted:   {len(records)} attack records")
    for r in records[:3]:
        print(f"  {r.qname}")


if __name__ == "__main__":
    main()
