"""Reference payload generator (paper Section 5.3, Component 1).

Produces raw bytes for the four payload classes named in the paper:

  * ``"credit_card"``: newline-separated synthetic PAN records.
  * ``"log"``: synthetic Apache-style access log lines.
  * ``"image"``: pseudo-random bytes with a plausible header. The output
    is not a real image; it exists so detectors are exercised against
    high-entropy unstructured data.
  * ``"text"``: pseudo-English filler text drawn from a built-in vocabulary.

All four are deterministic given a constructor seed. ``compress=True``
applies a single zlib pass at default level; the post-compression byte
count is what's compared against the ``size_bytes`` argument.

The synthetic credit card numbers do not validate against the Luhn check
and are obviously not real: they are placeholder data for evaluating
detector behavior on structured payloads, nothing more.
"""

from __future__ import annotations

import random
import zlib

from dnsexf.interfaces import PayloadGenerator


_LOG_TEMPLATE = (
    "{ip} - - [{ts}] \"GET {path} HTTP/1.1\" {status} {size} "
    "\"-\" \"Mozilla/5.0\"\n"
)

_LOG_PATHS = (
    "/", "/index.html", "/login", "/api/v1/users", "/api/v1/orders",
    "/static/app.js", "/static/style.css", "/images/logo.png",
    "/favicon.ico", "/robots.txt",
)

_TEXT_VOCAB = (
    "the", "and", "of", "to", "in", "is", "for", "on", "with", "as",
    "by", "at", "from", "this", "that", "an", "be", "or", "are", "was",
    "data", "system", "network", "request", "response", "service",
    "client", "server", "session", "record", "event", "message",
    "status", "code", "value", "field", "user", "id", "name", "type",
)


def _synth_pan(rng: random.Random) -> str:
    """Generate a placeholder PAN-shaped 16-digit string."""
    return "".join(rng.choices("0123456789", k=16))


def _synth_log_line(rng: random.Random) -> str:
    return _LOG_TEMPLATE.format(
        ip=f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}",
        ts=(
            f"{rng.randint(1,28):02d}/Jan/2025:"
            f"{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}"
            " +0000"
        ),
        path=rng.choice(_LOG_PATHS),
        status=rng.choice((200, 200, 200, 304, 404, 500)),
        size=rng.randint(120, 9000),
    )


def _synth_text(rng: random.Random, words: int) -> str:
    return " ".join(rng.choice(_TEXT_VOCAB) for _ in range(words))


class DefaultPayloadGenerator(PayloadGenerator):
    """Concrete reference generator covering all four ``SUPPORTED_TYPES``.

    Construction parameters:

      seed:
          Integer seed for all internal randomness. Two generators built
          with the same seed produce byte-identical output.
      compress:
          When True, payloads are zlib-compressed before return.
    """

    def __init__(self, seed: int = 0, compress: bool = False) -> None:
        super().__init__(compress=compress)
        self._seed = seed

    def _rng(self, payload_type: str) -> random.Random:
        # Per-type RNG so payload types are seeded independently.
        return random.Random(f"{self._seed}:{payload_type}")

    def _maybe_compress(self, raw: bytes) -> bytes:
        return zlib.compress(raw) if self.compress else raw

    def _credit_cards(self, size_bytes: int, rng: random.Random) -> bytes:
        out: list[str] = []
        running = 0
        while running < size_bytes:
            line = _synth_pan(rng) + "\n"
            out.append(line)
            running += len(line)
        return "".join(out).encode("ascii")[:size_bytes]

    def _log(self, size_bytes: int, rng: random.Random) -> bytes:
        out: list[str] = []
        running = 0
        while running < size_bytes:
            line = _synth_log_line(rng)
            out.append(line)
            running += len(line)
        return "".join(out).encode("ascii")[:size_bytes]

    def _image(self, size_bytes: int, rng: random.Random) -> bytes:
        # JFIF-ish leading bytes; the rest is high-entropy noise so the
        # output looks plausibly image-like to an entropy-focused detector
        # without being a valid decodable image.
        header = bytes((0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46))
        body = bytes(rng.randint(0, 255) for _ in range(max(0, size_bytes - len(header))))
        return (header + body)[:size_bytes]

    def _text(self, size_bytes: int, rng: random.Random) -> bytes:
        out: list[str] = []
        running = 0
        while running < size_bytes:
            words = rng.randint(8, 24)
            block = _synth_text(rng, words) + ".\n"
            out.append(block)
            running += len(block)
        return "".join(out).encode("utf-8")[:size_bytes]

    def generate(self, size_bytes: int, payload_type: str) -> bytes:
        if size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")
        if payload_type not in self.SUPPORTED_TYPES:
            raise ValueError(
                f"unknown payload_type {payload_type!r}; "
                f"expected one of {self.SUPPORTED_TYPES}"
            )
        rng = self._rng(payload_type)
        if payload_type == "credit_card":
            raw = self._credit_cards(size_bytes, rng)
        elif payload_type == "log":
            raw = self._log(size_bytes, rng)
        elif payload_type == "image":
            raw = self._image(size_bytes, rng)
        elif payload_type == "text":
            raw = self._text(size_bytes, rng)
        else:
            raise AssertionError(f"unreachable: payload_type {payload_type!r}")
        return self._maybe_compress(raw)


__all__ = ("DefaultPayloadGenerator",)
