"""Generic newline-delimited JSON loader.

Each line is a JSON object with the following required keys:

  * ``timestamp``: ISO 8601 string, parsed via ``datetime.fromisoformat``.
                      Timezone-aware values are preferred.
  * ``src_ip``: source client IP, as a string.
  * ``qname``: queried name. Lowercased and trailing-dot stripped
                      by the loader.
  * ``qtype``: DNS RR type mnemonic, e.g. ``"A"``, ``"AAAA"``,
                      ``"TXT"``. Numeric type values are stringified
                      as-is; callers wanting mnemonic resolution should
                      pre-process.

Optional keys:

  * ``event_type``: ``"query"`` (default) or ``"response"``.

Lines that fail to parse, or that are missing any required key, are skipped
silently, so small format quirks (blank trailing lines, comments stripped
to whitespace) do not break iteration.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterator

from dnsexf.interfaces import DNSRecord
from dnsexf.loaders import REQUIRED_FIELDS, normalize_qname


class JSONLLoader:
    """Stream ``DNSRecord`` events from a newline-delimited JSON file."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def records(self) -> Iterator[DNSRecord]:
        with self._path.open("r", encoding="utf-8") as fh:
            for raw_line in fh:
                stripped = raw_line.strip()
                if not stripped:
                    continue
                try:
                    obj = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if not all(k in obj for k in REQUIRED_FIELDS):
                    continue
                try:
                    ts = datetime.fromisoformat(str(obj["timestamp"]))
                except ValueError:
                    continue
                yield DNSRecord(
                    timestamp=ts,
                    src_ip=str(obj["src_ip"]),
                    qname=normalize_qname(str(obj["qname"])),
                    qtype=str(obj["qtype"]),
                    event_type=str(obj.get("event_type", "query")),
                )

    def dns_queries(self) -> Iterator[DNSRecord]:
        return (r for r in self.records() if r.event_type == "query")


__all__ = ("JSONLLoader",)
