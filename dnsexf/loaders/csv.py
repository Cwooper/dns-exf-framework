"""Generic CSV loader.

The file is expected to have a header row naming at least these columns:

  * ``timestamp``: ISO 8601 string.
  * ``src_ip``: source client IP.
  * ``qname``: queried name (lowercased, trailing-dot stripped).
  * ``qtype``: DNS RR type mnemonic.

Optional column:

  * ``event_type``: ``"query"`` (default) or ``"response"``.

Rows missing any required column, or with an unparsable timestamp, are
skipped silently.
"""

from __future__ import annotations

import csv as _csv
from datetime import datetime
from pathlib import Path
from typing import Iterator

from dnsexf.interfaces import DNSRecord
from dnsexf.loaders import REQUIRED_FIELDS, normalize_qname


class CSVLoader:
    """Stream ``DNSRecord`` events from a CSV file."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def records(self) -> Iterator[DNSRecord]:
        with self._path.open("r", encoding="utf-8", newline="") as fh:
            reader = _csv.DictReader(fh)
            if reader.fieldnames is None or not all(
                col in reader.fieldnames for col in REQUIRED_FIELDS
            ):
                return
            for row in reader:
                if not all(row.get(col) for col in REQUIRED_FIELDS):
                    continue
                try:
                    ts = datetime.fromisoformat(row["timestamp"])
                except ValueError:
                    continue
                yield DNSRecord(
                    timestamp=ts,
                    src_ip=row["src_ip"],
                    qname=normalize_qname(row["qname"]),
                    qtype=row["qtype"],
                    event_type=row.get("event_type") or "query",
                )

    def dns_queries(self) -> Iterator[DNSRecord]:
        return (r for r in self.records() if r.event_type == "query")


__all__ = ("CSVLoader",)
