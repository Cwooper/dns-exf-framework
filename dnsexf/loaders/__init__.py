"""Reference loaders.

The framework does not commit to a single on-disk format. The two
loaders here cover the most common cases for sharing benign DNS traces:

  * ``JSONLLoader``: newline-delimited JSON with one DNS event per line.
  * ``CSVLoader``: CSV with one DNS event per row.

For dataset-specific formats (e.g. PCAP, vendor JSON dumps), implement the
``DNSRecordLoader`` protocol directly. See ``docs/extending.md`` for the
template.
"""

# Field keys every reference loader requires on every record.
REQUIRED_FIELDS: tuple[str, ...] = ("timestamp", "src_ip", "qname", "qtype")


def normalize_qname(name: str) -> str:
    """Lowercase the name and strip any trailing dot.

    Loader implementations should apply this to ``qname`` so consumers do
    not need to special-case per-source quirks.
    """
    return name.lower().rstrip(".")


from dnsexf.loaders.jsonl import JSONLLoader  # noqa: E402
from dnsexf.loaders.csv import CSVLoader  # noqa: E402

__all__ = ("JSONLLoader", "CSVLoader", "REQUIRED_FIELDS", "normalize_qname")
