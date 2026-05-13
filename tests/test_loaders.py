"""Loader smoke tests against the bundled synthetic fixture."""

import csv
import json

import pytest

from dnsexf.loaders import CSVLoader, JSONLLoader


def test_jsonl_loader_yields_records(benign_jsonl, benign_jsonl_size):
    recs = list(JSONLLoader(benign_jsonl).records())
    assert len(recs) == benign_jsonl_size
    for r in recs[:5]:
        assert r.timestamp is not None
        assert r.src_ip
        assert r.qname
        assert r.qtype in {"A", "AAAA", "TXT", "MX", "CNAME"}


def test_jsonl_loader_filters_queries(benign_jsonl, benign_jsonl_size):
    queries = list(JSONLLoader(benign_jsonl).dns_queries())
    assert all(r.event_type == "query" for r in queries)
    assert len(queries) == benign_jsonl_size


def test_jsonl_loader_chronological(benign_jsonl):
    recs = list(JSONLLoader(benign_jsonl).records())
    for prev, nxt in zip(recs, recs[1:]):
        assert prev.timestamp <= nxt.timestamp


def test_jsonl_loader_skips_broken_lines(tmp_path, benign_jsonl):
    junk = tmp_path / "with_junk.jsonl"
    with benign_jsonl.open() as src, junk.open("w") as dst:
        dst.write("not json\n")
        dst.write('{"missing":"fields"}\n')
        for i, line in enumerate(src):
            if i >= 10:
                break
            dst.write(line)
    recs = list(JSONLLoader(junk).records())
    assert len(recs) == 10


def test_csv_loader_round_trip(tmp_path, benign_jsonl, benign_jsonl_size):
    target = tmp_path / "benign.csv"
    with benign_jsonl.open() as src, target.open("w", newline="") as dst:
        writer = csv.DictWriter(
            dst, fieldnames=["timestamp", "src_ip", "qname", "qtype", "event_type"]
        )
        writer.writeheader()
        for line in src:
            row = json.loads(line)
            writer.writerow(
                {
                    "timestamp": row["timestamp"],
                    "src_ip": row["src_ip"],
                    "qname": row["qname"],
                    "qtype": row["qtype"],
                    "event_type": row.get("event_type", "query"),
                }
            )
    recs = list(CSVLoader(target).records())
    assert len(recs) == benign_jsonl_size


def test_csv_loader_missing_columns_yields_nothing(tmp_path):
    target = tmp_path / "bad.csv"
    target.write_text("name,value\nfoo,bar\n")
    recs = list(CSVLoader(target).records())
    assert recs == []


def test_jsonl_loader_missing_path_raises(tmp_path):
    missing = tmp_path / "nope.jsonl"
    with pytest.raises(FileNotFoundError):
        list(JSONLLoader(missing).records())
