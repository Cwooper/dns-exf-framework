# Extending the framework

The framework is designed to be extended at each of its component
boundaries. This guide walks through the five common extension tasks.

## Adding a new encoder

Subclass `QueryEncoder` and implement the four required methods. If your
encoder is invertible, also implement `decode`. The validator's
round-trip check will then exercise it.

```python
from dnsexf.interfaces import QueryEncoder

class MyEncoder(QueryEncoder):
    def encode_chunk(self, data, seq_id):
        return data.hex()
    def chunk_size(self):    return 25
    def record_type(self):   return "A"
    def name(self):          return "my-hex"
    def decode(self, label): return bytes.fromhex(label)
```

`examples/02_custom_encoder.py` has a working version.

## Adding a new victim selector

Subclass `VictimSelector` and implement `select` and `stats`. The base
class stores `victims`, `seed`, and `mode` for you. Picking
`mode="custom"` is fine; the framework treats it as an opaque string.

```python
from dnsexf.interfaces import VictimSelector

class StealthSelector(VictimSelector):
    def __init__(self, victims, seed=0):
        super().__init__(victims=victims, seed=seed, mode="custom")
        self._counts = {v.client_ip: 0 for v in self._victims}

    def select(self, timestamp=None):
        chosen = min(self._victims, key=lambda v: v.query_count)
        self._counts[chosen.client_ip] += 1
        return chosen.client_ip

    def stats(self):
        return {"selection_counts": dict(self._counts)}
```

`examples/05_custom_selector_and_timing.py` has a working version.

## Adding a new timing controller

Subclass `TimingController`. The two required methods are
`next_interval` (return seconds until the next query) and
`record_injection` (notification hook; stateless controllers make this a
no-op).

## Writing a custom data loader

Implement the `DNSRecordLoader` Protocol: `records()` and
`dns_queries()` returning iterators of `DNSRecord`. You do not need to
inherit from a framework base class.

```python
from datetime import datetime
from dnsexf.interfaces import DNSRecord

class MyLoader:
    def __init__(self, path):
        self._path = path

    def records(self):
        with open(self._path) as fh:
            for line in fh:
                ts, src, name, qtype = line.rstrip().split(",")
                yield DNSRecord(
                    timestamp=datetime.fromisoformat(ts),
                    src_ip=src,
                    qname=name.lower().rstrip("."),
                    qtype=qtype,
                )

    def dns_queries(self):
        return self.records()
```

Two responsibilities of any loader: yield records in non-decreasing
timestamp order, and normalize `qname` (lowercased, trailing-dot
stripped). `examples/03_custom_loader.py` shows the same pattern with an
in-memory list.

## Plugging in a detector

Subclass `Detector` and implement the four methods. Rule-based or
pre-trained detectors make `fit` a no-op. Detectors that need wider
context than a single FQDN accept that context via their constructor and
still expose `score(fqdn)` / `predict(fqdn)`.

```python
from dnsexf.interfaces import Detector

class MyDetector(Detector):
    def __init__(self): self._threshold = 0.0
    def fit(self, benign_queries):  # find a threshold from data
        self._threshold = some_calibration(benign_queries)
    def score(self, fqdn):    return float(my_model(fqdn))
    def predict(self, fqdn):  return self.score(fqdn) >= self._threshold
    def name(self):           return "my-detector"
```

`examples/04_custom_detector.py` has a working version.

## A note on randomness and reproducibility

Every randomized component takes an integer `seed`. Same seed, same
inputs, same outputs is a guaranteed contract for the bundled
components and is the recommended contract for custom subclasses. Tests
in `tests/test_victim_selector.py` and `tests/test_timing.py` show how
the determinism property is asserted; mirror those patterns when adding
new components.
