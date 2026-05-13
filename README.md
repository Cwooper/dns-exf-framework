# Adversarial DNS Exfiltration Framework

Code release accompanying *Adversarial DNS Exfiltration: Framework and
Defense Evaluation* (C. Morgan, L. Day, F. Jagodzinski, H.-J. Hong;
ACNS 2026).

The framework provides four extensible components for building
semantically-valid DNS exfiltration experiments: a payload generator,
a victim selector, a timing controller, and a query validator. A
format-agnostic data loader and a detector adapter round out the public
surface. The validator also exposes an optional round-trip decodability
check that callers can use to verify a custom encoder against its
original payload. The check delegates to the encoder's own `decode`
method, so meaningful round-trip verification has to be wired in
per-encoder: it only really matters for custom or lossy encoders, and
those implementations are responsible for supplying the matching
`decode` (or for skipping the check entirely if the encoder is
stateful or otherwise not round-trippable in isolation). See
`docs/architecture.md` for the component diagram and
`docs/interfaces.md` for the contract specification.

This repository ships the framework only. The adversarial generators
described in Section 6 of the paper, the ContraDNS detector from
Section 7, and the SoTA detectors evaluated alongside it are not part
of this release; refer to the paper and the cited works for their
design. The dataset adapters used during the paper's evaluation are
likewise internal and not included here.

The framework was rewritten from a private research codebase against a
clean-room interface so that the public release does not leak details
of the NDA-covered dataset used in development. This rewrite was done
with significant help from AI (Claude); apologies for any mismatched
content.

## Install

The project uses [uv](https://docs.astral.sh/uv/) for environment
management.

```bash
git clone https://github.com/Cwooper/dns-exf-framework.git
cd dns-exf-framework
uv sync --extra dev
```

This creates a `.venv/` and installs the package in editable mode along
with the test runner. Python 3.11 or newer is required. The core
framework has no runtime dependencies; the `dev` extra adds `pytest`.

## Quickstart

Run the bundled example end-to-end against the synthetic benign fixture:

```bash
uv run python examples/01_quickstart.py
```

Expected output is a count of benign and attack records, the injector
stats, and the first few generated attack queries. The full
quickstart in code form:

```python
from collections import Counter
from itertools import islice

from dnsexf import (
    AttackInjector, DefaultPayloadGenerator, HexEncoder, JitteredTiming,
    RoundRobinSelector, VictimProfile, filter_workstation_range,
)
from dnsexf.loaders import JSONLLoader

benign = list(JSONLLoader("fixtures/benign_sample.jsonl").dns_queries())

profiles = filter_workstation_range(
    [VictimProfile(client_ip=ip, query_count=n)
     for ip, n in Counter(r.src_ip for r in benign).items()],
    min_queries=1,
)

payload = DefaultPayloadGenerator(seed=42, compress=True).generate(
    size_bytes=200, payload_type="credit_card"
)

injector = AttackInjector(
    encoder=HexEncoder(),
    victim_selector=RoundRobinSelector(profiles, seed=1),
    timing=JitteredTiming(base_rate_qph=720.0, seed=1),
    parent_domain="exfil.example.com",
)

merged = injector.merge_with_benign(iter(benign), benign[0].timestamp, payload)
for record in islice(merged, 5):
    print(record)
```

## Examples

| Script                                      | Demonstrates                                       |
| ------------------------------------------- | -------------------------------------------------- |
| `examples/01_quickstart.py`                 | End-to-end attack run against the bundled fixture. |
| `examples/02_custom_encoder.py`             | Writing a `QueryEncoder` subclass.                 |
| `examples/03_custom_loader.py`              | Implementing the `DNSRecordLoader` protocol.       |
| `examples/04_custom_detector.py`            | Plugging a `Detector` into evaluation.             |
| `examples/05_custom_selector_and_timing.py` | Custom `VictimSelector` and `TimingController`.    |

Each example is self-contained and runs from the repo root via `uv run python ...`.

## Tests

```bash
uv run pytest
```

The test suite covers the validator, every bundled encoder, the payload
generator, both bundled loaders, both selector and timing subclasses,
and the injector pipeline.

## Repository layout

```
dns-exf-framework/
├── dnsexf/                 # the package
│   ├── interfaces.py       # public types (DNSRecord, ABCs, Protocol)
│   ├── payload.py          # Component 1: payload generator
│   ├── encoders.py         # Table 2 baseline encoders
│   ├── victim_selector.py  # Component 2: victim selection
│   ├── timing.py           # Component 3: timing controllers
│   ├── injector.py         # Orchestration (AttackInjector)
│   └── loaders/            # JSONL and CSV loaders
├── fixtures/               # synthetic benign DNS trace
├── examples/               # five runnable examples
├── tests/                  # pytest suite
└── docs/                   # architecture, interfaces, extending
```

## Documentation

- [docs/architecture.md](docs/architecture.md) walks through the four
  components and the orchestration layer.
- [docs/interfaces.md](docs/interfaces.md) is the contract specification
  for every public type.
- [docs/extending.md](docs/extending.md) covers the five common extension
  tasks with worked examples.

## Bringing your own data

The two bundled loaders (`JSONLLoader`, `CSVLoader`) read records with
fields `timestamp, src_ip, qname, qtype, event_type`. The synthetic
fixture at `fixtures/benign_sample.jsonl` shows the JSONL format. For
other formats, implement the `DNSRecordLoader` protocol directly;
see `examples/03_custom_loader.py` and `docs/extending.md`.

## License

MIT. See [LICENSE](LICENSE).
