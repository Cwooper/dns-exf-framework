# Architecture

The framework is organized around four components, plus a format-agnostic
data loader and an external detector adapter. Each piece is independently
replaceable; researchers extending the framework subclass an interface or
implement a protocol and plug the new object into the pipeline.

```
              +-------------------+
              | DNSRecordLoader   |   format-agnostic benign source
              +---------+---------+
                        |
                        v
+------------------+    |    +-----------------------+
| PayloadGenerator |    |    | VictimSelector        |
+--------+---------+    |    +-----------+-----------+
         |              |                |
         v              |                |
+--------+---------+    |                |
| QueryEncoder     |    |                |
+--------+---------+    |                |
         |              |                |
         |   +----------v---------+      |
         +-->| AttackInjector     |<-----+
             | (orchestration)    |
             +----------+---------+
                        |
                        v
              +-------------------+
              | QueryValidator    |   RFC 1035 backstop
              +---------+---------+
                        |
                        v
              +-------------------+
              | Detector (eval)   |   optional, per-query scoring
              +-------------------+
```

## Component 1: PayloadGenerator

Produces raw bytes for the four payload classes the paper enumerates:
credit card data, log files, image data, and text. Optional zlib
compression. Subclass `PayloadGenerator` to add new payload classes; the
existing four are provided by `DefaultPayloadGenerator`.

## Component 2: VictimSelector

Picks the source IP for the next attack query from a pool of
`VictimProfile` candidates. Three modes are bundled:

- `RoundRobinSelector` cycles through victims deterministically.
- `WeightedSelector` biases by log-scaled query count.
- `AdaptiveSelector` adds an hour-of-day multiplier on top of weighted.

The pool is the selector's responsibility to filter. `filter_workstation_range`
is provided as a convenience helper for the Section 5.4 query-count band.

## Component 3: TimingController

Decides when each attack query fires. Returns the inter-arrival delay in
seconds. Three bundled modes:

- `FixedTiming` produces an exact `3600 / qph` interval.
- `JitteredTiming` adds a uniform plus-or-minus 10 percent jitter.
- `AdaptiveTiming` scales the interval by an hour-of-day multiplier map.

## Component 4: QueryValidator

RFC 1035 backstop: total FQDN length, per-label length, allowed
characters, leading and trailing hyphen rules. Optional decodability check
that round-trips a candidate FQDN through the encoder. Subclass for
additional constraints; the default rules are sufficient for the
reference pipeline.

## Supporting: QueryEncoder

The strategy that turns payload bytes into one or more DNS labels. Six
baseline encoders ship with the framework, spanning the Table 2 feature
space: high entropy base64, hex, alphabetic base32, short subdomain, long
subdomain, and a TXT-targeted variant. The encoder returns only the label
portion; the injector joins it to the attacker-controlled parent domain.

## Supporting: DNSRecordLoader

A `Protocol` that yields `DNSRecord` instances in chronological order. The
framework does not commit to a single on-disk format. Two
reference loaders are provided for sharing benign traces:
`JSONLLoader` and `CSVLoader`. For other formats (PCAP, vendor JSON,
live capture) implement the protocol directly; the contract is two
methods, `records()` and `dns_queries()`.

## Supporting: Detector

A four-method adapter over an external NIDS: `fit`, `score`, `predict`,
`name`. Detectors that do not need training make `fit` a no-op. Detectors
that need richer context than a single FQDN can accept that context via
their constructor and still expose the adapter interface.

## Orchestration: AttackInjector

The user-facing entry point. Composes a payload generator (via the caller),
a query encoder, a victim selector, a timing controller, and a validator
into an iterator of attack `DNSRecord` events. `merge_with_benign` then
interleaves the attack stream with a benign stream from a loader in a
single chronological pass.

## Design principles

- **Semantic validity by construction.** Encoders are expected to emit
  RFC-valid labels; the validator catches edge cases and surfaces them
  in `injector.stats`.
- **Temporal realism.** Timing decisions are made against real
  timestamps drawn from the benign stream provided by a loader.
- **Reproducibility.** Every randomized component accepts an integer
  `seed`; the same seed, same inputs, same outputs.
- **Extensibility.** All four components are abstract or protocol-typed.
  The injector's core dependency is the method signatures, not the
  concrete classes.
