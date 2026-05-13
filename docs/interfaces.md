# Interface specification

This file lists the framework's public types and their contracts. The
authoritative source is `dnsexf/interfaces.py`; this document summarizes
the contract so reviewers can audit the surface without reading code.

## `DNSRecord`

A frozen dataclass with five required fields and one opaque passthrough:

| Field        | Type                | Notes                                               |
| ------------ | ------------------- | --------------------------------------------------- |
| `timestamp`  | `datetime`          | Timezone-aware preferred.                           |
| `src_ip`     | `str`               | IPv4 dotted-quad or IPv6.                           |
| `qname`      | `str`               | Lowercased, trailing-dot stripped.                  |
| `qtype`      | `str`               | RR-type mnemonic, e.g. `"A"`, `"AAAA"`, `"TXT"`.    |
| `event_type` | `str`               | `"query"` (default) or `"response"`.                |
| `raw`        | `Mapping[str, Any]` | Adapter-private. Framework code does not read this. |

## `DNSRecordLoader` (Protocol)

Two methods. Implementations are expected to yield records in
non-decreasing timestamp order.

| Method        | Signature                   | Description                        |
| ------------- | --------------------------- | ---------------------------------- |
| `records`     | `() -> Iterator[DNSRecord]` | Every event from the source.       |
| `dns_queries` | `() -> Iterator[DNSRecord]` | Filter to `event_type == "query"`. |

## `PayloadGenerator` (ABC)

Constructor takes a `compress: bool` flag. Subclass and override
`generate`.

| Method     | Signature                                       | Description                          |
| ---------- | ----------------------------------------------- | ------------------------------------ |
| `generate` | `(size_bytes: int, payload_type: str) -> bytes` | Return bytes of the requested class. |

Reference implementation: `DefaultPayloadGenerator` covering
`"credit_card"`, `"log"`, `"image"`, `"text"`.

## `QueryEncoder` (ABC)

Strategy for turning payload bytes into one or more DNS labels.

| Method         | Signature                           | Description                                     |
| -------------- | ----------------------------------- | ----------------------------------------------- |
| `encode_chunk` | `(data: bytes, seq_id: int) -> str` | One chunk in, label portion out.                |
| `chunk_size`   | `() -> int`                         | Bytes per `encode_chunk`.                       |
| `record_type`  | `() -> str`                         | Target RR type.                                 |
| `name`         | `() -> str`                         | Stable identifier for logging.                  |
| `decode`       | `(label: str) -> bytes`             | Optional. Default raises `NotImplementedError`. |

Six bundled encoders cover the Table 2 baselines.

## `VictimProfile`

Frozen dataclass.

| Field             | Type                  | Notes                           |
| ----------------- | --------------------- | ------------------------------- |
| `client_ip`       | `str`                 | Matches `DNSRecord.src_ip`.     |
| `query_count`     | `int`                 | Observed benign queries.        |
| `hourly_activity` | `Mapping[int, float]` | Optional per-hour rate.         |
| `extra`           | `Mapping[str, Any]`   | Passthrough for custom scoring. |

## `VictimSelector` (ABC)

Constructor takes `victims`, `seed`, `mode`.

| Method   | Signature                                     | Description                 |
| -------- | --------------------------------------------- | --------------------------- |
| `select` | `(timestamp: datetime \| None = None) -> str` | Return the next client IP.  |
| `stats`  | `() -> Mapping[str, Any]`                     | Selection-count audit data. |

Bundled modes: `"round_robin"`, `"weighted"`, `"adaptive"`. Custom modes
are allowed; `mode` is treated as opaque.

## `TimingController` (ABC)

Constructor takes `base_rate_qph`, `seed`, `mode`.

| Method             | Signature                  | Description                                 |
| ------------------ | -------------------------- | ------------------------------------------- |
| `next_interval`    | `(now: datetime) -> float` | Seconds until the next query.               |
| `record_injection` | `(now: datetime) -> None`  | Notification hook for stateful controllers. |

Bundled modes: `"fixed"`, `"jittered"`, `"adaptive"`.

## `ValidationResult`

Frozen dataclass.

| Field     | Type              | Notes                        |
| --------- | ----------------- | ---------------------------- |
| `valid`   | `bool`            | True iff `reasons` is empty. |
| `reasons` | `tuple[str, ...]` | Failure rule names.          |

## `QueryValidator` (concrete)

Two methods. RFC 1035 syntactic check, plus optional round-trip decode.

| Method               | Signature                                                                 | Description                      |
| -------------------- | ------------------------------------------------------------------------- | -------------------------------- |
| `validate`           | `(fqdn: str) -> ValidationResult`                                         | Syntactic check.                 |
| `validate_decodable` | `(fqdn: str, encoder: QueryEncoder, original: bytes) -> ValidationResult` | Syntactic check plus round-trip. |

Failure reason vocabulary: `empty`, `empty_label`, `fqdn_too_long`,
`label_too_long`, `leading_hyphen`, `trailing_hyphen`, `invalid_character`,
`encoder_not_invertible`, `decode_error`, `decode_mismatch`.

## `Detector` (ABC)

Four methods.

| Method    | Signature                                 | Description                               |
| --------- | ----------------------------------------- | ----------------------------------------- |
| `fit`     | `(benign_queries: Iterable[str]) -> None` | Train or calibrate; no-op for rule-based. |
| `score`   | `(fqdn: str) -> float`                    | Real-valued maliciousness score.          |
| `predict` | `(fqdn: str) -> bool`                     | Binary verdict.                           |
| `name`    | `() -> str`                               | Stable identifier.                        |

The detector contract is FQDN-only by design. Detectors that need wider
context (timing, batching) accept it via their constructor.
