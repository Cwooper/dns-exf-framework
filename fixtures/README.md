# Fixtures

Synthetic data used by the test suite and the quickstart examples.

* `benign_sample.jsonl`: 300 synthetic benign DNS query records in the
  flat JSONL format consumed by `dnsexf.loaders.JSONLLoader`. The data is
  generated programmatically (no real network capture) and is meant only
  to exercise the loader/injector pipeline end-to-end. It is not a
  realistic traffic distribution and should not be used as a benchmark.
