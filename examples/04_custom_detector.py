"""How to plug a detector into the evaluation pipeline.

This example defines a toy ``EntropyDetector`` that flags queries whose
subdomain Shannon entropy exceeds a threshold. It is not a real detector;
it exists to show the contract a ``Detector`` implementation needs to
satisfy.

Run from the repo root::

    uv run python examples/04_custom_detector.py
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable

from dnsexf.encoders import Base64Encoder
from dnsexf.injector import AttackInjector
from dnsexf.interfaces import Detector, VictimProfile
from dnsexf.loaders import JSONLLoader
from dnsexf.payload import DefaultPayloadGenerator
from dnsexf.timing import FixedTiming
from dnsexf.victim_selector import RoundRobinSelector


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class EntropyDetector(Detector):
    """Flag a query when its leftmost label entropy exceeds ``threshold``.

    The ``fit`` step sets the threshold to the 99th percentile of the
    entropy distribution observed in the benign training stream. This is
    a simple way to demonstrate the interface, nothing more.
    """

    def __init__(self) -> None:
        # Until fit() runs, predict() flags nothing.
        self.threshold: float = float("inf")

    def fit(self, benign_queries: Iterable[str]) -> None:
        ents = sorted(_shannon_entropy(q.split(".", 1)[0]) for q in benign_queries)
        if not ents:
            return
        idx = max(0, int(0.99 * len(ents)) - 1)
        self.threshold = ents[idx]

    def score(self, fqdn: str) -> float:
        return _shannon_entropy(fqdn.split(".", 1)[0])

    def predict(self, fqdn: str) -> bool:
        return self.score(fqdn) > self.threshold

    def name(self) -> str:
        return "entropy"


def main() -> None:
    benign = list(JSONLLoader("fixtures/benign_sample.jsonl").dns_queries())
    detector = EntropyDetector()
    detector.fit(r.qname for r in benign)
    print(f"detector trained, threshold={detector.threshold:.3f}")

    # Generate a small attack stream of high-entropy base64 queries.
    injector = AttackInjector(
        encoder=Base64Encoder(),
        victim_selector=RoundRobinSelector(
            (VictimProfile(client_ip="10.0.0.10", query_count=100),)
        ),
        timing=FixedTiming(base_rate_qph=720.0),
    )
    payload = DefaultPayloadGenerator(seed=7, compress=False).generate(
        size_bytes=500, payload_type="credit_card"
    )
    attack = list(injector.stream(benign[0].timestamp, payload))

    benign_flags = sum(1 for r in benign if detector.predict(r.qname))
    attack_flags = sum(1 for r in attack if detector.predict(r.qname))
    print(f"benign:  {benign_flags}/{len(benign)} flagged (FPR proxy)")
    print(f"attack:  {attack_flags}/{len(attack)} flagged (recall proxy)")


if __name__ == "__main__":
    main()
