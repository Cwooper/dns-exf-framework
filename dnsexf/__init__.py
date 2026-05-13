"""dnsexf: a modular research framework for DNS exfiltration experiments.

See ``docs/architecture.md`` for the framework overview,
``docs/interfaces.md`` for the component contract specification, and
``docs/extending.md`` for the extension guide.
"""

from dnsexf.interfaces import (
    DNSRecord,
    DNSRecordLoader,
    Detector,
    PayloadGenerator,
    QueryEncoder,
    QueryValidator,
    TimingController,
    ValidationResult,
    VictimProfile,
    VictimSelector,
)
from dnsexf.encoders import (
    AlphabeticBase32Encoder,
    Base64Encoder,
    HexEncoder,
    LongSubdomainEncoder,
    ShortSubdomainEncoder,
    TXTRecordEncoder,
    all_baseline_encoders,
)
from dnsexf.payload import DefaultPayloadGenerator
from dnsexf.victim_selector import (
    AdaptiveSelector,
    RoundRobinSelector,
    WeightedSelector,
    filter_workstation_range,
)
from dnsexf.timing import AdaptiveTiming, FixedTiming, JitteredTiming
from dnsexf.injector import AttackInjector


__version__ = "0.1.0"

__all__ = (
    # Core types
    "DNSRecord",
    "DNSRecordLoader",
    "ValidationResult",
    "VictimProfile",
    # Abstract bases
    "PayloadGenerator",
    "QueryEncoder",
    "VictimSelector",
    "TimingController",
    "Detector",
    # Concrete reference implementations
    "QueryValidator",
    "DefaultPayloadGenerator",
    "Base64Encoder",
    "HexEncoder",
    "AlphabeticBase32Encoder",
    "ShortSubdomainEncoder",
    "LongSubdomainEncoder",
    "TXTRecordEncoder",
    "all_baseline_encoders",
    "RoundRobinSelector",
    "WeightedSelector",
    "AdaptiveSelector",
    "FixedTiming",
    "JitteredTiming",
    "AdaptiveTiming",
    "AttackInjector",
    "filter_workstation_range",
)
