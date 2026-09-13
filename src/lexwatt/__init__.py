"""LexWatt — estimate model work, meter local package energy, stop the
contained workload when its budget is exhausted.

Local-first OSS core: no listener, no telemetry, no hosted dependencies.
"""

from .errors import LexwattError

__version__ = "1.0.0"

__all__ = ["LexwattError"]
