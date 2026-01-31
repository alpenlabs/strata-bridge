from dataclasses import dataclass


@dataclass
class Duration:
    secs: int
    nanos: int
