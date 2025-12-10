from dataclasses import dataclass


@dataclass
class TlsConfig:
    key: str
    cert: str
    ca: str


@dataclass
class TransportConfig:
    addr: str


@dataclass
class S2Config:
    seed: str
    tls: TlsConfig
    transport: TransportConfig
    network: str = "regtest"
