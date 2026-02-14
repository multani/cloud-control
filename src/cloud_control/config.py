import json
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from .providers._base import BaseProvider


@dataclass
class DiskConfig:
    data: str


@dataclass
class NetworkConfig:
    eni: str
    ip: str
    interface: str


@dataclass
class VaultConfig:
    root_token_secret_name: str


@dataclass
class Config:
    disk: DiskConfig
    network: NetworkConfig
    vault: VaultConfig
    provider: str = "aws"

    def get_provider(self) -> BaseProvider:
        if self.provider == "aws":
            from .providers.aws import AWS

            return AWS(self)
        else:
            raise ValueError(f"Unknown provider {self.provider}")

    @classmethod
    def load(cls) -> Self:
        path = Path("/etc/conf.json")
        return cls.load_from_file(path)

    @classmethod
    def load_from_file(cls, path: Path) -> Self:
        data = {}

        if path.is_file():
            data = json.loads(path.read_text())
        else:
            for p in path.iterdir():
                if p.suffix != ".json":
                    continue

                part = json.loads(path.read_text())
                data.update(part)

        disk = DiskConfig(**data["disk"])
        network = NetworkConfig(**data["network"])
        vault = VaultConfig(**data["vault"])
        return cls(disk=disk, network=network, vault=vault)
