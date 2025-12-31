from dataclasses import dataclass
from pathlib import Path
import json
from typing import Self


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

    @classmethod
    def load(cls, path: Path) -> Self:
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
