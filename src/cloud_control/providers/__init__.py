from ..config import Config
from ._base import BaseProvider
from .aws import AWS


def get_provider(config: Config) -> BaseProvider:
    if config.provider == "aws":
        return AWS()
    else:
        raise ValueError(f"Unknown provider {config.provider}")
