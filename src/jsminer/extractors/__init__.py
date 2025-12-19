"""Extractors for JSMiner."""

from jsminer.extractors.base import BaseExtractor
from jsminer.extractors.secrets import SecretExtractor
from jsminer.extractors.endpoints import EndpointExtractor
from jsminer.extractors.urls import URLExtractor

__all__ = [
    "BaseExtractor",
    "SecretExtractor",
    "EndpointExtractor",
    "URLExtractor",
]
