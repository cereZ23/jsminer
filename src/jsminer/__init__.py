"""JSMiner - JavaScript security mining tool."""

__version__ = "1.0.0"
__author__ = "Andrea Ceresoni"
__email__ = "andrea.ceresoni@gmail.com"

from jsminer.core.models import Finding, ScanResult, SecretType

__all__ = [
    "__version__",
    "Finding",
    "ScanResult",
    "SecretType",
]
