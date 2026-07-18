"""exposed — find what of your personal data is leaking online, then remove it."""

from .scan import run_scan

__version__ = "0.1.0"
__all__ = ["run_scan", "__version__"]
