"""wazuhdevenv package."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("wazuhdevenv")
except PackageNotFoundError:  # source checkout
    __version__ = "0.4.0.dev0"

__all__ = ["__version__"]
