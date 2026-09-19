"""Domain exceptions for wazuh-devenv."""


class WazuhDevenvError(RuntimeError):
    """Base error reported as a concise CLI diagnostic."""


class UnsupportedPlatformError(WazuhDevenvError):
    """Raised when the host platform cannot be provisioned."""


class CommandError(WazuhDevenvError):
    """Raised when an external command fails."""


class ConfigurationError(WazuhDevenvError):
    """Raised when an existing configuration cannot be changed safely."""


class CorpusError(WazuhDevenvError):
    """Raised for corpus discovery, verification, or installation failures."""
