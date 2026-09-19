from pathlib import Path

import pytest

from wazuhdevenv.errors import ConfigurationError
from wazuhdevenv.paths import resolve_workspace


def test_workspace_is_resolved(tmp_path: Path) -> None:
    assert resolve_workspace(str(tmp_path)) == tmp_path.resolve()


@pytest.mark.parametrize(
    "path",
    ["/", "/etc", "/etc/wazuh-project", "/var/tmp/project", "/usr/local/project", "/opt/project"],
)
def test_sensitive_system_workspaces_are_rejected(path: str) -> None:
    with pytest.raises(ConfigurationError):
        resolve_workspace(path)
