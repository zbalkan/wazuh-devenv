from __future__ import annotations

import pytest

from wazuhdevenv.errors import ConfigurationError
from wazuhdevenv.provisioning import _replace_block_child, _replace_simple_tag


def test_replace_simple_tag_is_idempotent() -> None:
    source = "<logall_json>no</logall_json>"
    changed = _replace_simple_tag(source, "logall_json", "yes", {"yes", "no"})
    assert changed == "<logall_json>yes</logall_json>"
    assert _replace_simple_tag(changed, "logall_json", "yes", {"yes", "no"}) == changed


def test_replace_simple_tag_rejects_unknown_state() -> None:
    with pytest.raises(ConfigurationError):
        _replace_simple_tag("<logall_json>maybe</logall_json>", "logall_json", "yes", {"yes", "no"})


def test_replace_block_child_changes_only_selected_block() -> None:
    source = """<rootcheck>
  <disabled>no</disabled>
</rootcheck>
<syscheck>
  <disabled>no</disabled>
</syscheck>
"""
    changed = _replace_block_child(
        source,
        r"<rootcheck>.*?</rootcheck>",
        "disabled",
        "yes",
        {"yes", "no"},
        "rootcheck",
    )
    assert "<rootcheck>\n  <disabled>yes</disabled>" in changed
    assert "<syscheck>\n  <disabled>no</disabled>" in changed
