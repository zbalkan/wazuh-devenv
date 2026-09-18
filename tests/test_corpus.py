from __future__ import annotations

import stat
import zipfile

import pytest

from wazuhdevenv.corpus import _release_key, _validate_member
from wazuhdevenv.errors import CorpusError


def test_release_key_orders_corpus_revisions() -> None:
    assert _release_key("4.14-r2") > _release_key("4.14-r1")
    assert _release_key("4.15-r1") > _release_key("4.14-r99")


@pytest.mark.parametrize("name", ["/etc/passwd", "../escape", "tests/../../escape"])
def test_archive_paths_cannot_escape_root(name: str) -> None:
    info = zipfile.ZipInfo(name)
    with pytest.raises(CorpusError):
        _validate_member(info)


def test_symlink_archive_member_is_rejected() -> None:
    info = zipfile.ZipInfo("tests/link")
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(CorpusError):
        _validate_member(info)


def test_regular_archive_member_is_allowed() -> None:
    info = zipfile.ZipInfo("tests/test_example.py")
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    _validate_member(info)
