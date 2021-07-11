"""Test Tarfile functions."""
import asyncio
import os
from pathlib import Path, PurePath
import shutil

import attr

from supervisor.utils.tar import (
    SecureTarReader,
    _is_excluded_by_filter,
    open_archive_async,
    secure_path,
)


@attr.s
class TarInfo:
    """Fake TarInfo."""

    name: str = attr.ib()


def test_secure_path():
    """Test Secure Path."""
    test_list = [
        TarInfo("test.txt"),
        TarInfo("data/xy.blob"),
        TarInfo("bla/blu/ble"),
        TarInfo("data/../xy.blob"),
    ]
    assert test_list == list(secure_path(test_list))


def test_not_secure_path():
    """Test Not secure path."""
    test_list = [
        TarInfo("/test.txt"),
        TarInfo("data/../../xy.blob"),
        TarInfo("/bla/blu/ble"),
    ]
    assert [] == list(secure_path(test_list))


def test_is_excluded_by_filter_good():
    """Test exclude filter."""
    filter_list = ["not/match", "/dev/xy"]
    test_list = [
        PurePath("test.txt"),
        PurePath("data/xy.blob"),
        PurePath("bla/blu/ble"),
        PurePath("data/../xy.blob"),
    ]

    for path_object in test_list:
        assert _is_excluded_by_filter(path_object, filter_list) is False


def test_is_exclude_by_filter_bad():
    """Test exclude filter."""
    filter_list = ["*.txt", "data/*", "bla/blu/ble"]
    test_list = [
        PurePath("test.txt"),
        PurePath("data/xy.blob"),
        PurePath("bla/blu/ble"),
        PurePath("data/test_files/kk.txt"),
    ]

    for path_object in test_list:
        assert _is_excluded_by_filter(path_object, filter_list) is True


def test_create_pure_tar(tmp_path):
    """Test to create a tar file without encryption."""
    # Prepair test folder
    temp_orig = tmp_path.joinpath("orig")
    fixture_data = Path(__file__).parents[1].joinpath("fixtures/tar_data")
    shutil.copytree(fixture_data, temp_orig, symlinks=True)

    # Create Tarfile
    temp_tar = tmp_path.joinpath("backup.tar")

    async def open_archive_wrapper():
        """wrap into async for test, that's how it'll be used."""
        async with open_archive_async(temp_tar) as ta:
            await ta.add_immediate("foobar", b"just some data")
            await ta.atomic_contents_add(
                temp_orig,
                excludes=[],
                arcname=".",
            )

    asyncio.get_event_loop().run_until_complete(open_archive_wrapper())

    assert temp_tar.exists()

    # Restore
    temp_new = tmp_path.joinpath("new")
    with SecureTarReader(temp_tar) as tar_file:
        tar_file.extractall(path=temp_new, members=tar_file)

    assert temp_new.is_dir()
    assert temp_new.joinpath("test_symlink").is_symlink()
    assert temp_new.joinpath("test1").is_dir()
    assert temp_new.joinpath("test1/script.sh").is_file()

    # 775 is correct for local, but in GitHub action it's 755, both is fine
    assert oct(temp_new.joinpath("test1/script.sh").stat().st_mode)[-3:] in [
        "755",
        "775",
    ]
    assert temp_new.joinpath("README.md").is_file()
    assert temp_new.joinpath("foobar").read_text() == "just some data"


def test_create_ecrypted_tar(tmp_path):
    """Test to create a tar file with encryption."""
    key = os.urandom(16)

    # Prepair test folder
    temp_orig = tmp_path.joinpath("orig")
    fixture_data = Path(__file__).parents[1].joinpath("fixtures/tar_data")
    shutil.copytree(fixture_data, temp_orig, symlinks=True)

    # Create Tarfile
    temp_tar = tmp_path.joinpath("backup.tar")

    async def open_archive_wrapper():
        async with open_archive_async(temp_tar, key) as ta:
            await ta.atomic_contents_add(
                temp_orig,
                excludes=[],
                arcname=".",
            )

    asyncio.get_event_loop().run_until_complete(open_archive_wrapper())

    assert temp_tar.exists()

    # Restore
    temp_new = tmp_path.joinpath("new")
    with SecureTarReader(temp_tar, key=key) as tar_file:
        tar_file.extractall(path=temp_new, members=tar_file)

    assert temp_new.is_dir()
    assert temp_new.joinpath("test_symlink").is_symlink()
    assert temp_new.joinpath("test1").is_dir()
    assert temp_new.joinpath("test1/script.sh").is_file()

    # 775 is correct for local, but in GitHub action it's 755, both is fine
    assert oct(temp_new.joinpath("test1/script.sh").stat().st_mode)[-3:] in [
        "755",
        "775",
    ]
    assert temp_new.joinpath("README.md").is_file()
