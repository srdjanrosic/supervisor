"""Tarfile fileobject handler for encrypted files."""
import asyncio
import contextlib
import hashlib
from io import BytesIO
import logging
import os
from pathlib import Path, PurePath
import tarfile
from tarfile import TarFile, TarInfo
from typing import IO, TYPE_CHECKING, Callable, Generator, List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)

_LOGGER: logging.Logger = logging.getLogger(__name__)

BLOCK_SIZE = 16
BLOCK_SIZE_BITS = 128


def SecureTarReader(name: Path, key: Optional[bytes] = None, gzip: bool = True):
    return _SecureTarFile(name, "r", key, gzip)


class _SecureTarFile:
    """Handle encrypted files for tarfile library."""

    def __init__(
        self, name: Path, mode: str, key: Optional[bytes] = None, gzip: bool = True
    ) -> None:
        """Initialize encryption handler."""
        self._file: Optional[IO[bytes]] = None
        self._mode: str = mode
        self._name: Path = name

        # Tarfile options
        self._tar: Optional[tarfile.TarFile] = None
        self._tar_mode: str = f"{mode}|gz" if gzip else f"{mode}|"

        # Encryption/Description
        self._aes: Optional[Cipher] = None
        self._key: Optional[bytes] = key

        # Function helper
        self._decrypt: Optional[CipherContext] = None
        self._encrypt: Optional[CipherContext] = None

    def __enter__(self) -> tarfile.TarFile:
        """Start context manager tarfile."""
        if not self._key:
            self._tar = tarfile.open(
                name=str(self._name), mode=self._tar_mode, dereference=False
            )
            return self._tar

        # Encrypted/Decryped Tarfile
        if self._mode.startswith("r"):
            file_mode: int = os.O_RDONLY
        else:
            file_mode: int = os.O_WRONLY | os.O_CREAT
        self._file = os.open(self._name, file_mode, 0o666)

        # Extract IV for CBC
        if self._mode == "r":
            cbc_rand = os.read(self._file, 16)
        else:
            cbc_rand = os.urandom(16)
            os.write(self._file, cbc_rand)

        # Create Cipher
        self._aes = Cipher(
            algorithms.AES(self._key),
            modes.CBC(_generate_iv(self._key, cbc_rand)),
            backend=default_backend(),
        )

        self._decrypt = self._aes.decryptor()
        self._encrypt = self._aes.encryptor()

        self._tar = tarfile.open(fileobj=self, mode=self._tar_mode, dereference=False)
        return self._tar

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """Close file."""
        if self._tar:
            self._tar.close()
            self._tar = None
        if self._file:
            os.close(self._file)
            self._file = None

    def write(self, data: bytes) -> None:
        """Write data."""
        if len(data) % BLOCK_SIZE != 0:
            padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
            data = padder.update(data) + padder.finalize()

        os.write(self._file, self._encrypt.update(data))

    def read(self, size: int = 0) -> bytes:
        """Read data."""
        return self._decrypt.update(os.read(self._file, size))

    @property
    def path(self) -> Path:
        """Return path object of tarfile."""
        return self._name

    @property
    def size(self) -> float:
        """Return snapshot size."""
        if not self._name.is_file():
            return 0
        return round(self._name.stat().st_size / 1_048_576, 2)  # calc mbyte


def _generate_iv(key: bytes, salt: bytes) -> bytes:
    """Generate an iv from data."""
    temp_iv = key + salt
    for _ in range(100):
        temp_iv = hashlib.sha256(temp_iv).digest()
    return temp_iv[:16]


def secure_path(tar: tarfile.TarFile) -> Generator[tarfile.TarInfo, None, None]:
    """Security safe check of path.

    Prevent ../ or absolute paths
    """
    for member in tar:
        file_path = Path(member.name)
        try:
            if file_path.is_absolute():
                raise ValueError()
            Path("/fake", file_path).resolve().relative_to("/fake")
        except (ValueError, RuntimeError):
            _LOGGER.warning("Found issue with file %s", file_path)
            continue
        else:
            yield member


def _is_excluded_by_filter(path: PurePath, exclude_list: List[str]) -> bool:
    """Filter to filter excludes."""

    for exclude in exclude_list:
        if not path.match(exclude):
            continue
        _LOGGER.debug("Ignoring %s because of %s", path, exclude)
        return True

    return False


def atomic_contents_add(
    tar_file: tarfile.TarFile,
    origin_path: Path,
    excludes: List[str],
    arcname: str = ".",
) -> None:
    """Append directories and/or files to the TarFile if excludes wont filter."""

    if _is_excluded_by_filter(origin_path, excludes):
        return None

    # Add directory only (recursive=False) to ensure we also archive empty directories
    tar_file.add(origin_path.as_posix(), arcname=arcname, recursive=False)

    for directory_item in origin_path.iterdir():
        if _is_excluded_by_filter(directory_item, excludes):
            continue

        arcpath = PurePath(arcname, directory_item.name).as_posix()
        if directory_item.is_dir() and not directory_item.is_symlink():
            atomic_contents_add(tar_file, directory_item, excludes, arcpath)
            continue

        tar_file.add(directory_item.as_posix(), arcname=arcpath, recursive=False)

    return None


class Adder(contextlib.AbstractAsyncContextManager):
    """Interface allowing for archive contents to be added.

    The API is async, and it's expected that the implementation will know
    enough about the underlying streams avoid blocking where needed and remain efficient.
    """

    def __init__(self):
        """Construct the object."""

    async def add(
        self,
        name: str,
        arcname: Optional[str] = None,
        recursive: bool = True,
        filter: Optional[Callable[[tarfile.TarInfo], Optional[tarfile.TarInfo]]] = None,
    ):
        ...

    async def atomic_contents_add(
        self, origin_path: Path, excludes: List[str], arcname: str = "."
    ):
        """Append directories and/or files to the TarFile if excludes wont filter."""

    async def add_immediate(self, name: str, buf: memoryview, mode: int = 0o644):
        """Write the contents of the memoryview as a file into the archive."""
        ...

    @contextlib.asynccontextmanager
    async def add_open(
        self, name: str, mode: int = 0o644
    ) -> Generator[BytesIO, None, None]:
        ...

    @property
    def size(self) -> float:
        """Return size of archive in megabytes."""
        ...


class _AdderImpl:
    """Wraps a tar archive."""

    def __init__(self, name: Path, key: Optional[bytes] = None, gzip: bool = True):
        self._secure_tar_file = _SecureTarFile(name, "w", key=key, gzip=gzip)
        self._tar: Optional[TarFile] = None
        self._exit_stack = contextlib.ExitStack()
        self._closed = False

    async def __aenter__(self) -> Adder:
        self._tar = await asyncio.get_running_loop().run_in_executor(
            None, self._exit_stack.enter_context, self._secure_tar_file
        )
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        """Close any underlying files, or signal errors in case of exceptions."""
        await asyncio.get_running_loop().run_in_executor(None, self._exit_stack.close)

    async def add(
        self,
        name: str,
        arcname: Optional[str] = None,
        recursive: bool = True,
        filter: Optional[Callable[[tarfile.TarInfo], Optional[tarfile.TarInfo]]] = None,
    ):
        await asyncio.get_running_loop().run_in_executor(
            None,  # executor
            self._tar.add,
            name,
            arcname,
            recursive,
            filter,
        )

    async def atomic_contents_add(
        self, origin_path: Path, excludes: List[str], arcname: str = "."
    ):
        await asyncio.get_running_loop().run_in_executor(
            None,  # executor
            atomic_contents_add,
            self._tar,
            origin_path,
            excludes,
            arcname,
        )

    async def add_immediate(self, name: str, buf: memoryview, mode: int = 0o644):
        tinfo = TarInfo(name)
        sz = len(buf)
        tinfo.size = sz
        tinfo.mode = mode

        def _add_blocking():
            self._tar.addfile(tinfo)
            self._tar.fileobj.write(buf)
            padding = 512 - sz % 512
            self._tar.fileobj.write(b"\0" * padding)
            self._tar.offset += sz + padding

        await asyncio.get_running_loop().run_in_executor(None, _add_blocking)

    @contextlib.asynccontextmanager
    async def add_open(
        self, name: str, mode: int = 0o644
    ) -> Generator[BytesIO, None, None]:
        buf: BytesIO = BytesIO()
        try:
            yield buf
        finally:
            await self.add_immediate(name, buf.getbuffer(), mode=mode)

    @property
    def size(self) -> float:
        """Return snapshot size."""
        if not self._closed:
            raise ValueError("cannot determine sized of yet to be written archive.")
        return self._secure_tar_file.size


def make_archive(name: Path, key: Optional[bytes] = None, gzip: bool = True) -> Adder:
    """Make a new (optionally) secure archive on disk."""
    return _AdderImpl(name, key, gzip)
