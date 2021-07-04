"""Tarfile fileobject handler for encrypted files."""
import asyncio
import contextlib
import hashlib
from io import BufferedReader, BufferedWriter, BytesIO
import logging
import os
from pathlib import Path, PurePath
import tarfile
from tarfile import TarFile, TarInfo
from typing import Any, IO, Literal, TYPE_CHECKING, Callable, Generator, List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)

_LOGGER: logging.Logger = logging.getLogger(__name__)


def _cipher(key: bytes, salt: bytes) -> Cipher:
    temp_iv = key + salt
    for _ in range(100):
        temp_iv = hashlib.sha256(temp_iv).digest()
    iv = temp_iv[:16]

    return Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )


class _SecureWriter:
    def __init__(self, f: BufferedWriter, key: bytes) -> None:
        self._file: BufferedWriter = f
        rand = os.urandom(16)
        f.write(rand)
        self._encrypt: CipherContext = _cipher(key, rand).encryptor()
        self._bytes_written: int = 0

    def write(self, data: bytes):
        """Writes the data.

        Because AES is a block cipher the length of bytes written to the
        underlying file might be longer or shorter than input data.
        """
        self._bytes_written += len(data)
        ecrypted = self._encrypt.update(data)
        self._file.write(ecrypted)

    def close(self):
        """Flushes any buffered data and closes the underlying file."""
        # pad bytes to block size, as per PKCS7 it's the number of padded bytes
        # that is the byte value
        padding_len = 16 - self._bytes_written % 16
        padding_data = padding_len.to_bytes(1, "little") * padding_len
        self._file.write(self._encrypt.update(padding_data))
        _LOGGER.critical("wrote padding: %r", padding_data)
        # self._file.write(self._encrypt.finalize())
        self._file.close()

    def __enter__(self) -> "_SecureWriter":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


class _SecureReader:
    def __init__(self, f: BufferedReader, key: bytes) -> None:
        self._file: BufferedReader = f
        rand = f.read(16)
        self._decrypt: CipherContext = _cipher(key, rand).decryptor()

    def read(self, n: int) -> bytes:
        """Return the next n bytes."""
        # only works if n is a multiple of 16.. it's ok for tar files and
        return self._decrypt.update(self._file.read(n))

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> "_SecureReader":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


class _InsecureTarFile:
    """Handle encrypted files for tarfile library."""

    def __init__(self, name: Path, mode: Literal["r", "w"]) -> None:
        """Initialize encryption handler."""
        self._mode: str = mode
        self._name: Path = name

        self._tar: Optional[tarfile.TarFile] = None
        self._tar_mode: str = f"{mode}|gz"

    def __enter__(self) -> tarfile.TarFile:
        """Start context manager tarfile."""
        self._tar = tarfile.open(
            name=str(self._name), mode=self._tar_mode, dereference=False
        )
        return self._tar

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """Close file."""
        if self._tar:
            self._tar.close()
            self._tar = None

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


class _SecureTarFile:
    """Handle encrypted files for tarfile library."""

    def __init__(self, name: Path, mode: Literal["r", "w"], key: bytes) -> None:
        """Initialize encryption handler."""
        self._file: Any = None
        self._name: Path = name

        # Encrypted/Decryped Tarfile
        if mode.startswith("r"):
            self._file = _SecureReader(self._name.open("rb"), key)
        else:
            self._file = _SecureWriter(self._name.open("wb"), key)

        tar_mode: str = f"{mode}|gz"
        self._tar = tarfile.open(fileobj=self._file, mode=tar_mode, dereference=False)

    def __enter__(self) -> tarfile.TarFile:
        """Start context manager tarfile."""

        return self._tar

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """Close file."""
        if self._tar:
            self._tar.close()
            self._tar = None
        if self._file:
            self._file.close()
            self._file = None

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


def SecureTarReader(name: Path, key: Optional[bytes] = None):
    if not key:
        return _InsecureTarFile(name, "r")
    else:
        return _SecureTarFile(name, "r", key)


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

    def __init__(self, name: Path, key: Optional[bytes] = None):
        if not key:
            self._secure_tar_file = _InsecureTarFile(name, "w")
        else:
            self._secure_tar_file = _SecureTarFile(name, "w", key)
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


def make_archive(name: Path, key: Optional[bytes] = None) -> Adder:
    """Make a new (optionally) secure archive on disk."""
    return _AdderImpl(name, key)
