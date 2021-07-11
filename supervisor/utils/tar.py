"""Tarfile fileobject handler for encrypted files."""
import asyncio
import contextlib
import hashlib
from io import BufferedReader, BytesIO
import logging
import os
from pathlib import Path, PurePath
import tarfile
from tarfile import TarFile, TarInfo
from typing import (
    AsyncContextManager,
    AsyncIterator,
    BinaryIO,
    Callable,
    Generator,
    List,
    Optional,
    Protocol,
    Union,
)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    CipherContext,
    algorithms,
    modes,
)

_LOGGER: logging.Logger = logging.getLogger(__name__)


class WriterCloser(Protocol):
    """Support write(...) and close()."""

    def write(self, data: bytes) -> int:
        """Write data bytes."""
        ...

    def close(self) -> None:
        """Flush and releases any buffers and closes all handles."""
        ...


class ReaderCloser(Protocol):
    """Support read(...) and close()."""

    def read(self, n: int) -> bytes:
        """Read up to _n_ bytes."""
        ...

    def close(self):
        """Release any unread buffers and handles."""
        ...


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
    def __init__(self, f: WriterCloser, key: bytes) -> None:
        self._file: WriterCloser = f
        self._rand: Union[bytes, None] = os.urandom(16)
        self._encrypt: CipherContext = _cipher(key, self._rand).encryptor()
        self._bytes_written: int = 0

    def write(self, data: bytes) -> int:
        """Encrypt and write the data.

        Because AES is a block cipher the length of bytes written to the
        underlying file might be longer or shorter than input data.
        """
        # write self._rand once, done at first write to make __init__ always
        # non blocking, and simplify code somewhat.
        if self._rand:
            self._file.write(self._rand)
            self._rand = None
        self._bytes_written += len(data)
        ecrypted = self._encrypt.update(data)
        self._file.write(ecrypted)
        return len(data)

    def close(self):
        """Flush any buffered data, padding as necessary.

        It does not close the underlying file, as it did not open it.
        """
        # pad bytes to block size, as per PKCS7 it's the number of padded bytes
        # that is the byte value
        padding_len = 16 - self._bytes_written % 16
        padding_data = padding_len.to_bytes(1, "little") * padding_len
        self._file.write(self._encrypt.update(padding_data))

    def __enter__(self) -> WriterCloser:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


class _SecureReader:
    def __init__(self, f: ReaderCloser, key: bytes) -> None:
        self._file: ReaderCloser = f
        self._key: bytes = key
        # Initialized on first read, to make __init__ non-blocking.
        self._decrypt: Optional[CipherContext] = None

    def read(self, n: int) -> bytes:
        """Return at most the next n bytes."""
        # only works if n is a multiple of 16.. it's ok for tar files that read
        # 10k blocks by default.
        if not self._decrypt:
            decrypt = _cipher(self._key, self._file.read(16)).decryptor()
            self._key = b""  # no need for key to stick around
            self._decrypt = decrypt
        else:
            decrypt = self._decrypt
        edata = self._file.read(n)
        return decrypt.update(edata)

    def close(self) -> None:
        """Close file handles and release any buffers."""
        self._file.close()

    def __enter__(self) -> ReaderCloser:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


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


def SecureTarReader(name: Path, key: Optional[bytes] = None) -> TarFile:
    """Return and open TarFile, decrypt file if key is provided."""
    f: ReaderCloser = name.open("rb")
    if key:
        f = _SecureReader(f, key)
    # As of 2021-07-11 the typeshed for tarfile.open is lacking overrides
    # to recognize what's precisely needed for mode="r|gz"
    return tarfile.open(None, mode="r|gz", fileobj=f)  # type: ignore


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


class Adder(Protocol):
    """Interface allowing for archive contents to be added.

    The API is async, and it's expected that the implementation will know
    enough about the underlying streams avoid blocking where needed and remain efficient.
    """

    def __init__(self, open_f: WriterCloser, key: Optional[bytes] = None):
        """Construct the object."""

    async def aclose(self):
        """Flushes all buffers, but does not close a previously opened file."""
        ...

    async def add(
        self,
        name: str,
        arcname: Optional[str] = None,
        recursive: bool = True,
        filter: Optional[Callable[[tarfile.TarInfo], Optional[tarfile.TarInfo]]] = None,
    ):
        """Add a file from a filesystem, analogue to Tarfile.add."""
        ...

    async def atomic_contents_add(
        self, origin_path: Path, excludes: List[str], arcname: str = "."
    ):
        """Append directories and/or files to the TarFile if excludes wont filter."""

    async def add_immediate(
        self, name: str, buf: Union[memoryview, bytes], mode: int = 0o644
    ):
        """Write the contents of the buf as a file into the archive."""

    def add_open(
        self, name: str, mode: int = 0o644
    ) -> AsyncContextManager[WriterCloser]:
        """Return a BufferedWriter that when closed will add buffer content."""
        ...

    def add_nested_archive(
        self, path: Path, key: Optional[bytes] = None
    ) -> AsyncContextManager["Adder"]:
        """Make a new archive within the current archive."""
        ...


class _AdderImpl(contextlib.AbstractAsyncContextManager[Adder]):
    """Wraps a tar archive."""

    def __init__(self, open_f: WriterCloser, key: Optional[bytes] = None):
        """Open a tar archive (non-blocking)."""
        self._exit_stack = contextlib.ExitStack()

        # Optionally, wrap an open file with some encryption.
        if key:
            secure_f = _SecureWriter(open_f, key)
            open_f = self._exit_stack.enter_context(secure_f)

        self._file: WriterCloser = open_f
        # As of 2021-07-01: There don't seem to be good type overrides for
        # tarfile.open. Various type checkers think this needs a IO[Bytes] of
        # some kind, but WriterCloser is enough for w|gz mode.
        self._tar: TarFile = tarfile.open(None, mode="w|gz", fileobj=open_f)  # type: ignore
        self._exit_stack.callback(self._tar.close)

    def close(self):
        self._exit_stack.close()

    async def aclose(self):
        await asyncio.get_running_loop().run_in_executor(None, self.close)

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

    async def add_immediate(
        self, name: str, buf: Union[memoryview, bytes], mode: int = 0o644
    ):
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
    ) -> AsyncIterator[WriterCloser]:
        buf: BytesIO = BytesIO()
        try:
            yield buf
        finally:
            await self.add_immediate(name, buf.getbuffer(), mode=mode)

    @contextlib.asynccontextmanager
    async def add_nested_archive(self, path: Path, key: Optional[bytes] = None):
        stack = contextlib.AsyncExitStack()
        try:
            open_f: WriterCloser = await stack.enter_async_context(
                self.add_open(path.name)
            )
            open_a: Adder = await stack.enter_async_context(_AdderImpl(open_f, key))
            yield open_a
        finally:
            await stack.aclose()

    async def __aenter__(self) -> Adder:
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        """Close any underlying files, or signal errors in case of exceptions."""
        await self.aclose()


@contextlib.asynccontextmanager
async def open_archive_async(name: Path, key: Optional[bytes] = None):
    """Async friendly version of open_archive, delegates blocking to separate threadpool."""

    open_f: Optional[WriterCloser] = None
    try:
        open_f = await asyncio.get_running_loop().run_in_executor(None, name.open, "wb")
        async with _AdderImpl(open_f, key) as a:
            yield a
    finally:
        if open_f is not None:
            await asyncio.get_running_loop().run_in_executor(None, open_f.close)
