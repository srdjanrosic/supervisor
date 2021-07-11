"""Representation of a snapshot file."""
from base64 import b64decode, b64encode
from contextlib import AsyncExitStack
import json
import logging
from pathlib import Path
import tarfile
from typing import Any, Dict, List, Optional, Set

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import voluptuous as vol
from voluptuous.humanize import humanize_error

from ..addons import Addon
from ..const import (
    ATTR_ADDONS,
    ATTR_AUDIO_INPUT,
    ATTR_AUDIO_OUTPUT,
    ATTR_BOOT,
    ATTR_CRYPTO,
    ATTR_DATE,
    ATTR_DOCKER,
    ATTR_FOLDERS,
    ATTR_HOMEASSISTANT,
    ATTR_IMAGE,
    ATTR_NAME,
    ATTR_PASSWORD,
    ATTR_PORT,
    ATTR_PROTECTED,
    ATTR_REFRESH_TOKEN,
    ATTR_REGISTRIES,
    ATTR_REPOSITORIES,
    ATTR_SLUG,
    ATTR_SSL,
    ATTR_TYPE,
    ATTR_USERNAME,
    ATTR_VERSION,
    ATTR_WAIT_BOOT,
    ATTR_WATCHDOG,
    CRYPTO_AES128,
    FOLDER_HOMEASSISTANT,
)
from ..coresys import CoreSys, CoreSysAttributes
from ..exceptions import AddonsError
from ..utils.json import write_json
from ..utils.tar import Adder, SecureTarReader, open_archive_async, secure_path
from .utils import key_to_iv, password_for_validating, password_to_key, remove_folder
from .validate import ALL_FOLDERS, SCHEMA_SNAPSHOT

_LOGGER: logging.Logger = logging.getLogger(__name__)

MAP_FOLDER_EXCLUDE = {
    FOLDER_HOMEASSISTANT: [
        "*.db-wal",
        "*.db-shm",
        "__pycache__/*",
        "*.log",
        "OZW_Log.txt",
    ]
}


class Snapshot(CoreSysAttributes):
    """A single Supervisor snapshot."""

    def __init__(self, coresys: CoreSys, tar_file: Path):
        """Initialize a snapshot."""
        self.coresys: CoreSys = coresys
        self._tarfile: Path = tar_file
        self._data: Dict[str, Any] = {}
        self._stack = AsyncExitStack()
        self._adder: Optional[Adder] = None  # used when creating snapshots.
        self._key: Optional[bytes] = None
        self._aes: Optional[Cipher] = None

    @property
    def slug(self):
        """Return snapshot slug."""
        return self._data.get(ATTR_SLUG)

    @property
    def sys_type(self):
        """Return snapshot type."""
        return self._data.get(ATTR_TYPE)

    @property
    def name(self):
        """Return snapshot name."""
        return self._data[ATTR_NAME]

    @property
    def date(self):
        """Return snapshot date."""
        return self._data[ATTR_DATE]

    @property
    def protected(self):
        """Return snapshot date."""
        return self._data.get(ATTR_PROTECTED) is not None

    @property
    def addons(self):
        """Return snapshot date."""
        return self._data[ATTR_ADDONS]

    @property
    def addon_list(self):
        """Return a list of add-ons slugs."""
        return [addon_data[ATTR_SLUG] for addon_data in self.addons]

    @property
    def folders(self):
        """Return list of saved folders."""
        return self._data[ATTR_FOLDERS]

    @property
    def repositories(self):
        """Return snapshot date."""
        return self._data[ATTR_REPOSITORIES]

    @repositories.setter
    def repositories(self, value):
        """Set snapshot date."""
        self._data[ATTR_REPOSITORIES] = value

    @property
    def homeassistant_version(self):
        """Return snapshot Home Assistant version."""
        return self._data[ATTR_HOMEASSISTANT].get(ATTR_VERSION)

    @property
    def homeassistant(self):
        """Return snapshot Home Assistant data."""
        return self._data[ATTR_HOMEASSISTANT]

    @property
    def docker(self):
        """Return snapshot Docker config data."""
        return self._data.get(ATTR_DOCKER, {})

    @docker.setter
    def docker(self, value):
        """Set the Docker config data."""
        self._data[ATTR_DOCKER] = value

    @property
    def size(self):
        """Return snapshot size."""
        if not self.tarfile.is_file():
            return 0  # not yet created.
        return round(self.tarfile.stat().st_size / 1048576, 2)  # calc mbyte

    @property
    def is_new(self):
        """Return True if tarfile does not exist."""
        return not self.tarfile.exists()

    @property
    def tarfile(self):
        """Return path to Snapshot tarfile."""
        return self._tarfile

    def new(self, slug, name, date, sys_type, password=None):
        """Initialize a new snapshot."""
        # Init metadata
        self._data[ATTR_SLUG] = slug
        self._data[ATTR_NAME] = name
        self._data[ATTR_DATE] = date
        self._data[ATTR_TYPE] = sys_type

        # Add defaults
        self._data = SCHEMA_SNAPSHOT(self._data)

        # Set password
        if password:
            self._init_password(password)
            self._data[ATTR_PROTECTED] = password_for_validating(password)
            self._data[ATTR_CRYPTO] = CRYPTO_AES128

    def set_password(self, password: str) -> bool:
        """Set the password for an existing snapshot."""
        if not password:
            return False

        validating = password_for_validating(password)
        if validating != self._data[ATTR_PROTECTED]:
            return False

        self._init_password(password)
        return True

    def _init_password(self, password: str) -> None:
        """Set password + init aes cipher."""
        self._key = password_to_key(password)
        self._aes = Cipher(
            algorithms.AES(self._key),
            modes.CBC(key_to_iv(self._key)),
            backend=default_backend(),
        )

    def _encrypt_data(self, data: str) -> str:
        """Make data secure."""
        if not self._key or data is None:
            return data

        aes: Cipher = self._aes  # type: ignore  # always initialized
        encrypt = aes.encryptor()
        padder = padding.PKCS7(128).padder()

        data = padder.update(data.encode()) + padder.finalize()
        return b64encode(encrypt.update(data)).decode()

    def _decrypt_data(self, data: str) -> str:
        """Make data readable."""
        if not self._key or data is None:
            return data

        aes: Cipher = self._aes  # type: ignore  # always initialized
        decrypt = aes.decryptor()
        padder = padding.PKCS7(128).unpadder()

        data = padder.update(decrypt.update(b64decode(data))) + padder.finalize()
        return data.decode()

    async def load(self):
        """Read snapshot.json from tar file."""
        if not self.tarfile.is_file():
            _LOGGER.error("No tarfile located at %s", self.tarfile)
            return False

        def _load_file():
            """Read snapshot.json."""
            with tarfile.open(self.tarfile, "r:") as snapshot:
                json_file = snapshot.extractfile("./snapshot.json")
                return json_file.read()

        # read snapshot.json
        try:
            raw = await self.sys_run_in_executor(_load_file)
        except (tarfile.TarError, KeyError) as err:
            _LOGGER.error("Can't read snapshot tarfile %s: %s", self.tarfile, err)
            return False

        # parse data
        try:
            raw_dict = json.loads(raw)
        except json.JSONDecodeError as err:
            _LOGGER.error("Can't read data for %s: %s", self.tarfile, err)
            return False

        # validate
        try:
            self._data = SCHEMA_SNAPSHOT(raw_dict)
        except vol.Invalid as err:
            _LOGGER.error(
                "Can't validate data for %s: %s",
                self.tarfile,
                humanize_error(raw_dict, err),
            )
            return False

        return True

    async def _add_snapshot_json(self):
        """Serialize self._data into the archive as `snapshot.json`."""
        # validate data
        try:
            self._data = SCHEMA_SNAPSHOT(self._data)
        except vol.Invalid as err:
            _LOGGER.error(
                "Invalid data for %s: %s", self.tarfile, humanize_error(self._data, err)
            )
            raise ValueError("Invalid config") from None

        async with self._adder.add_open("snapshot.json", mode=0o600) as buf:
            write_json(buf, self._data)

    async def __aenter__(self):
        """Async context to open a snapshot, either new or an existing one."""
        if not self.tarfile.is_file():
            # We're using this Snapshot instance to create a new snapshot.
            # Initialize an Adder, and write out snapshot.json from already
            # populated/stored _data.
            self._adder = await self._stack.enter_async_context(
                open_archive_async(self.tarfile, self._key)
            )
            # Add snapshot.json first.
            await self._add_snapshot_json()
            return self

        # extract an existing snapshot
        def _extract_snapshot():
            """Extract a snapshot."""
            with tarfile.open(self.tarfile, "r:") as tar:
                tar.extractall(path=self._tmp.name, members=secure_path(tar))

        await self.sys_run_in_executor(_extract_snapshot)

    async def __aexit__(self, exception_type, exception_value, traceback):
        """Async context to close a snapshot."""
        if not self._adder:
            # We're using this Snapshot instance for a restore, nothing to do.
            return

        await self._stack.aclose()

    def store_addons_meta(self, addon_list: Optional[List[Addon]] = None):
        """Add a list of add-ons into snapshot _data."""
        addon_list: List[Addon] = addon_list or self.sys_addons.installed

        for addon in addon_list:
            try:
                # Store to config
                self._data[ATTR_ADDONS].append(
                    {
                        ATTR_SLUG: addon.slug,
                        ATTR_NAME: addon.name,
                        ATTR_VERSION: addon.version,
                    }
                )
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.warning("Can't save Add-on %s: %s", addon.slug, err)

    async def store_addons(self, addon_list: Optional[List[Addon]] = None):
        """Add a list of add-ons into snapshot."""
        addons: List[Addon] = addon_list or self.sys_addons.installed

        for addon in addons:
            try:
                adder = self._adder  # type: Adder
                async with adder.add_nested_archive(
                    f"{addon.slug}.tar.gz", key=self._key
                ) as addon_archive:
                    await addon.snapshot(addon_archive)
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.warning("Can't save Add-on %s: %s", addon.slug, err)

    async def restore_addons(self, addon_list: Optional[List[str]] = None):
        """Restore a list add-on from snapshot."""
        addon_list: List[str] = addon_list or self.addon_list

        async def _addon_restore(addon_slug: str):
            """Task to restore an add-on into snapshot."""
            addon_file = SecureTarReader(
                Path(self._tmp.name, f"{addon_slug}.tar.gz"), key=self._key
            )

            # If exists inside snapshot
            if not addon_file.path.exists():
                _LOGGER.error("Can't find snapshot %s", addon_slug)
                return

            # Perform a restore
            try:
                await self.sys_addons.restore(addon_slug, addon_file)
            except AddonsError:
                _LOGGER.error("Can't restore snapshot %s", addon_slug)

        # Save Add-ons sequential
        # avoid issue on slow IO
        for slug in addon_list:
            try:
                await _addon_restore(slug)
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.warning("Can't restore Add-on %s: %s", slug, err)

    def store_folders_meta(self, folder_list: Optional[List[str]] = None):
        """Backup Supervisor data into snapshot."""
        folder_list: Set[str] = set(folder_list or ALL_FOLDERS)

        for folder in sorted(folder_list):
            try:
                origin_dir = Path(self.sys_config.path_supervisor, folder)
                if not origin_dir.is_dir():
                    _LOGGER.warning("Can't find snapshot folder %s", folder)
                    continue
                self._data[ATTR_FOLDERS].append(folder)
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.warning("Can't save folder %s: %s", folder, err)

    async def store_folders(self, folder_list: Optional[List[str]] = None):
        """Backup Supervisor data into snapshot."""
        folder_list: Set[str] = set(folder_list or ALL_FOLDERS)

        async def _folder_save(name: str):
            """Take snapshot of a folder."""
            slug_name = name.replace("/", "_")
            tar_name = Path(self._tmp.name, f"{slug_name}.tar.gz")
            origin_dir = Path(self.sys_config.path_supervisor, name)

            # Check if exists
            if not origin_dir.is_dir():
                _LOGGER.warning("Can't find snapshot folder %s", name)
                return

            # Take snapshot
            try:
                _LOGGER.info("Snapshot folder %s", name)
                async with open_archive_async(tar_name, key=self._key) as ta:
                    await ta.atomic_contents_add(
                        origin_dir,
                        excludes=MAP_FOLDER_EXCLUDE.get(name, []),
                        arcname=".",
                    )

                _LOGGER.info("Snapshot folder %s done", name)
            except (tarfile.TarError, OSError) as err:
                _LOGGER.warning("Can't snapshot folder %s: %s", name, err)

        # Save folder sequential
        # avoid issue on slow IO
        for folder in sorted(folder_list):
            try:
                await _folder_save(folder)
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.warning("Can't save folder %s: %s", folder, err)

    async def restore_folders(self, folder_list: Optional[List[str]] = None):
        """Backup Supervisor data into snapshot."""
        folder_list: Set[str] = set(folder_list or self.folders)

        def _folder_restore(name: str):
            """Intenal function to restore a folder."""
            slug_name = name.replace("/", "_")
            tar_name = Path(self._tmp.name, f"{slug_name}.tar.gz")
            origin_dir = Path(self.sys_config.path_supervisor, name)

            # Check if exists inside snapshot
            if not tar_name.exists():
                _LOGGER.warning("Can't find restore folder %s", name)
                return

            # Clean old stuff
            if origin_dir.is_dir():
                remove_folder(origin_dir)

            # Perform a restore
            try:
                _LOGGER.info("Restore folder %s", name)
                with SecureTarReader(tar_name, key=self._key) as tar_file:
                    tar_file.extractall(path=origin_dir, members=tar_file)
                _LOGGER.info("Restore folder %s done", name)
            except (tarfile.TarError, OSError) as err:
                _LOGGER.warning("Can't restore folder %s: %s", name, err)

        # Restore folder sequential
        # avoid issue on slow IO
        for folder in folder_list:
            try:
                await self.sys_run_in_executor(_folder_restore, folder)
            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.warning("Can't restore folder %s: %s", folder, err)

    def store_homeassistant(self):
        """Read all data from Home Assistant object."""
        self.homeassistant[ATTR_VERSION] = self.sys_homeassistant.version
        self.homeassistant[ATTR_WATCHDOG] = self.sys_homeassistant.watchdog
        self.homeassistant[ATTR_BOOT] = self.sys_homeassistant.boot
        self.homeassistant[ATTR_WAIT_BOOT] = self.sys_homeassistant.wait_boot
        self.homeassistant[ATTR_IMAGE] = self.sys_homeassistant.image

        # API/Proxy
        self.homeassistant[ATTR_PORT] = self.sys_homeassistant.api_port
        self.homeassistant[ATTR_SSL] = self.sys_homeassistant.api_ssl
        self.homeassistant[ATTR_REFRESH_TOKEN] = self._encrypt_data(
            self.sys_homeassistant.refresh_token
        )

        # Audio
        self.homeassistant[ATTR_AUDIO_INPUT] = self.sys_homeassistant.audio_input
        self.homeassistant[ATTR_AUDIO_OUTPUT] = self.sys_homeassistant.audio_output

    def restore_homeassistant(self):
        """Write all data to the Home Assistant object."""
        self.sys_homeassistant.watchdog = self.homeassistant[ATTR_WATCHDOG]
        self.sys_homeassistant.boot = self.homeassistant[ATTR_BOOT]
        self.sys_homeassistant.wait_boot = self.homeassistant[ATTR_WAIT_BOOT]

        # API/Proxy
        self.sys_homeassistant.api_port = self.homeassistant[ATTR_PORT]
        self.sys_homeassistant.api_ssl = self.homeassistant[ATTR_SSL]
        self.sys_homeassistant.refresh_token = self._decrypt_data(
            self.homeassistant[ATTR_REFRESH_TOKEN]
        )

        # Audio
        self.sys_homeassistant.audio_input = self.homeassistant[ATTR_AUDIO_INPUT]
        self.sys_homeassistant.audio_output = self.homeassistant[ATTR_AUDIO_OUTPUT]

        # save
        self.sys_homeassistant.save_data()

    def store_repositories(self):
        """Store repository list into snapshot."""
        self.repositories = self.sys_config.addons_repositories

    def restore_repositories(self):
        """Restore repositories from snapshot.

        Return a coroutine.
        """
        return self.sys_store.update_repositories(self.repositories)

    def store_dockerconfig(self):
        """Store the configuration for Docker."""
        self.docker = {
            ATTR_REGISTRIES: {
                registry: {
                    ATTR_USERNAME: credentials[ATTR_USERNAME],
                    ATTR_PASSWORD: self._encrypt_data(credentials[ATTR_PASSWORD]),
                }
                for registry, credentials in self.sys_docker.config.registries.items()
            }
        }

    def restore_dockerconfig(self):
        """Restore the configuration for Docker."""
        if ATTR_REGISTRIES in self.docker:
            self.sys_docker.config.registries.update(
                {
                    registry: {
                        ATTR_USERNAME: credentials[ATTR_USERNAME],
                        ATTR_PASSWORD: self._decrypt_data(credentials[ATTR_PASSWORD]),
                    }
                    for registry, credentials in self.docker[ATTR_REGISTRIES].items()
                }
            )
            self.sys_docker.config.save_data()
