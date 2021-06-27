"""Tools file for Supervisor."""
from datetime import datetime
from io import BufferedWriter, TextIOWrapper
import json
import logging
from pathlib import Path
from typing import IO, Any

from atomicwrites import atomic_write

from ..exceptions import JsonFileError

_LOGGER: logging.Logger = logging.getLogger(__name__)


class JSONEncoder(json.JSONEncoder):
    """JSONEncoder that supports Supervisor objects."""

    def default(self, o: Any) -> Any:
        """Convert Supervisor special objects.

        Hand other objects to the original method.
        """
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, set):
            return list(o)
        if isinstance(o, Path):
            return str(o)
        if hasattr(o, "as_dict"):
            return o.as_dict()

        return json.JSONEncoder.default(self, o)


def write_json(fp: IO[bytes], data: Any) -> None:
    """Write JSON into a writer."""
    try:
        json.dump(
            data,
            TextIOWrapper(fp, encoding="utf-8", write_through=True),
            indent=2,
            cls=JSONEncoder,
        )
    except (OSError, ValueError, TypeError) as err:
        raise JsonFileError(f"Can't write JSON: {err!s}", _LOGGER.error) from err


def write_json_file(jsonfile: Path, data: Any) -> None:
    """Write a JSON file."""
    try:
        with atomic_write(jsonfile, overwrite=True) as fp:
            fp.write(json.dumps(data, indent=2, cls=JSONEncoder))
        jsonfile.chmod(0o600)
    except (OSError, ValueError, TypeError) as err:
        raise JsonFileError(
            f"Can't write {jsonfile!s}: {err!s}", _LOGGER.error
        ) from err


def read_json_file(jsonfile: Path) -> Any:
    """Read a JSON file and return a dict."""
    try:
        return json.loads(jsonfile.read_text())
    except (OSError, ValueError, TypeError, UnicodeDecodeError) as err:
        raise JsonFileError(
            f"Can't read json from {jsonfile!s}: {err!s}", _LOGGER.error
        ) from err
