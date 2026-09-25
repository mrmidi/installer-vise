"""installer-vise — experimental extractor for Installer VISE 3.x archives.

Reverse-engineered, dependency-free Python package.  Currently validated
against one reference archive.  See ``docs/`` in the repository for the
complete format specification and validation log.
"""

from .archive import Archive
from .catalog import Catalog, Record
from .deflate import InflateError, deflate_stored, inflate, inflate_span
from .errors import (
    ViseError,
    ViseFormatError,
    ViseInflateError,
    ViseIntegrityError,
)
from .extract import (
    FileResult,
    RecordStatus,
    Summary,
    extract_archive,
)
from .subst import TABLE as SUBST_TABLE
from .subst import invert_table, subst

__version__ = "1.0.0"

__all__ = [
    "Archive",
    "Catalog",
    "Record",
    "FileResult",
    "RecordStatus",
    "Summary",
    "SUBST_TABLE",
    "ViseError",
    "ViseFormatError",
    "ViseInflateError",
    "ViseIntegrityError",
    "InflateError",
    "deflate_stored",
    "extract_archive",
    "inflate",
    "inflate_span",
    "invert_table",
    "subst",
    "__version__",
]
