"""Exception types for the Installer VISE extractor."""


class ViseError(Exception):
    """Base class for all Installer VISE errors."""


class ViseFormatError(ViseError):
    """The archive or catalog is malformed / not an Installer VISE file."""


class ViseInflateError(ViseFormatError, ValueError):
    """A VISE word-aligned DEFLATE stream is corrupt.

    Inherits from :class:`ValueError` so callers that historically catch
    ``ValueError`` from the deflate layer keep working.
    """


class ViseIntegrityError(ViseError):
    """A decoded record failed its CRC32 verification.

    Raised only in strict mode; the normal pipeline records the failure in
    :class:`installer_vise.Summary` instead.
    """
