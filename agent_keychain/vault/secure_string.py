"""
Secure memory scrubbing for credential values.

Python strings are immutable and cannot be zeroed in place.
This module uses ctypes to overwrite the underlying memory buffer
so that credential values do not linger in process memory after use.
"""

import ctypes
import sys


def secure_zero(s: str) -> None:
    """
    Overwrite the memory backing a Python str object with zeros.

    Because Python strings are immutable, normal deletion only removes the
    reference — the bytes stay in the heap until reused.  This function
    uses ctypes.memset to zero the internal buffer so that secrets do not
    persist in memory longer than necessary.

    WARNING: This mutates an "immutable" object.  Only call this on
    strings you own and will never read again.
    """
    if not isinstance(s, str):
        return
    n = len(s)
    if n == 0:
        return

    # CPython str objects store their data as either Latin-1, UCS-2, or UCS-4
    # depending on the max codepoint.  sys.getsizeof gives the full object
    # size; we compute the data area by subtracting the size of an empty string.
    header_size = sys.getsizeof("")
    data_size = sys.getsizeof(s) - header_size

    if data_size <= 0:
        return

    # id(s) is the address of the PyObject.  The character data sits at
    # the end of the struct, at offset header_size.
    addr = id(s) + header_size

    ctypes.memset(addr, 0, data_size)


class SecureString:
    """
    A context manager that holds a credential string and automatically
    scrubs it from memory on exit.

    Usage::

        with SecureString(secret_value) as secret:
            use(secret)
        # secret is now zeroed in memory

    The underlying string can also be accessed via `str(secure_string)`
    or the `.value` property, but callers should prefer the context
    manager pattern to guarantee cleanup.
    """

    def __init__(self, value: str):
        if value is None:
            self._value: str | None = None
            self._scrubbed = True
        else:
            self._value = value
            self._scrubbed = False

    # --- context manager ---------------------------------------------------

    def __enter__(self) -> "SecureString":
        if self._scrubbed:
            raise RuntimeError("SecureString has already been scrubbed")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.scrub()
        return None  # do not suppress exceptions

    # --- value access ------------------------------------------------------

    @property
    def value(self) -> str | None:
        """Return the raw credential string (None after scrubbing)."""
        if self._scrubbed:
            return None
        return self._value

    def __str__(self) -> str:
        if self._scrubbed:
            return "<scrubbed>"
        return self._value if self._value is not None else ""

    def __repr__(self) -> str:
        if self._scrubbed:
            return "SecureString(<scrubbed>)"
        return "SecureString(***)"

    def __bool__(self) -> bool:
        """True if the SecureString holds a non-None, non-scrubbed value."""
        return not self._scrubbed and self._value is not None

    def __eq__(self, other) -> bool:
        if isinstance(other, SecureString):
            return self._value == other._value
        if isinstance(other, str):
            return self._value == other
        return NotImplemented

    # --- cleanup -----------------------------------------------------------

    def scrub(self) -> None:
        """Zero the credential in memory and mark as scrubbed."""
        if self._scrubbed:
            return
        if self._value is not None:
            secure_zero(self._value)
        self._value = None
        self._scrubbed = True

    @property
    def is_scrubbed(self) -> bool:
        return self._scrubbed
