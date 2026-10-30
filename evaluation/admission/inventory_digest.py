"""Bounded pure SHA256 values; reads, expectations and validity stay live."""
from functools import lru_cache
import hashlib
from types import BuiltinFunctionType

try:
    from _hashlib import openssl_sha256 as _SHA256
except ImportError:
    _SHA256 = None


@lru_cache(maxsize=512, typed=True)
def _hexdigest(data, sha256):
    return sha256(data).hexdigest()


@lru_cache(maxsize=64, typed=True)
def _large_hexdigest(data, sha256):
    # Keep repeated large source/corpus values out of the small-file working set.
    # The public guard admits at most1MiB per immutable key (at most64MiB here).
    return sha256(data).hexdigest()


def hexdigest(data):
    sha256 = hashlib.sha256
    # Substituted callables may be stateful, unhashable or equality-colliding.
    # Preserve their actual result and exception on every call.
    if type(data) is bytes and sha256 is _SHA256 and type(_SHA256) is BuiltinFunctionType:
        if 65536 < len(data) <= 1048576:
            return _large_hexdigest(data, sha256)
        return _hexdigest(data, sha256)
    return sha256(data).hexdigest()
