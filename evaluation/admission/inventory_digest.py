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


def hexdigest(data):
    sha256 = hashlib.sha256
    # Substituted callables may be stateful, unhashable or equality-colliding.
    # Preserve their actual result and exception on every call.
    if type(data) is bytes and sha256 is _SHA256 and type(_SHA256) is BuiltinFunctionType:
        return _hexdigest(data, sha256)
    return sha256(data).hexdigest()
