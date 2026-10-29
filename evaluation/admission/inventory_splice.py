"""Cache only bounded immutable splice results; validation stays in the caller."""
from functools import lru_cache


@lru_cache(maxsize=2048, typed=True)
def _splice(data, start, end, old):
    return data[:start] + old.encode() + data[end:]


def splice(data, start, end, old):
    # Exact immutable values cannot run slicing, comparison or encode callbacks.
    # ASCII also excludes stateful Unicode error-handler behavior. A valid range
    # makes the bound include input bytes, result bytes and 4 bytes per str char.
    if (type(data) is bytes and type(start) is int and type(end) is int
            and type(old) is str and old.isascii()
            and 0 <= start <= end <= len(data)
            and 2 * len(data) - (end - start) + 5 * len(old) <= 131072):
        return _splice(data, start, end, old)
    return data[:start] + old.encode() + data[end:]
