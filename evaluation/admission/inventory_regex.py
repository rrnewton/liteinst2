"""Bounded native regex values; compiler calls, source reads and checks stay live."""
import builtins
import marshal
import re
import sys
from threading import RLock
from types import BuiltinFunctionType, FunctionType, MethodDescriptorType, ModuleType

try:
    from _hashlib import openssl_sha256 as _SHA
except ImportError:
    _SHA = None

_TYPE, _STR, _INT = ().__class__.__class__, ''.__class__, (0).__class__
_TUPLE, _LIST, _DICT = ().__class__, [].__class__, {}.__class__
_ID, _LEN, _ALL, _SUM = id, len, all, sum
_SIZE, _MARSHAL = sys.getsizeof, marshal.dumps
_CODE_SHA = '3d3ecb131191bec43208412e15240ecd21beb05090c19eacb5fd7c8573c7bb0f'
_LIMIT, _ENTRIES, _TOTAL = 1048576, 256, 32 * 1048576
_CACHE = {}
_CACHE_BYTES = 0
_LOCK = RLock()
_MISSING = object()


def _builtin(value, module, name):
    return (_TYPE(value) is BuiltinFunctionType and
            _TYPE(value.__module__) is _STR and _TYPE(value.__name__) is _STR and
            value.__module__ == module and value.__name__ == name)


def _defaults(fn):
    value = fn.__defaults__
    return (_TYPE(value) is _TUPLE and _LEN(value) == 1 and
            _TYPE(value[0]) is _INT and value[0] == 0 and
            fn.__kwdefaults__ is None and fn.__closure__ is None)


def _authority():
    # Unknown interpreter/provider implementations simply retain the live call.
    if (_TYPE(re) is not ModuleType or
            not _builtin(_SHA, '_hashlib', 'openssl_sha256') or
            not _builtin(_MARSHAL, 'marshal', 'dumps') or
            not _builtin(_ID, 'builtins', 'id') or
            not _builtin(_LEN, 'builtins', 'len') or
            not _builtin(_ALL, 'builtins', 'all') or
            not _builtin(_SUM, 'builtins', 'sum') or
            not _builtin(_SIZE, 'sys', 'getsizeof')):
        return None
    namespace = re.__dict__
    fn, pattern = namespace.get('findall'), namespace.get('Pattern')
    if (_TYPE(fn) is not FunctionType or fn.__globals__ is not namespace or
            fn.__builtins__ is not builtins.__dict__ or not _defaults(fn) or
            _SHA(_MARSHAL(fn.__code__)).hexdigest() != _CODE_SHA or
            _TYPE(pattern) is not _TYPE or not (pattern.__flags__ & (1 << 8)) or
            _TYPE(pattern.__name__) is not _STR or pattern.__name__ != 'Pattern' or
            _TYPE(pattern.__module__) is not _STR or pattern.__module__ != 're'):
        return None
    method = pattern.__dict__.get('findall')
    if (_TYPE(method) is not MethodDescriptorType or method.__objclass__ is not pattern or
            method.__name__ != 'findall'):
        return None
    return fn, fn.__code__, namespace, fn.__builtins__, pattern, method


_AUTHORITY = _authority()


def _eligible(provider):
    if _AUTHORITY is None or provider is not _AUTHORITY[0]:
        return False
    return (provider.__code__ is _AUTHORITY[1] and
            provider.__globals__ is _AUTHORITY[2] and
            provider.__builtins__ is _AUTHORITY[3] and _defaults(provider))


def _fresh(rows):
    # Native findall's outer list and multi-group tuples are fresh each time.
    return [_TUPLE(item for item in row) if _TYPE(row) is _TUPLE else row for row in rows]


def _frozen(result):
    if _TYPE(result) is not _LIST:
        return None
    rows = []
    size = 0
    for row in result:
        if _TYPE(row) is _STR:
            size += _SIZE(row)
        elif _TYPE(row) is _TUPLE and _ALL(_TYPE(item) is _STR for item in row):
            size += _SIZE(row) + _SUM(_SIZE(item) for item in row)
        else:
            return None
        rows.append(row)
        if size > 2 * _LIMIT:
            return None
    frozen = _TUPLE(rows)
    return frozen, size + _SIZE(frozen)


def with_findall(provider, pattern, text):
    """Exactly the caller's two-argument findall, with live compilation once.

    Only the known Python dispatch is factored. Its actual current _compile
    runs even on a cache hit; foreign compiler results dispatch once directly.
    Keys retain native pattern identity and exact immutable text, never paths,
    expectations, compiler state or validation outcomes.
    """
    global _CACHE_BYTES
    if (not _eligible(provider) or _TYPE(pattern) is not _STR or
            _TYPE(text) is not _STR or _LEN(pattern) > 4096 or _LEN(text) > _LIMIT):
        return provider(pattern, text)
    compile_now = _AUTHORITY[2].get('_compile', _MISSING)
    if compile_now is _MISSING:
        # Preserve original global-then-builtin lookup, including NameError.
        return provider(pattern, text)
    compiled = compile_now(pattern, 0)
    if (_TYPE(compiled) is not _AUTHORITY[4] or _TYPE(compiled.pattern) is not _STR):
        return compiled.findall(text)
    key = (_ID(compiled), text)
    with _LOCK:
        found = _CACHE.get(key)
        if found is not None and found[0] is compiled:
            return _fresh(found[1])
    result = _AUTHORITY[5](compiled, text)
    saved = _frozen(result)
    if saved is None:
        return result
    frozen, result_size = saved
    size = (_SIZE(compiled) + _SIZE(compiled.pattern) + _SIZE(text) +
            _SIZE(key) + result_size + 256)
    if size > 2 * _LIMIT:
        return result
    with _LOCK:
        if key not in _CACHE:
            while _CACHE and (_LEN(_CACHE) >= _ENTRIES or _CACHE_BYTES + size > _TOTAL):
                for first in _CACHE:
                    break
                _CACHE_BYTES -= _CACHE.pop(first)[2]
            _CACHE[key] = (compiled, frozen, size)
            _CACHE_BYTES += size
    return result
