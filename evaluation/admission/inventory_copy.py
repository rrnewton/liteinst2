"""Fresh copies of exact plain JSON trees; all other deepcopy behavior stays live."""
import builtins
import copy
import marshal
from types import BuiltinFunctionType, FunctionType

try:
    from _hashlib import openssl_sha256 as _sha256
except ImportError:
    _sha256 = None

# Only this independently source-bound stdlib implementation is eligible.
# An unknown Python build or substituted implementation uses its live deepcopy.
_CODE_SHA256 = {
    'deepcopy': 'fcd4f553ffcf5a93e23c1da489df6bd052331c70a7ba571b1a04080756d8855c',
    '_deepcopy_list': 'e4e90e8adb5326c97a3f6bc5f32e24f760b09e8340541523ad33cca94548a06f',
    '_deepcopy_dict': 'd81ecdbec53a4852a37e68f6707a88b127b84c7ea0fbd51e50f39e8c7026a913',
    '_deepcopy_atomic': '74c2ce527e2ac56c50d222baf14809449cb79ae1e8f3935840789739721f2e80',
    '_keep_alive': 'ea259226c156762c95e1c761a762a66b7c9f6e15be3e60421682a87fc1364922',
}


def _authority():
    if type(_sha256) is not BuiltinFunctionType:
        return ()
    try:
        # These defaults retain the original constructor even if the mutable
        # copy.deepcopy attribute was replaced before this module imported.
        list_fn = getattr(copy, '_deepcopy_list', None)
        dict_fn = getattr(copy, '_deepcopy_dict', None)
        if type(list_fn) is not FunctionType or type(dict_fn) is not FunctionType:
            return ()
        for fn in (list_fn, dict_fn):
            if type(fn.__defaults__) is not tuple or len(fn.__defaults__) != 1:
                return ()
        original = list_fn.__defaults__[0]
        if type(original) is not FunctionType or dict_fn.__defaults__[0] is not original:
            return ()
        for name in ('_deepcopy_atomic', '_keep_alive'):
            if type(getattr(copy, name, None)) is not FunctionType:
                return ()
        defaults = original.__defaults__
        if (type(defaults) is not tuple or len(defaults) != 2 or defaults[0] is not None
                or type(defaults[1]) is not list or len(defaults[1]) != 0
                or len(copy._deepcopy_list.__defaults__) != 1
                or len(copy._deepcopy_dict.__defaults__) != 1
                or copy._deepcopy_atomic.__defaults__ is not None
                or copy._keep_alive.__defaults__ is not None):
            return ()
        functions = dict((name, original if name == 'deepcopy' else getattr(copy, name))
                         for name in _CODE_SHA256)
        for name, fn in functions.items():
            if (type(fn) is not FunctionType or fn.__globals__ is not vars(copy)
                    or _sha256(marshal.dumps(fn.__code__)).hexdigest() != _CODE_SHA256[name]):
                return ()
        return tuple((name, fn, fn.__code__, fn.__defaults__) for name, fn in functions.items())
    except (AttributeError, IndexError, TypeError, ValueError):
        return ()


_AUTHORITY = _authority()
_SCALARS = (str, int, float, bool, type(None))
_BUILTINS = (('id', id), ('type', type), ('KeyError', KeyError))


def _eligible():
    if not _AUTHORITY or type(getattr(copy, '_deepcopy_dispatch', None)) is not dict:
        return False
    if (getattr(copy, '__builtins__', None) is not vars(builtins)
            or any(name in vars(copy) or getattr(builtins, name) is not value
                   for name, value in _BUILTINS)):
        return False
    for name, fn, code, defaults in _AUTHORITY:
        if (getattr(copy, name, None) is not fn or fn.__code__ is not code
                or fn.__defaults__ is not defaults):
            return False
    return (copy._deepcopy_dispatch.get(list) is copy._deepcopy_list
            and copy._deepcopy_dispatch.get(dict) is copy._deepcopy_dict
            and all(copy._deepcopy_dispatch.get(cls) is copy._deepcopy_atomic for cls in _SCALARS))


class _NotPlain(Exception):
    pass


def _tree(value, seen, depth):
    cls = type(value)
    if cls is str or cls is int or cls is float or cls is bool or cls is type(None):
        return value
    if (cls is not dict and cls is not list) or depth >= 32 or id(value) in seen:
        raise _NotPlain
    seen.add(id(value))
    if cls is list:
        return [_tree(child, seen, depth + 1) for child in value]
    result = {}
    for key, child in value.items():
        if type(key) is not str:
            raise _NotPlain
        result[key] = _tree(child, seen, depth + 1)
    return result


def deepcopy(value):
    """Never cache inputs, results, validity or expected values."""
    if _eligible():
        try:
            return _tree(value, set(), 0)
        except _NotPlain:
            pass
    return copy.deepcopy(value)
