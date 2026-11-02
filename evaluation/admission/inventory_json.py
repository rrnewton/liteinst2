"""Bounded canonical bytes for exact builtin values; all validation stays live.

A fresh refusing C Pickler supplies a complete, type-preserving value key. It
only decodes its own literal-data key to a private snapshot; foreign reduction,
buffer, global lookup and persistent-ID protocols are refused. Only successful
source-bound JSON encodings enter the cache. Unknown providers or dependencies
execute the caller's original JSON operation, including its exceptions.
"""
import _codecs
import _json
import _pickle
import builtins
from collections import OrderedDict
import io
import json
import marshal
import sys
from threading import RLock
from types import BuiltinFunctionType, FunctionType, ModuleType, MemberDescriptorType, WrapperDescriptorType, GetSetDescriptorType

try:
    from _hashlib import openssl_sha256 as _sha256
except ImportError:
    _sha256 = None

_TYPE, _VARS = type, vars
_LIMIT = 1048576
_ENTRIES = 128
_TOTAL_LIMIT = 32 * 1048576
_CACHE = OrderedDict()
_CACHE_BYTES = 0
_CACHE_LOCK = RLock()
_STATS = dict(hits=0, misses=0, bypasses=0, evictions=0)
_GET_DIGITS = _VARS(sys).get('get_int_max_str_digits')
_GET_RECURSION = _VARS(sys).get('getrecursionlimit')
_LOOKUP_ERROR = _VARS(_codecs).get('lookup_error')
_PICKLER, _UNPICKLER = _VARS(_pickle).get('Pickler'), _VARS(_pickle).get('Unpickler')
_BYTES_IO, _MARSHAL_DUMPS = _VARS(io).get('BytesIO'), _VARS(marshal).get('dumps')
_ENCODER_MODULE = _VARS(json).get('encoder')
_CODES = {
    'dumps': '8e33c299c27674d4eed9916059120ae6c88124eac48d666f7801130bb393a1ff',
    '__init__': '11e605eda0983ee87021bd3d8e4124198c0c9ace87265089e89de81a0c8136b9',
    'default': '8626201f8da4554c786d48b43b0fa26b7b19f380dfc56fedea89b50d146c02ba',
    'encode': 'b13cbd70686b9c13cedd1ddddc48f9cd4d6c38a8372303993a7159a2c8713dbe',
    'iterencode': '758fddebc81772aa3d97699ffc35bc01c8c623a0de0e3a900f864dc3c994e1b2',
}
_OPTIONS = {'skipkeys': False, 'ensure_ascii': True, 'check_circular': True,
            'allow_nan': True, 'sort_keys': False, 'indent': None,
            'separators': None, 'default': None}
_BUILTINS = {name: _VARS(builtins)[name] for name in
             ('isinstance', 'str', 'list', 'tuple', 'float', 'TypeError', 'ValueError', 'repr')}
_CLASS_KEYS = {'__module__', '__doc__', '__init__', 'default', 'encode',
               'iterencode', '__dict__', '__weakref__', 'item_separator', 'key_separator'}


def _static_type(value, module, name):
    return (_TYPE(value) is type and bool(value.__flags__ & (1 << 8))
            and _TYPE(value.__module__) is str and _TYPE(value.__name__) is str
            and value.__module__ == module and value.__name__ == name)


def _builtin(value, module, name):
    return (_TYPE(value) is BuiltinFunctionType
            and _TYPE(value.__module__) is str and _TYPE(value.__name__) is str
            and value.__module__ == module and value.__name__ == name)


_KEY_AUTHORITY = (_static_type(_PICKLER, '_pickle', 'Pickler')
                  and _static_type(_UNPICKLER, '_pickle', 'Unpickler')
                  and _static_type(_BYTES_IO, '_io', 'BytesIO'))


def _keywords(actual, expected):
    # Identity avoids bool/int equality or a foreign value's comparison method.
    return (_TYPE(actual) is dict and len(actual) == len(expected)
            and all(_TYPE(k) is str and k in expected and v is expected[k]
                    for k, v in actual.items()))


def _defaults(name, fn):
    if name in ('dumps', '__init__'):
        expected = dict(_OPTIONS)
        if name == 'dumps':
            expected['cls'] = None
        return fn.__defaults__ is None and _keywords(fn.__kwdefaults__, expected)
    expected = (False,) if name == 'iterencode' else None
    actual = fn.__defaults__
    return (fn.__kwdefaults__ is None and
            (actual is None if expected is None else
             _TYPE(actual) is tuple and len(actual) == 1 and actual[0] is False))


def _c_function(value, name):
    return _builtin(value, '_json', name)


def _encoder_type(cls):
    # _json.Encoder is a mutable heap C type. Its native constructor and member
    # descriptors must belong to this exact type; Python lookalikes cannot.
    members = {'markers', 'default', 'encoder', 'indent', 'key_separator',
               'item_separator', 'sort_keys', 'skipkeys'}
    if (_TYPE(cls) is not type or _TYPE(cls.__module__) is not str or _TYPE(cls.__name__) is not str
            or cls.__module__ != '_json' or cls.__name__ != 'Encoder'
            or len(cls.__bases__) != 1 or cls.__bases__[0] is not object
            or set(_VARS(cls)) != members | {'__new__', '__call__', '__doc__', '__module__'}):
        return False
    new, call = _VARS(cls)['__new__'], _VARS(cls)['__call__']
    return (_TYPE(new) is BuiltinFunctionType and new.__name__ == '__new__'
            and new.__self__ is cls and _TYPE(call) is WrapperDescriptorType
            and call.__name__ == '__call__' and call.__objclass__ is cls
            and all(_TYPE(_VARS(cls)[name]) is MemberDescriptorType
                    and _VARS(cls)[name].__name__ == name
                    and _VARS(cls)[name].__objclass__ is cls for name in members))


def _authority():
    """Bind known code once; unknown builds take the unchanged live path."""
    if (not _KEY_AUTHORITY or not _builtin(_sha256, '_hashlib', 'openssl_sha256')
            or not _builtin(_MARSHAL_DUMPS, 'marshal', 'dumps')
            or not _builtin(_GET_DIGITS, 'sys', 'get_int_max_str_digits')
            or not _builtin(_GET_RECURSION, 'sys', 'getrecursionlimit')
            or not _builtin(_LOOKUP_ERROR, '_codecs', 'lookup_error') or
            any(_TYPE(m) is not ModuleType for m in (json, _ENCODER_MODULE, _json))):
        return None
    try:
        surrogatepass = _LOOKUP_ERROR('surrogatepass')
        if (_TYPE(surrogatepass) is not BuiltinFunctionType
                or _TYPE(surrogatepass.__name__) is not str or surrogatepass.__name__ != 'surrogatepass'
                or surrogatepass.__module__ is not None or surrogatepass.__self__ is not None):
            return None
        encoder = _ENCODER_MODULE
        cls = _VARS(json).get('JSONEncoder')
        if (_TYPE(cls) is not type or (len(cls.__bases__) != 1 or cls.__bases__[0] is not object)
                or set(_VARS(cls)) != _CLASS_KEYS or _VARS(encoder).get('JSONEncoder') is not cls):
            return None
        fields = _VARS(cls)
        for name, expected in (('item_separator', ', '), ('key_separator', ': ')):
            if _TYPE(fields[name]) is not str or fields[name] != expected:
                return None
        for name in ('__dict__', '__weakref__'):
            descriptor = fields[name]
            if (_TYPE(descriptor) is not GetSetDescriptorType
                    or descriptor.__name__ != name or descriptor.__objclass__ is not cls):
                return None
        functions = []
        for name, digest in _CODES.items():
            fn = _VARS(json).get(name) if name == 'dumps' else _VARS(cls).get(name)
            module = json if name == 'dumps' else encoder
            if (_TYPE(fn) is not FunctionType or fn.__globals__ is not _VARS(module)
                    or fn.__builtins__ is not _VARS(builtins)
                    or not _defaults(name, fn)
                    or _sha256(_MARSHAL_DUMPS(fn.__code__)).hexdigest() != digest):
                return None
            functions.append((name, fn, fn.__code__, module))
        maker = _VARS(_json).get('make_encoder')
        if not _encoder_type(maker) or _VARS(encoder).get('c_make_encoder') is not maker:
            return None
        strings = []
        for name in ('encode_basestring', 'encode_basestring_ascii'):
            fn = _VARS(_json).get(name)
            if not _c_function(fn, name) or _VARS(encoder).get(name) is not fn:
                return None
            strings.append((name, fn))
        infinity = _VARS(encoder).get('INFINITY')
        if _TYPE(infinity) is not float or infinity != float('inf'):
            return None
        # These are static builtin classes/functions, not lookalike Python objects.
        for name, value in _BUILTINS.items():
            if _TYPE(value) is BuiltinFunctionType:
                if not _builtin(value, 'builtins', name):
                    return None
            elif not _static_type(value, 'builtins', name):
                return None
        return (encoder, cls, tuple(_VARS(cls).items()), tuple(functions), maker, tuple(_VARS(maker).items()),
                tuple(strings), infinity, _GET_DIGITS(), _GET_RECURSION(), surrogatepass)
    except (AttributeError, TypeError, ValueError):
        return None


_AUTHORITY = _authority()


def _make_reference():
    # Captured __new__ still consults the mutable tp_new slot. Authenticate the
    # resulting native object's actual readonly C fields, not that constructor.
    if _AUTHORITY is None:
        return None
    maker, fields, strings = _AUTHORITY[4:7]
    fields = dict(fields)
    markers = {}
    ascii_encoder = dict(strings)['encode_basestring_ascii']
    expected = {'markers': markers, 'default': None, 'encoder': ascii_encoder,
                'indent': None, 'key_separator': ':', 'item_separator': ',',
                'sort_keys': True, 'skipkeys': False}
    try:
        instance = fields['__new__'](maker, markers, None, ascii_encoder,
                                     None, ':', ',', True, False, False)
        if _TYPE(instance) is not maker:
            return None
        for name, value in expected.items():
            if MemberDescriptorType.__get__(fields[name], instance, maker) is not value:
                return None
        return instance, fields['__call__'], markers
    except Exception:
        return None


_REFERENCE = _make_reference()
_REFERENCE_LOCK = RLock()
_REFERENCE_ACTIVE = False
_LITERAL_TYPES = (_TYPE(None), _TYPE(False), _TYPE(0), _TYPE(0.0),
                  _TYPE(''), _TYPE([]), _TYPE(()), _TYPE({}))


def _eligible(dumps):
    if (_AUTHORITY is None or _VARS(_pickle).get('Pickler') is not _PICKLER
            or _VARS(_pickle).get('Unpickler') is not _UNPICKLER
            or _VARS(io).get('BytesIO') is not _BYTES_IO
            or _VARS(marshal).get('dumps') is not _MARSHAL_DUMPS
            or not _builtin(_MARSHAL_DUMPS, 'marshal', 'dumps')
            or not _builtin(_GET_DIGITS, 'sys', 'get_int_max_str_digits')
            or not _builtin(_GET_RECURSION, 'sys', 'getrecursionlimit')
            or not _builtin(_LOOKUP_ERROR, '_codecs', 'lookup_error')):
        return False
    encoder, cls, fields, functions, maker, maker_fields, strings, infinity, digits, recursion, surrogatepass = _AUTHORITY
    # Foreign/stateful callers are tested by identity before inspecting values.
    if dumps is not functions[0][1]:
        return False
    if (_TYPE(json) is not ModuleType or _TYPE(encoder) is not ModuleType
            or _TYPE(_json) is not ModuleType or _VARS(json).get('encoder') is not encoder
            or _VARS(json).get('JSONEncoder') is not cls
            or _VARS(encoder).get('JSONEncoder') is not cls
            or (len(cls.__bases__) != 1 or cls.__bases__[0] is not object) or len(_VARS(cls)) != len(fields)
            or any(_VARS(cls).get(k) is not v for k, v in fields)):
        return False
    for name, fn, code, module in functions:
        current = _VARS(module).get(name) if name == 'dumps' else _VARS(cls).get(name)
        if current is not fn or fn.__code__ is not code or not _defaults(name, fn):
            return False
    for module in (json, encoder):
        if (_VARS(module).get('__builtins__') is not _VARS(builtins)
                or any(name in _VARS(module) or _VARS(builtins).get(name) is not value
                       for name, value in _BUILTINS.items())):
            return False
    return (_VARS(_json).get('make_encoder') is maker
            and len(_VARS(maker)) == len(maker_fields)
            and all(_VARS(maker).get(k) is v for k, v in maker_fields)
            and _VARS(encoder).get('c_make_encoder') is maker
            and all(_VARS(_json).get(name) is fn and _VARS(encoder).get(name) is fn
                    and _c_function(fn, name)
                    for name, fn in strings)
            and _VARS(encoder).get('INFINITY') is infinity
            and _VARS(sys).get('get_int_max_str_digits') is _GET_DIGITS and _GET_DIGITS() == digits
            and _VARS(sys).get('getrecursionlimit') is _GET_RECURSION and _GET_RECURSION() == recursion
            and _VARS(_codecs).get('lookup_error') is _LOOKUP_ERROR
            and _LOOKUP_ERROR('surrogatepass') is surrogatepass)


class _NotKey(Exception):
    pass


class _LimitedBytes(_BYTES_IO if _KEY_AUTHORITY else object):
    def write(self, data):
        if self.tell() + len(data) > _LIMIT:
            raise _NotKey
        return super().write(data)


class _RefusingPickler(_PICKLER if _KEY_AUTHORITY else object):
    def reducer_override(self, value):
        # C Pickler handles exact builtins before this hook. Foreign/subclass
        # values reach it BEFORE __reduce__, __reduce_ex__ or buffer protocols.
        raise _NotKey


class _LiteralUnpickler(_UNPICKLER if _KEY_AUTHORITY else object):
    def find_class(self, module, name):
        raise _NotKey

    def persistent_load(self, identity):
        raise _NotKey


def _snapshot(key):
    # Only canonical_bytes calls this with complete bytes emitted by _key in
    # this same invocation. No external bytes/buffers or foreign constructors.
    stream = _BYTES_IO(key)
    value = _LiteralUnpickler(stream).load()
    if stream.tell() != len(key):
        raise _NotKey
    return value


def _key(value):
    output = _LimitedBytes()
    try:
        _RefusingPickler(output, protocol=4).dump(value)
        return output.getvalue()
    except Exception:
        # Optional key failure is never acceptance: execute the actual JSON path.
        return None


def _literal_domain(value):
    # This is only optional cache eligibility. Every other value still goes
    # through the original JSON call. 2000 bits fit below every enabled CPython
    # integer-digit limit (at least 640), so temporary limit changes cannot bless
    # a cached success. Finite floats make the unexposed allow_nan bit irrelevant.
    none, boolean, integer, floating, string, sequence, pair, mapping = _LITERAL_TYPES
    active, complete = set(), set()
    stack = [(value, False, False)]
    while stack:
        item, leaving, key = stack.pop()
        kind = _TYPE(item)
        if kind is none or kind is boolean or kind is string:
            continue
        if kind is integer:
            if item.bit_length() > 2000:
                return False
            continue
        if kind is floating:
            if not -1e1000 < item < 1e1000:
                return False
            continue
        if key or kind not in (sequence, pair, mapping):
            return False
        identity = id(item)
        if leaving:
            active.remove(identity)
            complete.add(identity)
            continue
        if identity in active:
            return False
        if identity in complete:
            continue
        active.add(identity)
        stack.append((item, True, False))
        if kind is mapping:
            for k, v in item.items():
                stack.append((v, False, False))
                stack.append((k, False, True))
        else:
            stack.extend((child, False, False) for child in item)
    return True


def _reference_bytes(snapshot):
    # The captured wrapper descriptor invokes its immutable d_wrapped C pointer,
    # not the mutable native type's current __call__/tp_call. All instance fields
    # were read through their original readonly member descriptors at creation.
    global _REFERENCE_ACTIVE
    if _REFERENCE is None or not _literal_domain(snapshot):
        return None
    instance, call, markers = _REFERENCE
    with _REFERENCE_LOCK:
        if _REFERENCE_ACTIVE:
            return None
        _REFERENCE_ACTIVE = True
        try:
            markers.clear()
            return ''.join(call(instance, snapshot, 0)).encode()
        except Exception:
            return None
        finally:
            markers.clear()
            _REFERENCE_ACTIVE = False


def canonical_bytes(value, dumps):
    """The caller still hashes the returned bytes and performs every comparison."""
    global _CACHE_BYTES
    key = _key(value) if _eligible(dumps) else None
    if key is not None and not _eligible(dumps):
        key = None
    with _CACHE_LOCK:
        if key is None:
            _STATS['bypasses'] += 1
        elif key in _CACHE:
            _STATS['hits'] += 1
            _CACHE.move_to_end(key)
            return _CACHE[key]
        else:
            _STATS['misses'] += 1
    snapshot = value
    if key is not None:
        try:
            snapshot = _snapshot(key)
        except Exception:
            key, snapshot = None, value
        if not _eligible(dumps):
            key, snapshot = None, value
    reference = _reference_bytes(snapshot) if key is not None else None
    if reference is None:
        key, snapshot = None, value
    # Always call the actual provider on its original object, exactly once.
    # The independent private reference permits publication only when this
    # result still equals the value represented by the immutable key.
    result = dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if (key is not None and _TYPE(result) is bytes and len(result) <= _LIMIT
            and result == reference and _eligible(dumps)):
        with _CACHE_LOCK:
            prior = _CACHE.pop(key, None)
            if prior is not None:
                _CACHE_BYTES -= len(key) + len(prior)
            _CACHE[key] = result
            _CACHE_BYTES += len(key) + len(result)
            while len(_CACHE) > _ENTRIES or _CACHE_BYTES > _TOTAL_LIMIT:
                old_key, old_value = _CACHE.popitem(last=False)
                _STATS['evictions'] += 1
                _CACHE_BYTES -= len(old_key) + len(old_value)
    return result


def cache_info():
    """Accounting only, never an input to validation or cache eligibility."""
    with _CACHE_LOCK:
        return dict(_STATS, entries=len(_CACHE), bytes=_CACHE_BYTES,
                    max_entries=_ENTRIES, max_bytes=_TOTAL_LIMIT, max_blob=_LIMIT)
