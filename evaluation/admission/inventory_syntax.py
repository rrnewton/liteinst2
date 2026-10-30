"""Bounded pure syntax extraction; never cache source validity or expectations."""
import ast
from functools import lru_cache
from io import BytesIO
import tokenize


@lru_cache(maxsize=32, typed=True)
def _assignments(source, parse):
    # Parse the complete source even if the caller requests no assignments.
    tree = parse(source)
    if isinstance(source, bytes):
        encoding, _ = tokenize.detect_encoding(BytesIO(source).readline)
        text = source.decode(encoding)
    else:
        text = source
    return tuple((tuple(target.id for target in node.targets
                        if isinstance(target, ast.Name)),
                  ast.get_source_segment(text, node))
                 for node in tree.body if isinstance(node, ast.Assign))


def assignments(source):
    """Immutable exact assignment sources, in original module order."""
    return _assignments(source, ast.parse)


def literal_values(rows, name):
    # Complete assignment syntax preserves chained targets and expression
    # grammar. Literal evaluation is live and creates fresh mutable values.
    return [ast.literal_eval(ast.parse(source).body[0].value)
            for targets, source in rows if name in targets]


@lru_cache(maxsize=64, typed=True)
def _identities(source, parse):
    return tuple(cls.name + '.' + method.name
                 for cls in parse(source).body if isinstance(cls, ast.ClassDef)
                 for method in cls.body
                 if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and method.name.startswith('test_'))


def identities(source):
    """Immutable class/method identities; the caller supplies the path prefix."""
    return _identities(source, ast.parse)


# This optional cache is separate from the older assignment/identity caches.
# Unknown implementations keep the caller's original parse/walk path.
import _ast
import builtins
import collections
from _collections import deque as _TEST_NAMES_DEQUE
import marshal
import sys
from types import (BuiltinFunctionType, FunctionType, GetSetDescriptorType,
                   MemberDescriptorType, ModuleType, WrapperDescriptorType)

try:
    from _hashlib import openssl_sha256 as _TEST_NAMES_SHA256
except ImportError:
    _TEST_NAMES_SHA256 = None

_TEST_NAMES_CODE_SHA256 = {
    'parse': '59151fc87f0973b7d43944d173752800d1ee514811eb997bb72ba5fb670579d5',
    'walk': '31ca758314d35e6d0c1412c7803745ba158f2e609a17352303708f8ae4ae666f',
    'iter_child_nodes': '66f166d82d2d89c4239fd8510291dac33dd1396e12fab7a9cef008b6820d913d',
    'iter_fields': '0d543a6b29e7bd37cf4bd00459b106c7007ab7f89299525fad29a44a16f78ce6',
}
_TEST_NAMES_TYPE = (0).__class__.__class__


def _test_names_plain_keys(mapping):
    # Exact-dict iteration and type identity do not call a key's hash/equality.
    if _TEST_NAMES_TYPE(mapping) is not {}.__class__:
        return False
    for key in mapping:
        if _TEST_NAMES_TYPE(key) is not ''.__class__:
            return False
    return True


_TEST_NAMES_AST = ast
_TEST_NAMES_AST_DICT = ast.__dict__ if _TEST_NAMES_TYPE(ast) is ModuleType else {}
_TEST_NAMES_GLOBALS = globals()
_TEST_NAMES_BUILTINS_DICT = (builtins.__dict__
                             if _TEST_NAMES_TYPE(builtins) is ModuleType else {})
_TEST_NAMES_COLLECTIONS = collections
_TEST_NAMES_MODULES = (sys.__dict__.get('modules')
                       if _TEST_NAMES_TYPE(sys) is ModuleType
                       and _test_names_plain_keys(sys.__dict__) else None)
_TEST_NAMES_MISSING = object()
_TEST_NAMES_BUILTIN_ROWS = tuple(
    (name, _TEST_NAMES_BUILTINS_DICT.get(name)) for name in (
        'compile', 'isinstance', 'issubclass', 'getattr', 'len', 'vars', 'all', 'any',
        'tuple', 'list', 'dict', 'str', 'bytes', 'bool', 'int', 'type', 'AttributeError',
        '__import__')) if _test_names_plain_keys(_TEST_NAMES_BUILTINS_DICT) else ()
_TEST_NAMES_ISINSTANCE = (_TEST_NAMES_BUILTINS_DICT.get('isinstance')
                          if _test_names_plain_keys(_TEST_NAMES_BUILTINS_DICT) else None)


def _test_names_primitives():
    # Reject module overrides and nonplain keys before any direct lookup.
    for module in (ast, builtins, collections, sys, _ast):
        if _TEST_NAMES_TYPE(module) is not ModuleType:
            return False
    for namespace in (_TEST_NAMES_BUILTINS_DICT, _TEST_NAMES_AST_DICT,
                      _TEST_NAMES_GLOBALS, collections.__dict__,
                      sys.__dict__, _ast.__dict__):
        if not _test_names_plain_keys(namespace):
            return False
    if (ast.__dict__ is not _TEST_NAMES_AST_DICT
            or not _test_names_plain_keys(sys.__dict__.get('modules'))
            or _TEST_NAMES_BUILTINS_DICT.get('type') is not _TEST_NAMES_TYPE):
        return False
    for name, original in _TEST_NAMES_BUILTIN_ROWS:
        if (_TEST_NAMES_BUILTINS_DICT.get(name) is not original
                or name in _TEST_NAMES_AST_DICT or name in _TEST_NAMES_GLOBALS):
            return False
    return (builtins.__dict__ is _TEST_NAMES_BUILTINS_DICT
            and _TEST_NAMES_AST_DICT.get('__builtins__') is _TEST_NAMES_BUILTINS_DICT
            and _TEST_NAMES_GLOBALS.get('__builtins__') is _TEST_NAMES_BUILTINS_DICT)


def _test_names_defaults(name, fn):
    if name != 'parse':
        return fn.__defaults__ is None and fn.__kwdefaults__ is None
    defaults, keywords = fn.__defaults__, fn.__kwdefaults__
    return (type(defaults) is tuple and len(defaults) == 2
            and all(type(value) is str for value in defaults)
            and defaults == ('<unknown>', 'exec')
            and _test_names_plain_keys(keywords) and len(keywords) == 2
            and keywords.get('type_comments', _TEST_NAMES_MISSING) is False
            and keywords.get('feature_version', _TEST_NAMES_MISSING) is None)


def _test_names_fields(cls, name='_fields'):
    # Read inherited schema/field data without invoking a descriptor.
    for base in cls.__mro__:
        attributes = vars(base)
        if name in attributes:
            return attributes[name]
    return _TEST_NAMES_MISSING


def _test_names_authority():
    # A callable captured during import is not, by itself, trusted authority.
    if not _test_names_primitives():
        return ()
    functions = ('compile', 'isinstance', 'issubclass', 'getattr', 'len', 'vars',
                 'all', 'any', '__import__')
    for name, value in _TEST_NAMES_BUILTIN_ROWS:
        if name in functions:
            if (type(value) is not BuiltinFunctionType
                    or type(value.__name__) is not str or value.__name__ != name
                    or type(value.__module__) is not str or value.__module__ != 'builtins'):
                return ()
    for name, expected in (('tuple', ().__class__), ('list', [].__class__),
                           ('dict', {}.__class__), ('str', ''.__class__),
                           ('bytes', b''.__class__), ('bool', True.__class__),
                           ('int', (0).__class__),
                           ('type', _TEST_NAMES_TYPE)):
        if _TEST_NAMES_BUILTINS_DICT.get(name) is not expected:
            return ()
    if (type(_TEST_NAMES_SHA256) is not BuiltinFunctionType
            or type(marshal.dumps) is not BuiltinFunctionType
            or type(collections) is not ModuleType
            or collections.__dict__.get('deque') is not _TEST_NAMES_DEQUE
            or type(sys.modules) is not dict
            or sys.modules.get('collections') is not collections):
        return ()
    functions = []
    for name, expected in _TEST_NAMES_CODE_SHA256.items():
        fn = _TEST_NAMES_AST_DICT.get(name)
        if (type(fn) is not FunctionType or fn.__globals__ is not _TEST_NAMES_AST_DICT
                or fn.__builtins__ is not _TEST_NAMES_BUILTINS_DICT
                or fn.__closure__ is not None or not _test_names_defaults(name, fn)
                or _TEST_NAMES_SHA256(marshal.dumps(fn.__code__)).hexdigest() != expected):
            return ()
        functions.append((name, fn, fn.__code__, fn.__defaults__, fn.__kwdefaults__))
    ast_base = vars(_ast).get('AST')
    if type(ast_base) is not type or _TEST_NAMES_AST_DICT.get('AST') is not ast_base:
        return ()
    classes = []
    for name, cls in vars(_ast).items():
        if type(cls) is not type or not issubclass(cls, ast_base):
            continue
        fields = _test_names_fields(cls)
        if (_TEST_NAMES_AST_DICT.get(name) is not cls or type(fields) is not tuple
                or any(type(field) is not str for field in fields)):
            return ()
        # Field descriptors and attribute hooks, including inherited ones, are
        # traversal dependencies. Never authorize a captured Python callback.
        watched = tuple((field, _test_names_fields(cls, field))
                        for field in fields + ('__getattribute__', '__getattr__'))
        if any(value is not _TEST_NAMES_MISSING and value is not None
               and not any(type(value) is allowed for allowed in
                           (str, int, bool, bytes, WrapperDescriptorType,
                            GetSetDescriptorType, MemberDescriptorType))
               for _, value in watched):
            return ()
        classes.append((name, cls, fields, cls.__bases__, watched))
    if not classes:
        return ()
    flags = tuple((name, vars(_ast).get(name)) for name in
                  ('PyCF_ONLY_AST', 'PyCF_TYPE_COMMENTS'))
    if any(type(value) is not int or type(_TEST_NAMES_AST_DICT.get(name)) is not int
           or _TEST_NAMES_AST_DICT.get(name) != value for name, value in flags):
        return ()
    return tuple(functions), tuple(classes), flags


_TEST_NAMES_AUTHORITY = _test_names_authority()


def _test_names_eligible(source, syntax, caller):
    if not _TEST_NAMES_AUTHORITY or not _test_names_primitives():
        return False
    if (syntax is not _TEST_NAMES_AST or ast is not _TEST_NAMES_AST
            or type(caller) is not tuple or len(caller) != 2
            or not _test_names_plain_keys(caller[0]) or not _test_names_plain_keys(caller[1])
            or caller[1] is not _TEST_NAMES_BUILTINS_DICT
            or type(source) is not bytes or len(source) > 65536
            or sys.modules is not _TEST_NAMES_MODULES
            or type(sys.modules) is not dict
            or sys.modules.get('collections') is not _TEST_NAMES_COLLECTIONS
            or collections is not _TEST_NAMES_COLLECTIONS
            or type(collections) is not ModuleType
            or collections.__dict__.get('deque') is not _TEST_NAMES_DEQUE):
        return False
    classifier = caller[0].get('isinstance', _TEST_NAMES_MISSING)
    if classifier is _TEST_NAMES_MISSING:
        classifier = caller[1].get('isinstance', _TEST_NAMES_MISSING)
    if classifier is not _TEST_NAMES_ISINSTANCE:
        return False
    functions, classes, flags = _TEST_NAMES_AUTHORITY
    for name, fn, code, defaults, keywords in functions:
        if (_TEST_NAMES_AST_DICT.get(name) is not fn or fn.__code__ is not code
                or fn.__defaults__ is not defaults or fn.__kwdefaults__ is not keywords
                or fn.__globals__ is not _TEST_NAMES_AST_DICT
                or fn.__builtins__ is not _TEST_NAMES_BUILTINS_DICT
                or not _test_names_defaults(name, fn)):
            return False
    for name, cls, fields, bases, watched in classes:
        if (vars(_ast).get(name) is not cls or _TEST_NAMES_AST_DICT.get(name) is not cls
                or _test_names_fields(cls) is not fields or cls.__bases__ is not bases):
            return False
        for field, value in watched:
            if _test_names_fields(cls, field) is not value:
                return False
    return all(type(vars(_ast).get(name)) is int and vars(_ast).get(name) == value
               and type(_TEST_NAMES_AST_DICT.get(name)) is int
               and _TEST_NAMES_AST_DICT.get(name) == value for name, value in flags)


@lru_cache(maxsize=8, typed=True)
def _test_names(source):
    tree = ast.parse(source)
    return tuple(node.name for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name.startswith('test_'))


def cached_test_names(source, syntax, caller):
    """Return an immutable tuple only for supported intact syntax; else None.

    The caller retains its original live branch, including its global lookups.
    No source read, expected value, validity result or mutable AST is cached.
    """
    if _test_names_eligible(source, syntax, caller):
        return _test_names(source)
    return None
