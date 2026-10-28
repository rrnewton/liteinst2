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
