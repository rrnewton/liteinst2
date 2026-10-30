"""Exact recorder354 successor; historical350 remains a separate proof boundary."""
import hashlib
import json
from pathlib import Path
from parsing import require
import core_367_inventory as main367

ROOT = Path(__file__).resolve().parents[2]
RAW = Path(__file__).with_suffix('.json').read_bytes()
require(hashlib.sha256(RAW).hexdigest() == '55e4cdcc53533e6cc2f335b91acbaead6daa6356b787786e50532c9fbda5b453', 'recorder_shards_data_differs')
DATA = json.loads(RAW)
CURRENT = DATA['current_corpus_sha256']
PREVIOUS = DATA['previous_corpus_sha256']
PYTHON_CURRENT = DATA['python_current_sha256']
PYTHON_PREVIOUS = DATA['python_previous_sha256']
RECORDER_TESTS = 354
ADDED = tuple(DATA['added'])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def source_before(path, raw, error):
    row = DATA['sources'][path]
    require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == row['current_sha256'], error)
    last = len(raw)
    for first, end, old in reversed(row['edits']):
        require(type(first) is int and type(end) is int and 0 <= first <= end <= last and type(old) is str, error)
        raw = raw[:first] + old.encode() + raw[end:]
        last = first
    require(hashlib.sha256(raw).hexdigest() == row['previous_sha256'], error)
    return raw


def require_sources(error='recorder_shards_source_differs'):
    for path in DATA['sources']:
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = main367.source_before_evaluation(path, raw, error)
        source_before(path, raw, error)


def before_current(declared, error='recorder_shards_corpus_differs', source_error='recorder_shards_source_differs'):
    declared = main367.peel_current(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT, error)
    require_sources(source_error)
    require(type(declared['recorder_tests']) is int and declared['recorder_tests'] == RECORDER_TESTS, error)
    old = dict(declared, recorder_tests=350)
    require(digest(old) == PREVIOUS, error)
    return old


def peel_current(declared, error, source_error):
    declared = main367.peel_current(declared, error, source_error)
    return before_current(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT else declared


def before_python(identities, error='recorder_shards_python_differs'):
    identities = main367.peel_python(identities, error)
    require(type(identities) is list and all(type(x) is str for x in identities) and
            len(identities) == len(set(identities)) == RECORDER_TESTS and digest(identities) == PYTHON_CURRENT, error)
    require([x for x in identities if x in ADDED] == list(ADDED) and len(ADDED) == 4, error)
    old = [x for x in identities if x not in ADDED]
    require(len(old) == 350 and digest(old) == PYTHON_PREVIOUS, error)
    return old


def peel_python(identities):
    identities = main367.peel_python(identities)
    return before_python(identities) if type(identities) is list and digest(identities) == PYTHON_CURRENT else identities
