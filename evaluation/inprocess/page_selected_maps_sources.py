"""Exact static-source inverses for the maintained-default rollout.

Only explicit source-roster gates call historical(). Actual pin/fact functions,
compiled inputs, retained executions and receipt/capture comparisons stay exact.
Reconstructed bytes are never imported, executed, compiled or written to disk.
"""
import hashlib
import json
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[2]
DATA = Path(__file__).with_suffix('.json')
DATA_FACT = {'bytes': 33446, 'sha256': 'edfc1ef5b7f7d6d16530ffbba911aa12a29f849bc1d8df86b3745c0f8091d0e6'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def byte_fact(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def bind(pin):
    """Retain the actual shared adapter/table in the caller's ordinary closure."""
    pin(Path(__file__).resolve())
    path = pin(DATA)
    need(byte_fact(path.read_bytes()) == DATA_FACT, 'whole source-owned maps inverse table')


def inverse(raw, spans, expected):
    lines = raw.decode('utf-8').splitlines(keepends=True)
    need(type(spans) is list, 'explicit source inverse spans')
    at = 0; result = []
    for span in spans:
        need(type(span) is list and len(span) == 3, 'one whole source inverse span')
        first, end, text = span
        need(type(first) is int and type(end) is int and type(text) is str and
             at <= first <= end <= len(lines) and ''.join(lines[first:end]) != text,
             'ordered bounded nonempty source edit; no ignored bytes')
        result.extend(lines[at:first]); result.append(text); at = end
    result.extend(lines[at:])
    raw = ''.join(result).encode('utf-8')
    need(byte_fact(raw) == expected, 'whole exact original source endpoint')
    return raw


def historical(path, expected, observed):
    """Return a checked historical fact only for the listed static source target.

The returned comparison fact is not an actual-input fact. The caller records
observed bytes normally and retains its original expected dictionary unchanged.
Unknown paths/targets do not acquire an inverse or an acceptance exemption.
"""
    path = Path(path).resolve(strict=True)
    need(type(expected) is dict and type(observed) is dict and
         all(k in expected and k in observed for k in ('bytes', 'sha256')),
         'complete original and actual source facts')
    want = {k: expected[k] for k in ('bytes', 'sha256')}
    actual = {k: observed[k] for k in ('bytes', 'sha256')}
    raw = path.read_bytes()
    need(byte_fact(raw) == actual, 'actual source bytes match the ordinary recorded fact')
    if 'mode' in observed:
        mode = observed['mode']
        need(type(mode) in (int, str) and
             (int(mode, 8) if type(mode) is str else mode) == stat.S_IMODE(path.stat().st_mode),
             'actual source mode remains exact')
    if actual == want:
        return dict(observed)
    need(path.is_relative_to(ROOT), 'source inverse never applies outside the checkout')
    data = DATA.read_bytes()
    need(byte_fact(data) == DATA_FACT, 'whole source-owned maps inverse table')
    table = json.loads(data)
    need(set(table) == {'schema', 'profile', 'sources'} and table['schema'] == 1 and
         table['profile'] == 'maps-default-source-inverses-v1', 'exact inverse table domain')
    row = table['sources'].get(str(path.relative_to(ROOT)))
    if row is None:
        return dict(observed)  # The original caller comparison still rejects a mismatch.
    need(actual == row['current'], 'one exact installed source successor; no mixed versions')
    target = row['targets'].get(want['sha256'])
    need(target is not None and target['fact'] == want, 'one unchanged original source target')
    donor = inverse(raw, row['inverse'], row['donor'])
    original = inverse(donor, target['inverse'], want)
    return dict(observed, **byte_fact(original))
