"""Strict limiter setup record; successful exec/application remains external."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import importlib.util
import os
from pathlib import Path
import re

# An explicit sibling path prevents a same-named module elsewhere on sys.path
# from supplying the command identity. The enclosing recipe pins both sources.
_path = Path(__file__).resolve().with_name('process_timing.py')
_spec = importlib.util.spec_from_file_location('_limit_record_process_timing', _path)
assert _spec is not None and _spec.loader is not None
_timing = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_timing)

FIELDS = ('token', 'pid', 'argc', 'argv_bytes', 'argv_fnv1a64', 'fsize_soft', 'fsize_hard')
CAP = 1048576
U64 = (1 << 64)-1
SCOPE = ('Limiter setup record only; this does not establish exec or application success, '
    'the prior inherited limits, file ownership, or process-tree closure. The caller must '
    'join the actual timer child/wait PID, exact request and APP argv/source/ELF custody, '
    'application exit and functional output. FNV1a64 is integrity only, not cryptographic identity.')


def _argv(argv):
    assert type(argv) is list and 0 < len(argv) <= CAP
    assert all(type(word) is str and '\0' not in word for word in argv)
    assert argv[0].startswith('/')
    count, value = 0, 14695981039346656037
    for word in argv:
        # Bound encoding work too; every valid Linux filesystem character uses
        # at least one byte. Empty arguments still contribute their own NUL.
        assert len(word) < CAP
        try:
            raw = os.fsencode(word)
        except UnicodeError:
            raise AssertionError('argv is not filesystem encodable') from None
        assert b'\0' not in raw
        count += len(raw)+1
        assert count <= CAP
        for byte in raw+b'\0':
            value = ((value ^ byte)*1099511628211) & U64
    return count, value


def check(data, app_argv, expected_pid):
    assert type(expected_pid) is int and 0 < expected_pid < (1 << 31)
    assert type(data) is bytes and 0 < len(data) <= 511 and data.endswith(b'\n')
    assert all(32 <= byte <= 126 for byte in data[:-1])
    words = data[:-1].decode('ascii').split(' ')
    assert len(words) == len(FIELDS)+1 and words[0] == 'limit-exec-v1'
    count, fingerprint = _argv(app_argv)
    expected_token = _timing.token(app_argv)
    row = {}
    for name, word in zip(FIELDS, words[1:]):
        assert word.startswith(name+'=')
        value = word[len(name)+1:]
        if name == 'token':
            assert re.fullmatch('[0-9a-f]{64}', value) and value == expected_token
        else:
            assert re.fullmatch(r'0|[1-9][0-9]{0,19}', value)
            value = int(value)
            assert value <= U64
        row[name] = value
    assert row['pid'] == expected_pid
    assert row['argc'] == len(app_argv)
    assert (row['argv_bytes'], row['argv_fnv1a64']) == (count, fingerprint)
    assert row['fsize_soft'] == row['fsize_hard'] == CAP
    return dict(status='SETUP_RECORD_VALIDATED', **row, scope=SCOPE)
