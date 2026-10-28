"""Fabricated limiter record controls; no limiter, exec or native run."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import functools
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import types
import unittest


def local(name):
    path = Path(__file__).resolve().with_name('limit_record.py')
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


parser = local('_tested_limit_record')
FIELDS = ('token', 'pid', 'argc', 'argv_bytes', 'argv_fnv1a64', 'fsize_soft', 'fsize_hard')
ARGV = ['/app', 'one']
RAW = b'/app\0one\0'
JSON = b'["/app","one"]'


def reference(raw):
    # Test-side arithmetic over declared raw vectors, independent of argv
    # encoding/token helpers. Standard published FNV vectors anchor it below.
    return functools.reduce(lambda h, byte: ((h ^ byte)*0x100000001b3) % (1 << 64),
        raw, 0xcbf29ce484222325)


def fixture(argv=ARGV, raw=RAW, canonical=JSON, pid=124):
    return dict(token=hashlib.sha256(canonical).hexdigest(), pid=pid, argc=len(argv),
        argv_bytes=len(raw), argv_fnv1a64=reference(raw), fsize_soft=1048576, fsize_hard=1048576)


def encode(row):
    return ('limit-exec-v1 '+' '.join(name+'='+str(row[name]) for name in FIELDS)+'\n').encode('ascii')


class Controls(unittest.TestCase):
    def refuse(self, row, argv=ARGV, pid=124):
        with self.assertRaises(AssertionError): parser.check(encode(row), argv, pid)

    def test_complete_record_and_independent_arg_bytes(self):
        self.assertEqual(reference(b''), 0xcbf29ce484222325)
        self.assertEqual(reference(b'a'), 0xaf63dc4c8601ec8c)
        self.assertEqual(reference(b'foobar'), 0x85944171f73967e8)
        expected = fixture(); got = parser.check(encode(expected), ARGV, 124)
        self.assertEqual({k: got[k] for k in FIELDS}, expected)
        self.assertEqual(got['status'], 'SETUP_RECORD_VALIDATED')
        self.assertIn('does not establish exec', got['scope'])
        self.assertIn('not cryptographic identity', got['scope'])
        self.assertEqual((got['argc'], got['argv_bytes']), (2, 9))
        # A setup record can precede exec failure127; no success predicate is invented.
        self.assertNotIn('exit', got)
        self.assertNotIn('application_success', got)
        for pid in (1, (1 << 31)-1):
            row = fixture(pid=pid)
            self.assertEqual(parser.check(encode(row), ARGV, pid)['pid'], pid)

    def test_exact_argv_token_pid_and_fingerprint_identity(self):
        for key, value in (('token', '0'*64), ('pid', 125), ('argc', 1), ('argv_bytes', 8),
                ('argv_fnv1a64', fixture()['argv_fnv1a64'] ^ 1)):
            self.refuse(dict(fixture(), **{key: value}))
        other = ['/app', 'two']
        self.refuse(fixture(), other)
        self.refuse(dict(fixture(), token=hashlib.sha256(b'["/app","two"]').hexdigest()))
        # Raw-byte integrity and canonical JSON token are distinct joins.
        self.refuse(dict(fixture(), token=hashlib.sha256(RAW).hexdigest()))
        self.refuse(dict(fixture(), argv_fnv1a64=reference(JSON)))
        self.refuse(dict(fixture(), argv_bytes=len(RAW)-2,
            argv_fnv1a64=reference(RAW.replace(b'\0', b''))))
        for raw in (b'/app\0one', b'one\0/app\0', b'/appone\0'):
            self.refuse(dict(fixture(), argv_bytes=len(raw), argv_fnv1a64=reference(raw)))
        for pid in (0, -1, (1 << 31), True, 124.0, '124', None):
            self.refuse(fixture(), pid=pid)

    def test_all_fields_and_canonical_domains(self):
        good = encode(fixture()); words = good[:-1].split(b' ')
        for i in range(len(words)):
            for bad in (words[:i]+words[i+1:], words[:i]+[words[i]]+words[i:],
                    words[:i]+[words[i]+b'!']+words[i+1:]):
                with self.assertRaises(AssertionError): parser.check(b' '.join(bad)+b'\n', ARGV, 124)
        for i in range(1, len(words)-1):
            bad = list(words); bad[i], bad[i+1] = bad[i+1], bad[i]
            with self.assertRaises(AssertionError): parser.check(b' '.join(bad)+b'\n', ARGV, 124)
        for key in FIELDS[1:]:
            for value in ('', '-1', '-0', '+1', '00', '01', '1.0', '1e0', 'true', ' 1', '1 ',
                    str(1 << 64), '9'*21):
                self.refuse(dict(fixture(), **{key: value}))
        for token in ('', fixture()['token'].upper(), '0'*63, '0'*65, 'g'*64):
            self.refuse(dict(fixture(), token=token))
        for key in ('pid', 'argc', 'argv_bytes'):
            self.refuse(dict(fixture(), **{key: 0}))
        self.refuse(dict(fixture(), pid=1 << 31))

    def test_raw_argv_empty_unicode_newline_nul_and_encoding(self):
        vectors = [(['/app'], b'/app\0', b'["/app"]'),
            (['/app', ''], b'/app\0\0', b'["/app",""]'),
            (['/app', 'line\nbreak'], b'/app\0line\nbreak\0', b'["/app","line\\nbreak"]'),
            (['/app', '\u00e9', '\u96ea'], b'/app\0\xc3\xa9\0\xe9\x9b\xaa\0', b'["/app","\\u00e9","\\u96ea"]'),
            (['/\u00e9', 'a\n'], b'/\xc3\xa9\0a\n\0', b'["/\\u00e9","a\\n"]'),
            (['/app', '\udcff'], b'/app\0\xff\0', b'["/app","\\udcff"]')]
        for argv, raw, canonical in vectors:
            row = fixture(argv, raw, canonical)
            got = parser.check(encode(row), argv, 124)
            self.assertEqual({k: got[k] for k in FIELDS}, row)
        # Equal non-NUL concatenation does not identify argument boundaries.
        a = fixture(['/app', 'a', 'b'], b'/app\0a\0b\0', b'["/app","a","b"]')
        b = fixture(['/app', 'ab'], b'/app\0ab\0', b'["/app","ab"]')
        self.assertNotEqual(a['argv_fnv1a64'], b['argv_fnv1a64'])
        self.refuse(a, ['/app', 'ab'])
        self.refuse(b, ['/app', 'a', 'b'])
        for argv in ([], (), tuple(ARGV), '/app', None, [b'/app'], [Path('/app')],
                ['/app', 1], ['/app', True], [''], ['relative'], ['/app\0evil'],
                ['/app', 'bad\0arg'], ['/app', '\ud800']):
            self.refuse(fixture(), argv)

    def test_complete_ascii_lf_framing_and_bound(self):
        good = encode(fixture())
        for bad in (b'', good[:-1], good+b'\n', b'\n'+good, good+b'extra\n',
                good.replace(b'\n', b'\r\n'), good+good, b'x'*512,
                bytearray(good), memoryview(good), good.decode(), None):
            with self.assertRaises(AssertionError): parser.check(bad, ARGV, 124)
        for at in (0, good.index(b' '), good.index(b'pid='), len(good)-1):
            for separator in (b'\r', b'\v', b'\f', b'\x1c', b'\x1d', b'\x1e', b'\x00', b'\t', b'\xff', b'\n'):
                if at == len(good)-1 and separator == b'\n': continue
                with self.assertRaises(AssertionError): parser.check(good[:at]+separator+good[at+1:], ARGV, 124)
        with self.assertRaises(AssertionError): parser.check(good.replace(b' ', b'  ', 1), ARGV, 124)

    def test_exact_fsize_and_argv_byte_cap(self):
        for soft, hard in ((0, 1048576), (1048575, 1048576), (1048576, 1048575),
                (1048577, 1048576), (1048576, 1048577), (1048577, 1048577), ((1 << 64)-1, (1 << 64)-1)):
            self.refuse(dict(fixture(), fsize_soft=soft, fsize_hard=hard))
        word = '/'+'a'*(1048576-2)
        raw = word.encode('ascii')+b'\0'; canonical = b'["'+word.encode('ascii')+b'"]'
        row = fixture([word], raw, canonical)
        self.assertEqual(parser.check(encode(row), [word], 124)['argv_bytes'], 1048576)
        # One additional empty argument is one extra byte; it must not be dropped.
        over = fixture([word, ''], raw+b'\0', canonical[:-1]+b',""]')
        self.refuse(over, [word, ''])
        self.refuse(fixture(), ['/app', 'x'*1048576])

    def test_explicit_local_token_import_and_optimized_entrypoints(self):
        expected = Path(__file__).resolve().with_name('process_timing.py')
        self.assertEqual(Path(parser._timing.__file__).resolve(), expected)
        # An already-imported lookalike cannot replace the actual sibling helper.
        names = ('process_timing', '_limit_record_process_timing')
        missing = object(); saved = {n: sys.modules.get(n, missing) for n in names}
        fake = types.ModuleType('process_timing'); fake.token = lambda argv: '0'*64
        try:
            for name in names: sys.modules[name] = fake
            isolated = local('_isolated_limit_record')
            self.assertEqual(isolated.check(encode(fixture()), ARGV, 124)['token'], fixture()['token'])
            self.assertEqual(Path(isolated._timing.__file__).resolve(), expected)
        finally:
            for name, value in saved.items():
                if value is missing: sys.modules.pop(name, None)
                else: sys.modules[name] = value
        for name in ('limit_record.py', Path(__file__).name):
            path = str(Path(__file__).with_name(name))
            for tail in ([path], ['-c', 'import runpy,sys; runpy.run_path(sys.argv[1])', path]):
                process = subprocess.run([sys.executable, '-B', '-O', *tail], capture_output=True,
                    timeout=5, check=False)
                self.assertEqual((process.returncode, process.stdout, process.stderr),
                    (1, b'', b'assertions required\n'))


if __name__ == '__main__':
    unittest.main()
