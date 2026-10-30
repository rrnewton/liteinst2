#!/usr/bin/env python3
"""Pure source-batch parser and custody controls; no Git or child dispatch."""
import hashlib
from pathlib import Path
import subprocess
import types
import tempfile
import unittest
from unittest import mock
import startup_custody as C


REVISION = '1' * 40


def record(raw):
    prefix = b'blob ' + str(len(raw)).encode('ascii') + b'\0'
    oid = hashlib.sha1(prefix + raw).hexdigest().encode('ascii')
    return oid + b' blob ' + str(len(raw)).encode('ascii') + b'\n' + raw + b'\n'


def parse(raw, bodies, step=None):
    decoder = C.SourceBatch([C.sha(body) for body in bodies])
    if step is None:
        decoder.feed(raw)
    else:
        for at in range(0, len(raw), step):
            decoder.feed(raw[at:at + step])
    decoder.finish()
    return decoder


class BatchParser(unittest.TestCase):
    def test_every_ordered_blob_and_exact_empty_binary_contents_in_small_chunks(self):
        bodies = [b'', b'line\nwith\0binary\xff', bytes(range(256)), b'last']
        wire = b''.join(map(record, bodies))
        for step in (None, 1, 2, 7, 53, 65536):
            decoded = parse(wire, bodies, step)
            self.assertEqual(decoded.index, 4)
            self.assertEqual(decoded.total, sum(map(len, bodies)))
            self.assertEqual(decoded.header, bytearray())

    def test_reordered_duplicate_or_different_committed_contents_refuse(self):
        bodies = [b'first', b'second']
        for wire in (record(b'second') + record(b'first'),
                     record(b'first') + record(b'first'),
                     record(b'FIRST') + record(b'second')):
            with self.subTest(wire=wire), self.assertRaisesRegex(ValueError, 'committed source bytes'):
                parse(wire, bodies)

    def test_git_object_id_is_independently_checked(self):
        raw = b'exact SHA256 content'
        good = record(raw)
        with self.assertRaisesRegex(ValueError, 'committed source bytes'):
            parse(b'0' * 40 + good[40:], [raw])

    def test_missing_nonblob_and_noncanonical_headers_refuse(self):
        oid = b'1' * 40
        bad = [b'revision:path missing\n', oid + b' tree 0\n\n',
               oid + b' commit 0\n\n', oid.upper().replace(b'1', b'A') + b' blob 0\n\n',
               oid + b' blob 00\n\n', oid + b' blob +0\n\n', oid + b' blob -1\n',
               oid + b'  blob 0\n\n', oid + b' blob 0 extra\n\n',
               oid + b' blob 0\r\n\n', b'x' * 97]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse(raw, [b''])

    def test_each_truncated_prefix_wrong_separator_and_trailing_record_refuse(self):
        body = b'payload\nbody'
        wire = record(body)
        for end in range(len(wire)):
            with self.subTest(end=end), self.assertRaisesRegex(ValueError, 'missing/truncated'):
                parse(wire[:end], [body], 1)
        with self.assertRaisesRegex(ValueError, 'terminator'):
            parse(wire[:-1] + b'X', [body])
        for tail in (b'\n', b'\0', record(b'')):
            with self.assertRaisesRegex(ValueError, 'trailing'):
                parse(wire + tail, [body])

    def test_unchanged_file_cap_and_explicit_existing_custody_aggregate_cap(self):
        self.assertEqual(C.SOURCE_FILE_BYTES, 16 * C.MIB)
        self.assertEqual(C.SOURCE_BYTES, 512 * C.MIB)
        self.assertEqual(C.SOURCE_REQUEST_BYTES, C.MIB)
        self.assertEqual(C.GIT_SECONDS, 15)
        header = b'1' * 40 + b' blob ' + str(C.SOURCE_FILE_BYTES + 1).encode() + b'\n'
        with self.assertRaisesRegex(ValueError, 'file/aggregate bound'):
            parse(header, [b''])
        with mock.patch.object(C, 'SOURCE_BYTES', 3):
            with self.assertRaisesRegex(ValueError, 'file/aggregate bound'):
                parse(record(b'ab') + record(b'cd'), [b'ab', b'cd'])


class SourceSemantics(unittest.TestCase):
    def fixture(self):
        files = {'src/b.rs': b'B', 'Cargo.toml': b'cargo', 'src/a.rs': b'A'}
        pins = types.SimpleNamespace(SOURCE_REVISION=REVISION,
            SOURCE_PINS={name:C.sha(raw) for name,raw in files.items()})
        # The live snapshot now owns real no-follow reads and ctx.PINS. Only
        # Git transport is mocked; identical source assertions below remain.
        if hasattr(self, '_read_patch'):
            self._read_patch.stop()
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for name, raw in files.items():
            path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        reads = []
        original_read = C.Store.read
        def read(store, path, cap, pin=None):
            if str(path) not in store.files:
                self.assertEqual(cap, 16 * C.MIB)
                name = str(path.relative_to(root)); reads.append(name)
            else:
                # Final metadata verification is additional to the fresh byte
                # reads counted by the unchanged assertions below.
                self.assertEqual(cap, store.files[str(path)][0]['bytes'])
                self.assertEqual(pin, store.files[str(path)][0])
            return original_read(store, path, cap, pin)
        self._read_patch = mock.patch.object(C.Store, 'read', read)
        self._read_patch.start(); self.addCleanup(self._read_patch.stop)
        ctx = types.SimpleNamespace(ROOT=root, PINS={})
        calls = []
        def git(argv, *, env, timeout):
            self.assertEqual(argv[:3], ['/usr/bin/git', '-C', str(root)])
            self.assertEqual(env, {'TOKEN': 'fixed'})
            self.assertEqual(timeout, 15)
            command = argv[3:]; calls.append(command)
            if command == ['rev-parse', 'HEAD']:
                return (REVISION + '\n').encode()
            if command == ['diff', '--binary', 'HEAD', '--']:
                return b''
            self.assertEqual(command, ['ls-tree', '-r', '--name-only', REVISION, '--', *C.SOURCE_ROOTS])
            return ('\n'.join(sorted(files)) + '\n').encode()
        return files, pins, ctx, reads, calls, git

    def test_each_call_rechecks_inventory_all_committed_blobs_and_every_live_file(self):
        files, pins, ctx, reads, calls, git = self.fixture()
        observed = []
        def batch(root, revision, ordered, env):
            self.assertEqual(root, ctx.ROOT); self.assertEqual(revision, REVISION)
            self.assertEqual(env, {'TOKEN': 'fixed'})
            self.assertEqual(ordered, sorted(pins.SOURCE_PINS.items()))
            observed.append(list(ordered))
            parse(b''.join(record(files[name]) for name,_ in ordered), [files[name] for name,_ in ordered])
        with mock.patch.object(C.subprocess, 'check_output', side_effect=git), \
             mock.patch.object(C, 'source_batch', side_effect=batch):
            self.assertEqual(C.source_profile(ctx, pins, {'TOKEN': 'fixed'}), REVISION)
            self.assertEqual(C.source_profile(ctx, pins, {'TOKEN': 'fixed'}), REVISION)
        self.assertEqual(len(observed), 2)
        self.assertEqual(reads, sorted(files) * 2)
        self.assertEqual(len(calls), 6)
        self.assertFalse(any(command[0] == 'show' for command in calls))

    def test_dirty_or_incomplete_inventory_refuses_before_batch(self):
        for fault in ('dirty', 'missing', 'extra'):
            files, pins, ctx, reads, calls, git = self.fixture()
            def broken(argv, **kw):
                raw = git(argv, **kw)
                if argv[3] == 'diff' and fault == 'dirty':
                    return b'tracked change'
                if argv[3] == 'ls-tree':
                    return b'Cargo.toml\n' if fault == 'missing' else raw + b'extra.rs\n' if fault == 'extra' else raw
                return raw
            with mock.patch.object(C.subprocess, 'check_output', side_effect=broken), \
                 mock.patch.object(C, 'source_batch') as batch:
                with self.assertRaises(ValueError):
                    C.source_profile(ctx, pins, {'TOKEN': 'fixed'})
                batch.assert_not_called()
            self.assertEqual(reads, [])

    def test_live_drift_and_aggregate_overflow_are_never_cached_or_skipped(self):
        files, pins, ctx, reads, calls, git = self.fixture()
        with mock.patch.object(C.subprocess, 'check_output', side_effect=git), \
             mock.patch.object(C, 'source_batch') as batch:
            self.assertEqual(C.source_profile(ctx, pins, {'TOKEN': 'fixed'}), REVISION)
            files['src/a.rs'] = b'changed'; (ctx.ROOT/'src/a.rs').write_bytes(files['src/a.rs'])
            with self.assertRaisesRegex(ValueError, 'reviewed startup source bytes'):
                C.source_profile(ctx, pins, {'TOKEN': 'fixed'})
            self.assertEqual(batch.call_count, 2)
            self.assertEqual(reads.count('src/a.rs'), 2)
        # A fresh custody lifetime isolates the aggregate bound from the inode
        # drift deliberately introduced above; both prior assertions are kept.
        files, pins, ctx, reads, calls, git = self.fixture()
        with mock.patch.object(C.subprocess, 'check_output', side_effect=git), \
             mock.patch.object(C, 'source_batch'), mock.patch.object(C, 'SOURCE_BYTES', 6):
            with self.assertRaisesRegex(ValueError, 'live source file/aggregate bound'):
                C.source_profile(ctx, pins, {'TOKEN': 'fixed'})

    def test_request_injection_invalid_digest_and_bound_refuse_before_spawn(self):
        with mock.patch.object(C.subprocess, 'Popen') as spawn:
            for relative in ('../escape', '/absolute', 'src//a', 'src/./a', 'src/a\nHEAD', 'src/a\r', 'src/a\0'):
                with self.assertRaisesRegex(ValueError, 'reviewed source path'):
                    C.source_batch(Path('/repo'), REVISION, [(relative, C.sha(b'a'))], {})
            with self.assertRaisesRegex(ValueError, 'canonical digest'):
                C.source_batch(Path('/repo'), REVISION, [('src/a', 'A' * 64)], {})
            with mock.patch.object(C, 'SOURCE_REQUEST_BYTES', 10):
                with self.assertRaisesRegex(ValueError, 'request bound'):
                    C.source_batch(Path('/repo'), REVISION, [('src/a', C.sha(b'a'))], {})
            spawn.assert_not_called()


class BatchProcess(unittest.TestCase):
    def child(self):
        streams = [mock.Mock() for _ in range(3)]
        for fd, stream in zip((10, 11, 12), streams):
            stream.fileno.return_value = fd
        child = mock.Mock(stdin=streams[0], stdout=streams[1], stderr=streams[2])
        child.wait.return_value = 0; child.poll.return_value = 0
        return child

    def test_one_exact_process_complete_stdin_and_bounded_successful_closure(self):
        child = self.child(); wire = record(b'A') + record(b'B')
        reads = {11:iter((wire[:17], wire[17:], b'')), 12:iter((b'',))}
        def ready(reading, writing, exceptional, seconds):
            self.assertGreater(seconds, 0); self.assertLessEqual(seconds, 15)
            return (list(reading), list(writing), [])
        def write(fd, raw):
            self.assertEqual(fd, 10)
            self.assertEqual(bytes(raw), (REVISION + ':src/a\n' + REVISION + ':src/b\n').encode())
            return len(raw)
        with mock.patch.object(C.subprocess, 'Popen', return_value=child) as spawn, \
             mock.patch.object(C.time, 'monotonic', return_value=100), \
             mock.patch.object(C.os, 'set_blocking') as nonblock, \
             mock.patch.object(C.select, 'select', side_effect=ready), \
             mock.patch.object(C.os, 'write', side_effect=write) as sent, \
             mock.patch.object(C.os, 'read', side_effect=lambda fd,cap:next(reads[fd])):
            C.source_batch(Path('/repo'), REVISION, [('src/a',C.sha(b'A')),('src/b',C.sha(b'B'))], {'fixed':'env'})
        spawn.assert_called_once_with(['/usr/bin/git','-C','/repo','cat-file','--batch'],
            env={'fixed':'env'}, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.assertEqual(nonblock.call_args_list, [mock.call(10,False),mock.call(11,False),mock.call(12,False)])
        sent.assert_called_once(); child.kill.assert_not_called()
        self.assertEqual(child.wait.call_args_list, [mock.call(timeout=15),mock.call(timeout=C.GIT_CLEANUP_SECONDS)])
        child.stdout.close.assert_called_once(); child.stderr.close.assert_called_once()

    def test_timeout_and_bad_stream_kill_reap_and_close_without_retry(self):
        for failure in ('timeout', 'stderr', 'malformed'):
            child = self.child(); child.poll.return_value = None
            if failure == 'timeout':
                ready = ([], [], [])
            else:
                ready = ([12 if failure == 'stderr' else 11], [], [])
            with mock.patch.object(C.subprocess,'Popen',return_value=child) as spawn, \
                 mock.patch.object(C.time,'monotonic',return_value=100), \
                 mock.patch.object(C.os,'set_blocking'), \
                 mock.patch.object(C.select,'select',return_value=ready), \
                 mock.patch.object(C.os,'read',return_value=b'invalid\n'), \
                 mock.patch.object(C.os,'write') as sent:
                with self.assertRaises(subprocess.TimeoutExpired if failure == 'timeout' else ValueError):
                    C.source_batch(Path('/repo'),REVISION,[('src/a',C.sha(b'A'))],{})
            spawn.assert_called_once(); sent.assert_not_called()
            child.kill.assert_called_once(); child.wait.assert_called_once_with(timeout=C.GIT_CLEANUP_SECONDS)
            for stream in (child.stdin,child.stdout,child.stderr):
                stream.close.assert_called_once()

    def test_late_completion_nonzero_exit_and_missing_output_cannot_complete(self):
        for failure in ('late', 'exit', 'missing'):
            child = self.child()
            child.wait.return_value = 2 if failure == 'exit' else 0
            reads = {11:iter((b'' if failure == 'missing' else record(b'A'), b'')), 12:iter((b'',))}
            times = [100,100,100,100,116] if failure == 'late' else None
            def ready(reading, writing, exceptional, seconds):
                return (list(reading), list(writing), [])
            with mock.patch.object(C.subprocess,'Popen',return_value=child) as spawn, \
                 mock.patch.object(C.time,'monotonic',side_effect=times,return_value=100), \
                 mock.patch.object(C.os,'set_blocking'), \
                 mock.patch.object(C.select,'select',side_effect=ready), \
                 mock.patch.object(C.os,'write',side_effect=lambda fd,raw:len(raw)), \
                 mock.patch.object(C.os,'read',side_effect=lambda fd,cap:next(reads[fd])):
                with self.assertRaises(subprocess.TimeoutExpired if failure == 'late' else ValueError):
                    C.source_batch(Path('/repo'),REVISION,[('src/a',C.sha(b'A'))],{})
            spawn.assert_called_once(); child.stdout.close.assert_called_once(); child.stderr.close.assert_called_once()


class ExactBatchLengths(unittest.TestCase):
    def parser(self, bodies, lengths):
        return C.SourceBatch([C.sha(body) for body in bodies], expected_lengths=lengths)

    def test_exact_empty_binary_lengths_and_fragmented_records(self):
        bodies = [b'', b'a\0b\xff', bytes(range(256))]
        wire = b''.join(map(record, bodies))
        for step in (1, 2, 7, 53, 65536):
            lengths = list(map(len, bodies)); decoder = self.parser(bodies, lengths)
            lengths[:] = [999]  # The caller cannot change the retained roster.
            for at in range(0, len(wire), step):decoder.feed(wire[at:at+step])
            decoder.finish(); self.assertEqual(decoder.index, 3)
            self.assertEqual(decoder.total, sum(map(len, bodies)))

    def test_honest_hashes_with_wrong_expected_size_refuse_at_header(self):
        body = b'complete'; header = record(body).split(b'\n', 1)[0] + b'\n'
        for size in (len(body)-1, len(body)+1):
            decoder = self.parser([body], [size])
            with self.assertRaisesRegex(ValueError, 'exact committed source size'):
                decoder.feed(header)
            self.assertEqual(decoder.index, 0); self.assertEqual(decoder.total, 0)

    def test_invalid_exact_length_rosters_refuse_before_spawn(self):
        for lengths in ([], [1, 1], [True], [False], [-1], [1.0], ['1'],
                        [C.SOURCE_FILE_BYTES+1], '1', 1, {0:1}):
            with self.subTest(lengths=lengths), mock.patch.object(C.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(ValueError, 'exact length roster'):
                    C.source_batch(Path('/repo'), REVISION, [('src/a', C.sha(b'A'))], {},
                        expected_lengths=lengths)
                spawn.assert_not_called()
        with mock.patch.object(C.subprocess, 'Popen') as spawn, mock.patch.object(C, 'SOURCE_BYTES', 1):
            with self.assertRaisesRegex(ValueError, 'file/aggregate bound'):
                C.source_batch(Path('/repo'), REVISION, [('src/a', C.sha(b'AA'))], {}, expected_lengths=[2])
            spawn.assert_not_called()

    def test_equal_lengths_never_replace_content_order_or_git_object_checks(self):
        bodies = [b'AA', b'BB']
        for wire in (record(b'BB')+record(b'AA'), record(b'AA')+record(b'AA'),
                     record(b'CC')+record(b'BB'), b'0'*40+record(b'AA')[40:]+record(b'BB')):
            with self.assertRaisesRegex(ValueError, 'committed source bytes'):
                self.parser(bodies, [2, 2]).feed(wire)

    def test_exact_lengths_preserve_all_truncations_framing_and_caps(self):
        body = b'payload\nbody'; wire = record(body)
        for end in range(len(wire)):
            decoder = self.parser([body], [len(body)])
            decoder.feed(wire[:end])
            with self.assertRaisesRegex(ValueError, 'missing/truncated'):decoder.finish()
        for malformed in (wire[:-1]+b'X', wire+b'\n', wire+record(b''),
                          wire.replace(b' blob 12\n', b' blob 012\n', 1)):
            with self.assertRaises(ValueError):self.parser([body], [len(body)]).feed(malformed)
        header = b'1'*40+b' blob '+str(C.SOURCE_FILE_BYTES+1).encode()+b'\n'
        with self.assertRaisesRegex(ValueError, 'file/aggregate bound'):
            self.parser([b''], [0]).feed(header)
        decoder = self.parser([b'AA', b'BB'], [2, 2])
        with mock.patch.object(C, 'SOURCE_BYTES', 3):
            with self.assertRaisesRegex(ValueError, 'file/aggregate bound'):
                decoder.feed(record(b'AA')+record(b'BB'))

    def test_transport_enforces_exact_size_and_closes_success_or_refusal(self):
        for expected in (0, 1, 2):
            child = BatchProcess.child(self);child.poll.return_value = 0 if expected == 1 else None
            reads = {11:iter((record(b'A'), b'')), 12:iter((b'',))}
            def ready(reading, writing, exceptional, seconds):
                self.assertGreater(seconds, 0);self.assertLessEqual(seconds, 15)
                return (list(reading), list(writing), [])
            with mock.patch.object(C.subprocess, 'Popen', return_value=child) as spawn, \
                 mock.patch.object(C.time, 'monotonic', return_value=100), \
                 mock.patch.object(C.os, 'set_blocking'), \
                 mock.patch.object(C.select, 'select', side_effect=ready), \
                 mock.patch.object(C.os, 'write', side_effect=lambda fd,raw:len(raw)), \
                 mock.patch.object(C.os, 'read', side_effect=lambda fd,cap:next(reads[fd])):
                if expected == 1:
                    C.source_batch(Path('/repo'), REVISION, [('src/a', C.sha(b'A'))], {}, expected_lengths=[expected])
                else:
                    with self.assertRaisesRegex(ValueError, 'exact committed source size'):
                        C.source_batch(Path('/repo'), REVISION, [('src/a', C.sha(b'A'))], {}, expected_lengths=[expected])
            spawn.assert_called_once()
            if expected == 1:child.kill.assert_not_called()
            else:child.kill.assert_called_once()
            self.assertEqual(child.wait.call_args_list[-1], mock.call(timeout=C.GIT_CLEANUP_SECONDS))
            child.stdout.close.assert_called_once();child.stderr.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
