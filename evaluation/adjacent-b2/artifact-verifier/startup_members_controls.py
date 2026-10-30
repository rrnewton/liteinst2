#!/usr/bin/env python3
"""Real directory-custody controls; no child, producer, or candidate dispatch."""
from contextlib import contextmanager
import errno
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import startup_custody as C


def executor():
    path = Path(__file__).resolve().parents[2] / 'offline-corpus/full_startup_e9_execute.py'
    spec = importlib.util.spec_from_file_location('membership_e9_executor', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DirectoryMembers(unittest.TestCase):
    def fixture(self, names=('command.json', 'request.json')):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name).resolve() / 'command'
        directory.mkdir(mode=0o700)
        for name in names:
            (directory / name).write_bytes(name.encode())
        store = C.Store()
        self.addCleanup(store.close)
        return directory, store

    @contextmanager
    def descriptors(self, store, *, wrong_owner=None, open_error=False):
        original_directory, original_open = store.directory, os.open
        anchors, listings = [], []
        def directory(path):
            fd = original_directory(path)
            anchors.append(fd)
            return fd
        def opened(path, flags, *args, **kwargs):
            if path != '.':
                return original_open(path, flags, *args, **kwargs)
            self.assertEqual(flags, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.assertEqual(args, ())
            self.assertEqual(kwargs, {'dir_fd': anchors[-1]})
            if open_error:
                raise OSError(errno.EIO, 'injected fresh directory open error')
            fd = original_open(str(wrong_owner) if wrong_owner is not None else path,
                               flags, *args, **kwargs)
            listings.append(fd)
            return fd
        try:
            with mock.patch.object(store, 'directory', side_effect=directory), \
                 mock.patch.object(C.os, 'open', side_effect=opened):
                yield anchors, listings
        finally:
            for fd in anchors + listings:
                with self.assertRaises(OSError) as raised:
                    os.fstat(fd)
                self.assertEqual(raised.exception.errno, errno.EBADF)
            # Temporary enumeration descriptors must not consume the anchors
            # retained by the Store for later path/identity verification.
            for fd, _ in store.directories.values():
                os.fstat(fd)

    def inputs(self, store):
        module = executor()
        inputs = object.__new__(module.Inputs)
        inputs.store = store
        inputs.members = []
        inputs.readers = []
        return inputs

    def test_same_store_sees_synchronous_two_to_eight_transition(self):
        directory, store = self.fixture()
        # Match actual preparation: open the directory through its input files,
        # then list the two names before the command creates six more files.
        store.read(directory / 'request.json', C.MIB)
        self.assertEqual(store.members(directory)['members'], ['command.json', 'request.json'])
        for name in C.CONTROL:
            if name not in ('command.json', 'request.json'):
                (directory / name).write_bytes(name.encode())
        with self.descriptors(store) as (anchors, listings):
            for _ in range(3):
                self.assertEqual(store.members(directory)['members'], sorted(C.CONTROL))
            self.assertEqual((len(anchors), len(listings)), (3, 3))
        inputs = self.inputs(store)
        inputs.retain_command(directory)
        inputs.stable()
        self.assertEqual(inputs.members[0][1]['members'], sorted(C.CONTROL))

    def test_removed_or_unexpected_member_is_visible_and_exact_closure_refuses(self):
        for mutation in ('remove', 'add'):
            with self.subTest(mutation=mutation):
                directory, store = self.fixture(C.CONTROL)
                inputs = self.inputs(store)
                inputs.retain_command(directory)
                expected = set(C.CONTROL)
                if mutation == 'remove':
                    (directory / 'receipt.json').unlink()
                    expected.remove('receipt.json')
                else:
                    (directory / 'unexpected').write_bytes(b'extra')
                    expected.add('unexpected')
                self.assertEqual(store.members(directory)['members'], sorted(expected))
                with self.assertRaisesRegex(ValueError, 'whole exact raw command closure'):
                    inputs.retain_command(directory)
                self.assertEqual(len(inputs.members), 1)
                with self.assertRaisesRegex(ValueError, 'closed command directory changed'):
                    inputs.stable()

    def test_listing_description_is_independent_of_retained_cursor(self):
        directory, store = self.fixture()
        held = store.directory(directory)
        original_scandir = os.scandir
        def scan(fd):
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 0)
            os.lseek(held, 1, os.SEEK_SET)
            # A mere dup shares this cursor; open('.') must not.
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), 0)
            os.lseek(held, 0, os.SEEK_SET)
            return original_scandir(fd)
        try:
            with self.descriptors(store), mock.patch.object(C.os, 'scandir', side_effect=scan):
                self.assertEqual(store.members(directory)['members'], ['command.json', 'request.json'])
        finally:
            os.close(held)

    def test_fresh_description_wrong_owner_refuses_and_closes_both_fds(self):
        directory, store = self.fixture()
        other = directory.parent / 'other'
        other.mkdir()
        with self.descriptors(store, wrong_owner=other) as (anchors, listings), \
             mock.patch.object(C.os, 'scandir') as scan:
            with self.assertRaisesRegex(ValueError, 'listing directory owner changed'):
                store.members(directory)
            scan.assert_not_called()
            self.assertEqual((len(anchors), len(listings)), (1, 1))

    def test_fresh_open_error_closes_duplicate_anchor(self):
        directory, store = self.fixture()
        with self.descriptors(store, open_error=True) as (anchors, listings):
            with self.assertRaisesRegex(OSError, 'injected fresh directory open error'):
                store.members(directory)
            self.assertEqual((len(anchors), len(listings)), (1, 0))

    def test_scandir_error_closes_both_temporary_fds(self):
        directory, store = self.fixture()
        with self.descriptors(store) as (anchors, listings), \
             mock.patch.object(C.os, 'scandir', side_effect=OSError(errno.EIO, 'injected listing error')):
            with self.assertRaisesRegex(OSError, 'injected listing error'):
                store.members(directory)
            self.assertEqual((len(anchors), len(listings)), (1, 1))

    def test_full_directory_stamp_change_during_listing_refuses(self):
        directory, store = self.fixture()
        original_scandir = os.scandir
        @contextmanager
        def changed(fd):
            with original_scandir(fd) as entries:
                yield entries
            # Deterministic metadata change, independent of timestamp granularity.
            directory.chmod(0o750)
        try:
            with self.descriptors(store), mock.patch.object(C.os, 'scandir', side_effect=changed):
                with self.assertRaisesRegex(ValueError, 'directory changed during listing'):
                    store.members(directory)
        finally:
            directory.chmod(0o700)

    def test_flat_name_and_count_bounds_remain_exact(self):
        directory, store = self.fixture(('a', 'b'))
        self.assertEqual(store.members(directory, count=2)['members'], ['a', 'b'])
        with self.descriptors(store):
            with self.assertRaisesRegex(ValueError, 'flat publication member/name bound'):
                store.members(directory, count=1)
        (directory / 'not flat').write_bytes(b'bad name')
        with self.descriptors(store):
            with self.assertRaisesRegex(ValueError, 'flat publication member/name bound'):
                store.members(directory)

    def test_close_error_still_closes_duplicate_anchor(self):
        directory, store = self.fixture()
        original_close = os.close
        with self.descriptors(store) as (anchors, listings):
            def closed(fd):
                original_close(fd)
                if listings and fd == listings[-1]:
                    raise OSError(errno.EIO, 'injected listing close error')
            with mock.patch.object(C.os, 'close', side_effect=closed):
                with self.assertRaisesRegex(OSError, 'injected listing close error'):
                    store.members(directory)
            self.assertEqual((len(anchors), len(listings)), (1, 1))


if __name__ == '__main__':
    unittest.main()
