"""Pure synthetic controls only; never imports GDB or starts an inferior."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled Python -I -B")

path = Path(__file__).with_name("exec_transition.py")
spec = importlib.util.spec_from_file_location("exec_transition", path)
protocol = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protocol)


def note(name, value, kind):
    return (struct.pack("<III", len(name), len(value), kind)
            + name + b"\0" * (-len(name) % 4)
            + value + b"\0" * (-len(value) % 4))


class ExecTransitionTests(unittest.TestCase):
    def request(self, **changes):
        values = dict(entered=True, pending=322, number=59, orig_rax=59,
                      signed_rax=-12, exec_seen=False,
                      kernel_build_id=protocol.KERNEL_BUILD_ID,
                      pending_frame=(0x1234, 3, 0x2000, 0x3000, 0x4000, 4096),
                      frame=(0x1234, 3, 0x2000, 0x3000, 0x4000, 4096))
        values.update(changes)
        return protocol.exec_return_kind(**values)

    def test_running_note_identity_requires_exact_single_build_id(self):
        good = note(b"GNU\0", bytes.fromhex(protocol.KERNEL_BUILD_ID), 3)
        identity = protocol.kernel_identity(note(b"Linux\0", b"x", 1) + good)
        self.assertEqual(identity["build_id"], protocol.KERNEL_BUILD_ID)
        self.assertEqual(identity["profile"], protocol.PROFILE)
        for bad in (b"", good + good, good[:-1], good[:11], b"x" * 65537,
                    note(b"GNU\0", b"\0" * 20, 3),
                    note(b"GNU\0", bytes.fromhex(protocol.KERNEL_BUILD_ID), 4)):
            with self.subTest(size=len(bad)), self.assertRaises(RuntimeError):
                protocol.kernel_identity(bad)

    def test_ordinary_returns_retain_exact_pending_number(self):
        for number in (59, 322):
            for value in (-4095, -12, -1, 0):
                self.assertEqual(self.request(pending=number, number=number,
                                             orig_rax=number, signed_rax=value),
                                 "EXACT_PENDING_RETURN")
        for changes in (dict(pending=59, number=322, orig_rax=322),
                        dict(number=1, orig_rax=1), dict(orig_rax=322)):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                self.request(**changes)

    def test_only_proved_canonicalized_negative_transition_is_distinct(self):
        for value in (-4095, -12, -1):
            self.assertEqual(self.request(signed_rax=value),
                             "CANONICALIZED_POSTCOMMIT_EXEC_ERROR")
        for changes in (dict(signed_rax=-4096), dict(signed_rax=0),
                        dict(signed_rax=1), dict(exec_seen=True),
                        dict(kernel_build_id="0" * 40)):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                self.request(**changes)

    def test_absent_or_consumed_request_cannot_authorize_any_return(self):
        for number in (59, 322):
            for changes in (dict(entered=False), dict(pending=None), dict(pending=1)):
                with self.subTest(number=number, changes=changes), self.assertRaises(RuntimeError):
                    self.request(number=number, orig_rax=number, **changes)

    def test_canonicalized_return_requires_each_original_frame_field(self):
        original = (0x1234, 3, 0x2000, 0x3000, 0x4000, 4096)
        for index in range(6):
            changed = list(original)
            changed[index] += 1
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                self.request(frame=tuple(changed))
        for invalid in (None, (), original[:-1], list(original),
                        (True,) + original[1:], (-1,) + original[1:],
                        (1 << 64,) + original[1:]):
            with self.subTest(frame=invalid), self.assertRaises(RuntimeError):
                self.request(pending_frame=invalid, frame=invalid)


if __name__ == "__main__":
    unittest.main()
