#!/usr/bin/env python3
"""Pure transcript controls, not native execution or physical-return evidence."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import unittest
import json
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch
from session_driver import authenticate, check, checksum, main, remaining, reap, refusal

EXPECTED = [('CALL', 42, 3, b'a\0b'), ('FLUSH', 9)]
TRACE = f'''READY,normal-session-v1,10,1,10,2,4096,4096,4,1
HISTORY,1,1,published,7
RESULT,42,1,3,3,{checksum(b'a'+bytes([0])+b'b')},1,sampled,7,1,1,34,checkpoint,100,110,3,3,1
FLUSHED,9,1,1,1
HISTORY,2,2,removed,7
REPORT,7,1
SAMPLE,42,7,0,100,0,value,110
IO,0
DONE,EpochLimit,1,2,2,1,1,0,1,1,1,1
'''

class Controls(unittest.TestCase):
    def valid(self, text):
        return check(text, EXPECTED, 10, 1, 'EpochLimit')
    def refuse(self, text):
        with self.assertRaises((AssertionError, IndexError, ValueError, KeyError)):
            self.valid(text)
    def test_complete_population_and_independent_scalar(self):
        self.assertEqual(self.valid(TRACE)['calls'], 1)
        self.refuse(TRACE.replace(',1,sampled,', ',2,sampled,'))
        self.refuse(TRACE.replace(str(checksum(b'a\0b')), '0'))
    def test_missing_duplicate_or_reordered_request_and_barrier(self):
        row = next(x for x in TRACE.splitlines(True) if x.startswith('RESULT,'))
        self.refuse(TRACE.replace(row, ''))
        self.refuse(TRACE.replace(row, row+row))
        self.refuse(TRACE.replace('RESULT,42,', 'RESULT,43,'))
        self.refuse(TRACE.replace('FLUSHED,9,', 'FLUSHED,42,'))
        self.refuse(TRACE.replace(row, '').replace('HISTORY,1,1,published,7\n', row+'HISTORY,1,1,published,7\n'))
    def test_coherent_slot_shift_and_early_function_closed_refuse(self):
        self.refuse(TRACE.replace(',sampled,7,1,1,34,', ',sampled,7,2,1,34,').replace('SAMPLE,42,7,0,', 'SAMPLE,42,7,1,'))
        altered = TRACE.replace(',sampled,7,1,1,34,', ',closed,7,0,1,34,')
        altered = altered.replace('SAMPLE,42,7,0,100,0,value,110\n', '').replace('REPORT,7,1', 'REPORT,7,0')
        altered = altered.replace('FLUSHED,9,1,1,1', 'FLUSHED,9,1,1,0').replace('DONE,EpochLimit,1,2,2,1,1,0,', 'DONE,EpochLimit,1,2,2,1,0,1,')
        self.refuse(altered)
    def test_owner_prefix_ret_and_chunk_identity_refuse(self):
        for before, after in [(',sampled,7,1,1,34,', ',sampled,7,1,0,34,'),
                              (',sampled,7,1,1,34,', ',sampled,8,1,1,34,'),
                              (',1,34,checkpoint,', ',1,33,checkpoint,'),
                              ('HISTORY,2,2,', 'HISTORY,3,2,'),
                              ('HISTORY,2,2,removed,7', 'HISTORY,2,2,removed,8')]:
            self.refuse(TRACE.replace(before, after))
    def test_report_sequence_endpoint_and_complete_rows_refuse(self):
        for before, after in [('SAMPLE,42,7,0,100,0,', 'SAMPLE,42,7,0,100,1,'),
                              ('value,110', 'value,109'), ('REPORT,7,1', 'REPORT,7,0'),
                              ('REPORT,7,1', 'REPORT,7,1\nREPORT,7,1')]:
            self.refuse(TRACE.replace(before, after))
        self.refuse(TRACE.replace('SAMPLE,42,7,0,100,0,value,110\n', ''))
    def test_terminal_population_acknowledgement_and_join_refuse(self):
        self.refuse(TRACE.replace(',checkpoint,', ',next,'))
        self.refuse(TRACE.replace('DONE,EpochLimit,1,2,2,1,1,0,1,1,1,1', 'DONE,EpochLimit,1,2,2,1,1,0,1,1,1,0'))
        self.refuse(TRACE.replace('DONE,EpochLimit,1,2,2,', 'DONE,EpochLimit,1,2,1,'))
        self.refuse(TRACE.replace('DONE,EpochLimit,', 'DONE,Requested,'))
        self.refuse(TRACE + 'REPORT,7,1\n')
    def test_exact_lf_ascii_framing_and_pressure_snapshot(self):
        for delimiter in ('\r\n', '\r', '\v', '\f', '\x1c', '\x85', '\u2028'):
            self.refuse(TRACE.replace('\n', delimiter))
        self.refuse(TRACE[:-1])
        self.refuse(TRACE+'\n')
        self.refuse(TRACE.replace('IO,0\n', ''))
        self.refuse(TRACE.replace('IO,0\n', 'IO,0\nIO,0\n'))
        self.refuse(TRACE.replace('IO,0\n', '').replace('REPORT,7,1\n', 'IO,0\nREPORT,7,1\n'))
        self.assertEqual(self.valid(TRACE.replace('IO,0', 'IO,123'))['write_blocked_at_finalize'], 123)
    def test_scalar_path_requires_its_own_ret(self):
        old = next(line for line in TRACE.split('\n') if line.startswith('RESULT,'))
        for bound, data, value, ret in ((0, b'', 0, 34), (3, b'a\0b', 1, 34), (3, b'abc', 3, 40)):
            expected = [('CALL', 42, bound, data), ('FLUSH', 9)]
            row = f'RESULT,42,1,{bound},{len(data)},{checksum(data)},{value},sampled,7,1,1,{ret},checkpoint,100,110,3,3,1'
            text = TRACE.replace(old, row)
            self.assertEqual(check(text, expected, 10, 1, 'EpochLimit')['calls'], 1)
            with self.assertRaises(AssertionError):
                check(text.replace(f',1,{ret},checkpoint,', f',1,{74-ret},checkpoint,'), expected, 10, 1, 'EpochLimit')
    def test_coherent_history_reversal_and_aux_width_refuse(self):
        expected = [('CALL', 42, 3, b'a\0b'), ('CALL', 43, 3, b'a\0b')]
        digest = checksum(b'a\0b')
        text = f'''READY,normal-session-v1,10,2,10,2,4096,4096,4,1
HISTORY,1,1,published,7
HISTORY,2,2,published,9
RESULT,42,1,3,3,{digest},1,sampled,7,1,1,34,checkpoint,100,110,3,3,1
RESULT,43,2,3,3,{digest},1,sampled,9,1,2,34,checkpoint,120,130,3,3,2
HISTORY,3,3,removed,9
REPORT,7,1
REPORT,9,1
SAMPLE,42,7,0,100,0,value,110
SAMPLE,43,9,0,120,1,value,130
IO,0
DONE,EpochLimit,2,3,2,2,2,0,2,0,1,1
'''
        self.assertEqual(check(text, expected, 10, 2, 'EpochLimit')['calls'], 2)
        backwards_generations = text.replace(',7', ',TMP').replace(',9', ',7').replace(',TMP', ',9')
        backwards_prefixes = text.replace(',sampled,7,1,1,', ',sampled,9,1,2,').replace(',sampled,9,1,2,34,checkpoint,120', ',sampled,7,1,1,34,checkpoint,120')
        backwards_prefixes = backwards_prefixes.replace('SAMPLE,42,7,', 'SAMPLE,42,9,').replace('SAMPLE,43,9,', 'SAMPLE,43,7,')
        for changed in (backwards_generations, backwards_prefixes):
            with self.assertRaises(AssertionError): check(changed, expected, 10, 2, 'EpochLimit')
        self.refuse(TRACE.replace(',110,3,3,1', ',110,4294967296,4294967296,1'))
    def test_subject_authority_and_absolute_reap_deadline(self):
        candidate = Mock()
        with self.assertRaises(AssertionError): authenticate(candidate, candidate, 4096, 40)
        candidate.stat.assert_not_called()
        candidate.stat.return_value.st_size = 1
        candidate.read_bytes.return_value = b'x'
        with self.assertRaises(AssertionError): authenticate(candidate, candidate, 4096, 41)
        child = Mock()
        child.wait.return_value = 0
        with patch('session_driver.time.monotonic', side_effect=[10, 14]):
            self.assertEqual(reap(child, 15), 0)
        child.wait.assert_called_once_with(timeout=5)
        child.reset_mock()
        with patch('session_driver.time.monotonic', return_value=15):
            with self.assertRaises(AssertionError): reap(child, 15)
            with self.assertRaises(AssertionError): remaining(15)
        child.wait.assert_not_called()
        with patch('session_driver.time.monotonic', side_effect=[14, 15]):
            with self.assertRaises(AssertionError): reap(child, 15)
        child.wait.assert_called_once_with(timeout=1)
    def test_setup_failure_still_owns_and_reaps_child(self):
        for fail_at in ('selector', 'descriptor'):
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory)/'result'
                child = Mock(returncode=None)
                child.poll.return_value = None
                def reaped(): child.returncode = -9
                child.wait.side_effect = reaped
                selector = Mock()
                argv = ['driver', '--binary', 'b', '--candidate', 'c', '--trusted', 't', '--output', str(output),
                    '--elf-va', '4096', '--length', '41', '--k', '10', '--mode', 'full']
                with patch('sys.argv', argv), patch('session_driver.authenticate'), \
                     patch('session_driver.os.sched_getaffinity', return_value={0, 1, 2, 3}), \
                     patch('session_driver.os.sched_setaffinity'), patch('builtins.print'), \
                     patch('session_driver.subprocess.Popen', return_value=child), \
                     patch('session_driver.selectors.DefaultSelector', side_effect=OSError('setup') if fail_at == 'selector' else None, return_value=selector), \
                     patch('session_driver.os.set_blocking', side_effect=OSError('setup')):
                    with self.assertRaises(AssertionError): main()
                child.kill.assert_called_once_with()
                child.wait.assert_called_once_with()
                result = json.loads((output/'result.json').read_text())
                self.assertEqual(result['status'], 'FAILED')
                self.assertTrue(result['rescue'])

    def test_refusal_requires_exact_normal_exit_one(self):
        transcript = b'READY,normal-session-v1,10,520,10,2,4096,4096,4,1\n'
        for mode, reason in (('duplicate', b'duplicate request ID'),
                             ('eof', b'overlong or unterminated request')):
            errors = b'normal-session FAILED: ' + reason + b'\n'
            self.assertEqual(refusal(mode, 1, transcript, errors),
                dict(control=mode, expected_refusal=True, exit_code=1))
            for code in (0, 2, 123, -9, None, True, 1.0, '1'):
                with self.subTest(mode=mode, code=code):
                    with self.assertRaises(AssertionError):
                        refusal(mode, code, transcript, errors)
            for output, diagnostic in ((transcript+b'DONE,forged\n', errors),
                                       (transcript, b''),
                                       (transcript, reason),
                                       (transcript, b'normal-session FAILED: other failure\n')):
                with self.assertRaises(AssertionError):
                    refusal(mode, 1, output, diagnostic)
        with self.assertRaises(AssertionError):
            refusal('full', 1, transcript, b'normal-session FAILED: duplicate request ID\n')

if __name__ == '__main__': unittest.main()
