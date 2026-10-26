#!/usr/bin/env python3
"""Prospective pure parser calibrations: no subprocesses or ELF execution."""
import copy
import json
import struct
import sys

if sys.flags.optimize:
    raise SystemExit('optimized Python disables calibration assertions')
from audit import backend_stats, digest, elf64, executable_offset, loads, validate_helper_receipt, validate_rpc


def fixture():
    # Independent synthetic ELF layout: two file-backed PT_LOAD records, RX
    # instructions at file 0x100/VA 0x401100 and read-only data at file 0x200.
    data = bytearray(0x300)
    data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 2, 62, 1, 0x401100, 64, 0, 0, 64, 56, 2, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0x100, 0x401100, 0, 0x20, 0x20, 0x100)
    struct.pack_into('<IIQQQQQQ', data, 120, 1, 4, 0x200, 0x402200, 0, 0x20, 0x20, 0x100)
    data[0x100:0x106] = b'\xb8\x05\x00\x00\x00\xc3'
    data[0x106] = 0xc3
    case = dict(input='/private/original/exec', name='exec', pc=0x401100, file_offset=0x100, hook=0x401106, value=5)
    messages = [
        ('binary', dict(filename=case['input'], mode='exe')),
        ('trampoline', dict(name='passthru', template=['$instruction', '$continue'])),
        ('instruction', dict(address=case['pc'], length=5, offset=0x100)),
        ('instruction', dict(address=case['pc'] + 5, length=1, offset=0x105)),
        ('patch', dict(trampoline='passthru', offset=0x100)),
        ('emit', dict(filename='a.out', format='binary', mapping_size=4096)),
    ]
    rows = [dict(jsonrpc='2.0', method=method, params=params, id=i) for i, (method, params) in enumerate(messages)]
    return bytes(data), case, rows


def encode(rows):
    return b''.join((json.dumps(row, separators=(',', ':')) + '\n').encode() for row in rows)


def statistics(case, input_size, output_size):
    stdout = ('\x1b[32m.\x1b[0m\n\n'
        f"input_binary          = {case['input']}\n"
        'input_mode            = EXECUTABLE\n'
        'num_patched           = 1 / 1 (100.00%)\n'
        'num_patched_B1        = 1 / 1 (100.00%)\n'
        'num_patched_B2        = 0 / 1 (0.00%)\n'
        'num_patched_T1        = 0 / 1 (0.00%)\n'
        'num_patched_T2        = 0 / 1 (0.00%)\n'
        'num_patched_T3        = 0 / 1 (0.00%)\n'
        f'input_file_size       = {input_size}\n'
        f'output_file_size      = {output_size} (200.00%)\n').encode()
    stderr = f"debug: patched instruction 0x{case['pc']:x} [size=5, tactic=B1, trampoline=-0x8000..-0x7ff6]\n".encode()
    return stdout, stderr


def calibrate():
    successes, refusals = [], []
    def accepted(name, call):
        call(); successes.append(name)
    def rejected(name, call):
        try:
            call()
        except (AssertionError, ValueError, KeyError, TypeError, struct.error):
            refusals.append(name)
        else:
            raise AssertionError('corruption accepted: ' + name)
    data, case, rows = fixture(); image = elf64(data); raw = encode(rows)
    accepted('RX exact file translation', lambda: executable_offset(image, case['pc'], 6))
    assert executable_offset(image, case['pc'], 6) == 0x100
    accepted('exact one-site RPC', lambda: validate_rpc(raw, case, data, image))
    stdout, stderr = statistics(case, len(data), 2*len(data))
    accepted('exact B1 summary and debug witness', lambda: backend_stats(stdout, stderr, case, data, data*2))
    accepted('absolute trampoline coordinates', lambda: backend_stats(stdout, stderr.replace(b'-0x8000..-0x7ff6', b'[absolute] 0x8000..[absolute] 0x800a'), case, data, data*2))
    request = b'{"authored":"request"}\n'; helper_hash = 'a'*64
    receipt = dict(request_sha256=digest(request), helper_sha256=helper_hash, exit=0, wall_timeout=False,
        unexpected_descendants=[], absence_proof='ECHILD', stdout_sha256=digest(stdout), stderr_sha256=digest(stderr),
        elapsed_seconds=0.5, cleanup_events=[], cleanup_error=None, aborted=None, inputs_unchanged=True)
    accepted('exact bounded-helper success receipt', lambda: validate_helper_receipt(receipt, request, helper_hash, stdout, stderr))
    rejected('duplicate JSON key', lambda: loads('{"id":0,"id":0}'))
    rejected('non-JSON NaN', lambda: loads('{"elapsed":NaN}'))
    rejected('R metadata is not executable', lambda: executable_offset(image, 0x402200, 1))
    rejected('translation crosses file-backed extent', lambda: executable_offset(image, case['pc']+31, 2))
    rejected('unsigned virtual extent overflow', lambda: executable_offset(image, (1<<64)-1, 1))
    ambiguous = copy.deepcopy(image); ambiguous['headers'].append(copy.deepcopy(ambiguous['headers'][0]))
    rejected('ambiguous virtual ownership', lambda: executable_offset(ambiguous, case['pc'], 5))
    truncated = data[:119]
    rejected('truncated program headers', lambda: elf64(truncated))
    invalid = bytearray(data); struct.pack_into('<Q', invalid, 64+48, 3)
    rejected('non-power-of-two load alignment', lambda: elf64(invalid))
    def rpc_change(name, mutate):
        changed = copy.deepcopy(rows); mutate(changed)
        rejected(name, lambda: validate_rpc(encode(changed), case, data, image))
    rpc_change('wrong source path', lambda r: r[0]['params'].update(filename='/other'))
    rpc_change('wrong binary mode', lambda r: r[0]['params'].update(mode='dso'))
    rpc_change('extra action instruction', lambda r: r[1]['params']['template'].append(0xcc))
    rpc_change('wrong selected length', lambda r: r[2]['params'].update(length=4))
    rpc_change('wrong selected virtual address', lambda r: r[2]['params'].update(address=case['pc']+1))
    rpc_change('wrong selected file offset', lambda r: r[2]['params'].update(offset=0x101))
    rpc_change('boolean instruction length', lambda r: r[2]['params'].update(length=True))
    rpc_change('wrong patch offset', lambda r: r[-2]['params'].update(offset=0x105))
    rpc_change('wrong patch trampoline', lambda r: r[-2]['params'].update(trampoline='trap'))
    rpc_change('out-of-order RPC id', lambda r: r[3].update(id=2))
    rpc_change('extra patch', lambda r: r.insert(-1, copy.deepcopy(r[-2])))
    rpc_change('missing patch', lambda r: r.pop(-2))
    rpc_change('output path escape', lambda r: r[-1]['params'].update(filename='../a.out'))
    rpc_change('wrong mapping unit', lambda r: r[-1]['params'].update(mapping_size=8192))
    rpc_change('unknown method', lambda r: r[3].update(method='reserve'))
    rpc_change('unknown patch metadata', lambda r: r[-2]['params'].update(metadata={}))
    rejected('RPC incomplete final line', lambda: validate_rpc(raw[:-1], case, data, image))
    rejected('RPC duplicate JSON id', lambda: validate_rpc(raw.replace(b'"id":0', b'"id":0,"id":0', 1), case, data, image))
    def stat_change(name, old, new, debug=False):
        out, err = (stdout, stderr.replace(old, new)) if debug else (stdout.replace(old, new), stderr)
        rejected(name, lambda: backend_stats(out, err, case, data, data*2))
    stat_change('partial success', b'num_patched           = 1 / 1 (100.00%)', b'num_patched           = 0 / 1 (0.00%)')
    stat_change('fallback to B2', b'num_patched_B2        = 0 / 1 (0.00%)', b'num_patched_B2        = 1 / 1 (100.00%)')
    stat_change('duplicate statistic', b'num_patched_B1        = 1 / 1 (100.00%)', b'num_patched_B1        = 1 / 1 (100.00%)\nnum_patched_B1 = 1 / 1 (100.00%)')
    stat_change('wrong debug PC', b'0x401100', b'0x401101', True)
    stat_change('wrong debug length', b'size=5', b'size=4', True)
    stat_change('wrong debug tactic', b'tactic=B1', b'tactic=T2', True)
    stat_change('empty trampoline', b'-0x8000..-0x7ff6', b'-0x8000..-0x8000', True)
    stat_change('duplicate debug site', stderr, stderr+stderr, True)
    stat_change('warning is not a success', stderr, stderr+b'warning: changed behavior\n', True)
    stat_change('failed-site diagnostic', stderr, stderr+b'debug: failed to patch instruction at address 0x123 (5)\n', True)
    stat_change('missing success marker', b'\x1b[32m.\x1b[0m', b'')
    stat_change('failure marker', b'\x1b[32m.\x1b[0m', b'\x1b[32m.\x1b[0m\x1b[31mX\x1b[0m')
    stat_change('wrong input size', b'input_file_size       = 768', b'input_file_size       = 769')
    for key, value in [('exit', 1), ('exit', False), ('wall_timeout', True), ('unexpected_descendants', [123]),
                       ('absence_proof', None), ('stdout_sha256', 'b'*64), ('request_sha256', 'c'*64),
                       ('helper_sha256', 'd'*64), ('aborted', 'SIGTERM'), ('cleanup_error', 'deadline'),
                       ('inputs_unchanged', False), ('elapsed_seconds', float('inf')),
                       ('elapsed_seconds', -1), ('elapsed_seconds', 51)]:
        changed = copy.deepcopy(receipt); changed[key] = value
        rejected('helper ' + key + '=' + repr(value), lambda changed=changed: validate_helper_receipt(changed, request, helper_hash, stdout, stderr))
    assert len(successes) == 5 and len(refusals) == 53
    assert len(set(successes+refusals)) == 58
    # Preserve the entire original five/53 cohort before the two additive
    # receipt-consistency regressions from independent source review.
    for name, history in [('malformed cleanup event', [None]),
                          ('contradictory killed descendant', [dict(event='kill_requested', pid=123),
                             dict(event='reaped', pid=123, status=9)])]:
        changed = copy.deepcopy(receipt); changed['cleanup_events'] = history
        rejected(name, lambda changed=changed: validate_helper_receipt(changed, request, helper_hash, stdout, stderr))
    assert len(successes) == 5 and len(refusals) == 55
    assert len(set(successes+refusals)) == 60
    return dict(positive=len(successes), negative=len(refusals), successes=successes, refusals=refusals,
                e9_invocations=0, native_invocations=0, synthetic_parser_scope_only=True)


if __name__ == '__main__':
    print(json.dumps(calibrate(), indent=2))
