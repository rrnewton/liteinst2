#!/usr/bin/env python3
"""Rebuild and check 28 actual gateway/SUD/seccomp children on one CPU.

Run under taskset or a CPU allocator. Raw captures remain in a fresh target/
directory; stdout (and optional --output) is a compact, host-path-free receipt.
This qualifies this host mechanism, not the complete native-page runtime.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import shutil
import signal
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ("tools/page-entry/selected/native_seccomp.h",
           "tools/page-entry/selected/tests/native_pages/gateway_probe.c",
           "tools/page-entry/selected/tests/native_pages/gateway_probe.S",
           "evaluation/inprocess/native_gateway.py")
MODES = ("plain", "seccomp", "sud", "sud_seccomp")
OPS = ("vsyscall_gettimeofday", "vsyscall_time", "vsyscall_getcpu",
       "trusted_getpid", "outside_getpid", "compat_getpid", "x32_getpid")


def fact(path):
    raw = Path(path).read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def read_json(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def check(data, image, affinity, parent_status):
    """The prior 182 actual-cohort predicates, plus exact new header checks."""
    if len(data["events"]) != 28:
        raise ValueError("required 28 actual events")
    receipt = {"affinity": affinity, "parent_status": parent_status}
    checks = 0

    def need(test):
        nonlocal checks
        checks += 1
        if not test:
            raise ValueError("native evidence predicate " + str(checks))

    need(receipt['parent_status']['Seccomp'] == '0')
    need(data['gateway'][0] <= data['trusted_ip'] < data['gateway'][1])
    need(not(data['gateway'][0] <= data['outside_ip'] < data['gateway'][1]))
    # Bind each delivered vsyscall continuation to its unique actual CALL in
    # the retained ELF. Linux's emulated return precedes SIGSYS delivery.
    need(image[:7] == b'\x7fELF\x02\x01\x01')
    eh = struct.unpack_from('<16sHHIQQQIHHHHHH', image)
    need(eh[1] == 2 and eh[2] == 62)
    continuations = {}
    for op in range(3):
        target = 0xffffffffff600000 + op * 0x400
        pattern = b'\x48\xc7\xc0' + struct.pack('<I', target & 0xffffffff) + b'\xff\xd0'
        found = []
        for n in range(eh[10]):
            ph = struct.unpack_from('<IIQQQQQQ', image, eh[5] + n * eh[9])
            if ph[0] != 1 or not ph[1] & 1:
                continue
            blob = image[ph[2]:ph[2] + ph[5]]
            offset = blob.find(pattern)
            while offset >= 0:
                found.append(ph[3] + offset + len(pattern))
                offset = blob.find(pattern, offset + 1)
        need(len(found) == 1)
        continuations[op] = found[0]

    def returned(e):
        need(e['kind'] == 1 and e['wait_status'] == 0 and e['signal'] == 0)

    def trapped(e, code, reason, arch, nr, address):
        need(e['kind'] == 2 and e['wait_status'] == 125 * 256 and e['signal'] == signal.SIGSYS)
        need(e['code'] == code and e['errno'] == reason and e['arch'] == arch and e['syscall'] == nr)
        need(e['call_address'] == address)
        need(e['rip'] == (continuations[e['op']] if e['op'] < 3 else address))

    for i, e in enumerate(data['events']):
        mode, op = divmod(i, 7)
        need(e['mode'] == e['record_mode'] == mode and e['op'] == e['record_op'] == op)
        need(e['magic'] == 0x4757545950524f42 and e['child'] == e['pid'] == e['waited'])
        need(e['bytes'] == data['record_bytes'] and e['extra'] == 0 and e['stage'] == 3)
        if op == 3:
            returned(e)
            need(e['result'] == e['pid'])
        elif mode in (1, 3) and op < 3:
            trapped(e, 1, 3, 0xc000003e, (96, 201, 309)[op], 0xffffffffff600000 + op * 0x400)
            need(e['values'] == ([-1, -1, 0, 0] if op == 0 else [-1, 0, 0, 0] if op == 1 else [0xffffffff, 0xffffffff, 0, 0]))
        elif mode == 1 and op == 4:
            trapped(e, 1, 3, 0xc000003e, 39, data['outside_ip'])
        elif mode == 1 and op == 5:
            trapped(e, 1, 1, 0x40000003, 20, data['compat_ip'])
        elif mode in (1, 3) and op == 6:
            trapped(e, 1, 2, 0xc000003e, 0x40000000 | 39, data['trusted_ip'])
        elif mode in (2, 3) and op in (4, 5):
            trapped(e, 2, 0, 0xc000003e if op == 4 else 0x40000003, 39 if op == 4 else 20,
                    data['outside_ip'] if op == 4 else data['compat_ip'])
        elif mode == 0 or (mode == 2 and op < 3):
            returned(e)
            if op == 0:
                need(e['result'] == 0 and e['values'][0] > 0 and 0 <= e['values'][1] < 1000000)
            elif op == 1:
                need(e['result'] == e['values'][0] and e['result'] > 0)
            elif op == 2:
                need(e['result'] == 0 and e['values'][0] in receipt['affinity'] and e['values'][1] >= 0)
            elif op in (4, 5):
                need(e['result'] == e['pid'])
            else:
                need(e['result'] == -38)  # actual ENOSYS remains a failed operation
        elif mode == 2 and op == 6:
            returned(e)
            need(e['result'] == -38)
        else:
            raise ValueError('unhandled test row')
    need(checks == 182)
    need(data['record_bytes'] == 168 and data['layout'] == [8, 16, 64, 0, 4, 8])
    need(data['header_controls'] == 17 and data['supplied_raw_calls'] == 8)
    need(not(data['gateway'][0] <= data['compat_ip'] < data['gateway'][1]))
    return checks, continuations


def limits(cpu):
    def apply():
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
        resource.setrlimit(resource.RLIMIT_FSIZE, (2 << 20, 2 << 20))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='new compact JSON file; stdout always receives the same JSON')
    parser.add_argument('--private-dir', type=Path, help='new directory below target/ for raw captures')
    parser.add_argument('--cc', default='cc', help='actual compiler executable')
    args = parser.parse_args()
    private = args.private_dir or Path('target/evaluation/native-gateway') / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    private = (ROOT / private).resolve()
    if not private.is_relative_to(ROOT / 'target'):
        raise ValueError('private directory must be below target/')
    private.mkdir(parents=True, exist_ok=False)
    relative = str(private.relative_to(ROOT))
    environment = {'PATH': '/usr/bin:/bin:/usr/local/bin', 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}
    receipt = {'schema': 1, 'profile': 'native-gateway-v1', 'status': 'failed',
               'scope': 'Host confinement mechanism only; complete runtime integration not qualified.',
               'started_utc': datetime.now(timezone.utc).isoformat(),
               'affinity': sorted(os.sched_getaffinity(0)), 'commands': [],
               'bounds': {'native_wall_seconds': 15, 'parent_cpu_seconds': 5, 'child_cpu_seconds': 2,
                          'child_alarm_seconds': 3, 'address_space_bytes': 512 << 20, 'capture_bytes': 2 << 20},
               'environment': environment, 'sources': [{**fact(ROOT / name), 'path': name} for name in SOURCES],
               'final_errors': []}
    details = {'private_directory': str(private)}
    compiler = None

    def run(label, argv, wall=15, cpu=15):
        start = time.monotonic()
        out, err = private / (label + '.stdout'), private / (label + '.stderr')
        with out.open('xb') as stdout, err.open('xb') as stderr:
            proc = subprocess.Popen(argv, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr,
                                    start_new_session=True, preexec_fn=limits(cpu))
            timed_out = False
            try:
                code = proc.wait(timeout=wall)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(proc.pid, signal.SIGKILL)
                code = proc.wait()
        row = {'label': label, 'argv': argv, 'exit': code, 'timed_out': timed_out, 'reaped': True,
               'seconds': time.monotonic() - start, 'stdout': fact(out), 'stderr': fact(err)}
        receipt['commands'].append(row)
        if code or timed_out or err.stat().st_size:
            raise ValueError('command failed: ' + label)
        return out.read_bytes()

    try:
        if len(receipt['affinity']) != 1:
            raise ValueError('reserve exactly one CPU before invoking this evaluator')
        receipt['base_revision'] = run('revision', ['git', 'rev-parse', 'HEAD']).decode().strip()
        if not re.fullmatch('[a-f0-9]{40}', receipt['base_revision']):
            raise ValueError('revision shape')
        receipt['source_kind'] = 'exact working-tree inputs bound above, based on base_revision'
        status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        parent = {key: status[key].strip() for key in ('Seccomp', 'NoNewPrivs')}
        receipt['parent_status'] = parent
        if parent != {'Seccomp': '0', 'NoNewPrivs': '0'}:
            raise ValueError('plain native control requires an unfiltered parent')
        cpu = {}
        for line in Path('/proc/cpuinfo').read_text().splitlines():
            if not line:
                break
            if ':' in line:
                key, value = (item.strip() for item in line.split(':', 1))
                if key in ('vendor_id', 'cpu family', 'model', 'model name', 'stepping', 'microcode'):
                    cpu[key] = value
        receipt['hardware'] = {'kernel': platform.release(), 'machine': platform.machine(), 'cpu': cpu}
        found = shutil.which(args.cc, path=environment['PATH'])
        if not found:
            raise ValueError('compiler not found')
        compiler = Path(found).resolve()
        details['compiler'] = str(compiler)
        receipt['compiler'] = {'name': compiler.name, **fact(compiler)}
        version = run('compiler-version', [str(compiler), '--version'])
        receipt['compiler']['version'] = version.decode().splitlines()[0]
        argv = [str(compiler), '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-fno-stack-protector',
                '-fcf-protection=none', '-fno-pie', '-no-pie', '-Itools/page-entry/selected',
                SOURCES[1], SOURCES[2], '-o', relative + '/gateway-probe']
        run('compile', argv)
        raw = run('native', [relative + '/gateway-probe'], cpu=5)
        data = read_json(raw)
        checks, continuations = check(data, (private / 'gateway-probe').read_bytes(), receipt['affinity'], parent)
        receipt['comparisons'] = {'old_cohort_predicates': 182, 'total_python_predicates': checks,
                                  'supplied_header_controls': 17, 'header_layout': data['layout'],
                                  'event_bytes': 168, 'exact_waitpid_record_and_eof': True,
                                  'exact_call_address_and_elf_continuation': True,
                                  'refused_vsyscall_outputs_unchanged': True}
        receipt['cases'] = []
        for event in data['events']:
            operation = 'refused' if event['kind'] == 2 else 'failed' if event['result'] < 0 else 'completed'
            receipt['cases'].append({'mode': MODES[event['mode']], 'operation': OPS[event['op']],
                                     'status': operation, 'exit': os.waitstatus_to_exitcode(event['wait_status']),
                                     'signal': event['signal'], 'code': event['code'], 'reason': event['errno'],
                                     'arch': event['arch'], 'syscall': event['syscall'],
                                     'negative_return': event['result'] if event['result'] < 0 else None})
        receipt['totals'] = {'processes': 28, 'completed_operations': 12, 'refused_operations': 14,
                             'failed_enosys_operations': 2, 'plain_vsyscalls': 3, 'sud_only_vsyscalls': 3,
                             'seccomp_vsyscalls': 0, 'sud_seccomp_vsyscalls': 0, 'trusted_gateway_completions': 4}
        if [sum(c['status'] == key for c in receipt['cases']) for key in ('completed', 'refused', 'failed')] != [12, 14, 2]:
            raise ValueError('operation accounting')
        details['vsyscall_continuations'] = continuations
        receipt['status'] = 'passed'
    except Exception as error:
        receipt['error_type'] = type(error).__name__
        details['error'] = str(error)
    finally:
        try:
            after = [{**fact(ROOT / name), 'path': name} for name in SOURCES]
            receipt['source_unchanged'] = receipt['sources'] == after
            if not receipt['source_unchanged']:
                raise ValueError('source changed')
            if compiler is not None and receipt.get('compiler', {}).get('sha256') != fact(compiler)['sha256']:
                raise ValueError('compiler changed')
        except Exception as error:
            receipt['final_errors'].append(type(error).__name__)
            details['final_error'] = str(error)
        try:
            if (private / 'gateway-probe').exists():
                receipt['elf'] = fact(private / 'gateway-probe')
        except Exception as error:
            receipt['final_errors'].append(type(error).__name__)
            details['artifact_error'] = str(error)
        if receipt['final_errors']:
            receipt['status'] = 'failed'
        receipt['reproduce'] = ['python3', 'evaluation/inprocess/native_gateway.py']
        receipt['reproduce_condition'] = 'Reserve exactly one CPU; compiler and native command are bounded separately.'
        # Commands use repository-relative inputs. Private installation prefixes
        # of a compiler are replaced only in publication, with its full hash kept.
        if compiler is not None:
            for command in receipt['commands']:
                if command['argv'][0] == str(compiler):
                    command['argv'][0] = '{compiler:' + compiler.name + '}'
        encoded = json.dumps(receipt, sort_keys=True, indent=2, allow_nan=False) + '\n'
        (private / 'details.json').write_text(json.dumps(details, sort_keys=True, indent=2) + '\n')
        if re.search(r'/home/|devbig[0-9]+|internalfb\.com', encoded):
            raise ValueError('private location in public receipt')
        (private / 'receipt.json').write_text(encoded)
        if args.output:
            with args.output.open('x') as output:
                output.write(encoded)
        print(encoded, end='')
    return receipt['status'] != 'passed'


if __name__ == '__main__':
    raise SystemExit(main())
