#!/usr/bin/env python3
"""Reproduce the opt-in finite original-entry selected-instruction cohort."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import select
import shutil
import signal
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from checks import source
from run import hardware as host_hardware

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
PRODUCT = REPO/'tools/page-entry'
SELECTED = PRODUCT/'selected'
BUILD = REPO/'target/page-entry/selected'
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}
EH = struct.Struct('<16sHHIQQQIHHHHHH')
PH = struct.Struct('<IIQQQQQQ')
KEYS = set(('version scope source_patches status failure_code detail_abs detail_negative dependency_objects '
            'first_target_is_interpreter_entry interpreter_entry_faults nx_faults main_faults interpreter_faults '
            'dependency_faults vdso_selected cpuid rdtsc rdtscp syscalls forwarded tls_changes set_tid_address '
            'set_robust_list rseq mappings generations retired admissions sync_core kernel_errors partial_errors '
            'live_pages last_syscall last_mapping_syscall last_phase selected_profile selected_steps selected_selftests '
            'rdrand rdseed rdpid source_syscalls vdso_close_attempted vdso_close_observed vdso_close_result_abs '
            'vdso_close_result_negative vdso_closed selected_last_kind selected_last_width selected_last_destination '
            'selected_last_value selected_last_carry selected_last_input_destination selected_last_output_destination '
            'selected_last_status selected_last_phase selected_last_native_attempts builtin_kind builtin_phase '
            'builtin_enable_result_abs builtin_enable_result_negative builtin_restore_result_abs builtin_restore_result_negative '
            'builtin_a builtin_b builtin_c builtin_d').split())


def need(condition, message):
    if not condition:
        raise ValueError(message)


def fact(path):
    data = Path(path).read_bytes()
    return {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True)+'\n')


def invoke(row, output, cpu):
    process = None
    pidfd = None
    start = time.monotonic_ns()
    row.update(exit=None, timed_out=False, reaped=False, error=None, cleanup_errors=[])

    bounds = row.get('bounds', (3, 512 << 20, 16 << 20, 15))
    row['bounds'] = bounds
    def limits():
        os.sched_setaffinity(0, {cpu})
        for kind, value in ((resource.RLIMIT_CPU, bounds[0]), (resource.RLIMIT_AS, bounds[1]),
                            (resource.RLIMIT_FSIZE, bounds[2]), (resource.RLIMIT_CORE, 0)):
            resource.setrlimit(kind, (value, value))

    out, err = (output/(row['name']+suffix) for suffix in ('.stdout', '.stderr'))
    try:
        with out.open('xb') as stdout, err.open('xb') as stderr:
            process = subprocess.Popen(row['argv'], cwd=output, env=row.get('environment', ENV), stdout=stdout, stderr=stderr,
                                       start_new_session=True, preexec_fn=limits)
            row['pid'] = process.pid
            pidfd = os.pidfd_open(process.pid)
            if not select.select([pidfd], [], [], bounds[3])[0]:
                row['timed_out'] = True
                raise TimeoutError('command wall bound')
            # An exited, unreaped leader still pins the group identity. Close
            # any surviving build descendants before releasing that identity.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as exc:
                row['cleanup_errors'].append('kill: '+repr(exc))
            row['exit'] = process.wait(timeout=3)
            row['reaped'] = True
    except BaseException as exc:
        row['error'] = type(exc).__name__+': '+str(exc)
    finally:
        # Never signal a numeric process group after its leader was reaped.
        # Until wait(), the actual child pins that identity, including when its
        # pidfd is already readable but compiler children might still exist.
        if process is not None and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as exc:
                row['cleanup_errors'].append('kill: '+repr(exc))
            try:
                row['exit'] = process.wait(timeout=3); row['reaped'] = True
            except BaseException as exc:
                row['cleanup_errors'].append('wait: '+repr(exc))
        elif process is not None:
            row['exit'] = process.returncode; row['reaped'] = True
        if pidfd is not None:
            try:
                os.close(pidfd)
            except BaseException as exc:
                row['cleanup_errors'].append('pidfd_close: '+repr(exc))
        row['duration_ns'] = time.monotonic_ns()-start
        for stream, path in (('stdout', out), ('stderr', err)):
            try:
                row[stream] = dict(fact(path), file=path.name)
            except BaseException as exc:
                row['cleanup_errors'].append(stream+': '+repr(exc))
        try:
            save(output/(row['name']+'.json'), row)
        except BaseException as exc:
            row['cleanup_errors'].append('command_record: '+repr(exc))
    need(row['reaped'] and not row['error'] and not row['timed_out'] and not row['cleanup_errors'], 'command process/cleanup failed: '+row['name'])
    need(out.stat().st_size <= 65536 and err.stat().st_size <= 65536, 'capture bound')
    return out.read_bytes(), err.read_bytes()


def elf(path):
    data = Path(path).read_bytes(); need(len(data) >= EH.size, 'short ELF')
    h = EH.unpack_from(data)
    need(h[0][:7] == b'\x7fELF\2\1\1' and h[2] == 62 and h[9] == PH.size and 0 < h[10] <= 32, 'ELF header')
    need(h[5]+h[9]*h[10] <= len(data), 'ELF table extent')
    ph = [PH.unpack_from(data, h[5]+i*h[9]) for i in range(h[10])]
    return data, h, ph


def interpreter(path):
    data, _, ph = elf(path); rows = [p for p in ph if p[0] == 3]
    need(len(rows) == 1, 'one actual PT_INTERP')
    p = rows[0]; name = data[p[2]:p[2]+p[5]]
    need(name[:1] == b'/' and name[-1:] == b'\0' and b'\0' not in name[:-1], 'actual interpreter string')
    return Path(os.fsdecode(name[:-1])).resolve(strict=True)


def entry_bytes(path):
    data, h, ph = elf(path)
    rows = [p for p in ph if p[0] == 1 and p[1]&1 and p[3] <= h[4] and h[4]+15 <= p[3]+p[5]]
    need(len(rows) == 1, 'actual full entry byte owner')
    p = rows[0]; offset = p[2]+h[4]-p[3]
    return h[4], data[offset:offset+15]


def bridge_check(path):
    data, h, ph = elf(path)
    need(h[1] == 3 and not any(p[0] in (3, 7) for p in ph), 'freestanding ET_DYN/no PT_INTERP/TLS')
    dynamics = [p for p in ph if p[0] == 2]; need(len(dynamics) == 1, 'one dynamic table')
    p = dynamics[0]; tags = {}
    for at in range(p[2], p[2]+p[5], 16):
        tag, value = struct.unpack_from('<qQ', data, at)
        if not tag:
            break
        need(tag not in (1, 17, 23, 22), 'no imports/external/text relocation')
        need(tag not in tags, 'duplicate dynamic tag'); tags[tag] = value
    else:
        raise ValueError('unterminated bridge dynamic table')
    need(tags.get(9) == 24 and tags.get(8, 1)%24 == 0 and tags[8]//24 <= 4096, 'bounded RELA shape')
    rows = [p for p in ph if p[0] == 1 and p[3] <= tags[7] and tags[7]+tags[8] <= p[3]+p[5]]
    need(len(rows) == 1, 'RELA source extent'); p = rows[0]; offset = p[2]+tags[7]-p[3]
    for i in range(tags[8]//24):
        dest, info, _ = struct.unpack_from('<QQq', data, offset+i*24)
        need(info == 8 and any(p[0] == 1 and p[1]&2 and p[3] <= dest and dest+8 <= p[3]+p[6] for p in ph), 'relative writable relocation')
    return {'relative_relocations': tags[8]//24, 'imports': 0, 'tls': False, 'interpreter': False}


def object_row(data):
    lines = data.splitlines(); need(len(lines) == 1 and lines[0].startswith(b'LI2_LOADER '), 'one actual controller report')
    def unique(items):
        d = {}
        for k, v in items:
            need(k not in d, 'duplicate report key'); d[k] = v
        return d
    row = json.loads(lines[0][11:], object_pairs_hook=unique)
    need(set(row) == KEYS and row['scope'] == 'partial_selected_original_entry', 'closed selected report schema')
    need(all(type(v) is int and 0 <= v < 2**64 for k, v in row.items() if k != 'scope'), 'actual numeric fields')
    need(row['version'] == 1 and row['selected_profile'] == 1 and row['source_patches'] == 0, 'actual mechanism')
    need(row['selected_selftests'] == row['first_target_is_interpreter_entry'] == row['interpreter_entry_faults'] == 1, 'real selftest/first original entry')
    need(row['admissions'] == row['sync_core'] == row['main_faults'] == row['dependency_faults'] == 0, 'no full-page admission')
    need(row['nx_faults'] == row['interpreter_faults'] and row['generations'] == row['retired']+row['live_pages'], 'actual counter equations')
    need(row['vdso_close_attempted'] == row['vdso_close_observed'] == row['vdso_closed'] == 1 and
         row['vdso_close_result_abs'] == row['vdso_close_result_negative'] == 0, 'actual vDSO closure')
    need(all(row[k] == 0 for k in ('cpuid', 'rdtsc', 'rdtscp', 'vdso_selected', 'tls_changes', 'set_tid_address',
                                   'set_robust_list', 'rseq', 'kernel_errors', 'partial_errors', 'builtin_kind', 'builtin_phase',
                                   'builtin_enable_result_abs', 'builtin_enable_result_negative', 'builtin_restore_result_abs',
                                   'builtin_restore_result_negative', 'builtin_a', 'builtin_b', 'builtin_c', 'builtin_d')), 'no unclaimed operations')
    return row


def check_stream(spec, row, command, stdout, native, hardware):
    failure = spec.get('failure', 0)
    need(row['failure_code'] == failure and row['detail_abs'] == spec.get('detail', 0) and not row['detail_negative'], 'exact outcome')
    need(row['selected_steps'] == spec['steps'] and row['nx_faults'] == spec['faults'] and
         row['source_syscalls'] == row['syscalls'] == spec['syscalls'], 'exact per-instruction dispatch')
    need(row['dependency_objects'] == 1 and row['mappings'] == 1 and row['generations'] == 5 and
         row['retired'] == 2 and row['live_pages'] == 3, 'actual fixture ownership plus selftest')
    need(row['last_mapping_syscall'] == 11 and row['last_phase'] == 5, 'selftest mapping closure')
    counts = [row[k] for k in ('rdrand', 'rdseed', 'rdpid')]
    expected = [0, 0, 0]
    if spec['kind'] and not failure:
        expected[spec['kind']-2] = 1
    need(counts == expected, 'one actual provider sample')
    if not spec['kind']:
        need(all(row[key] == 0 for key in KEYS if key.startswith('selected_last_')), 'no fabricated provider outcome')
    if failure:
        need(command['exit'] == row['status'] == 125 and stdout == b'' and row['forwarded'] == 0, 'real pre-effect refusal')
        if spec['name'] == 'rsp_refusal':
            need(row['selected_last_status'] == 7 and row['selected_last_phase'] == row['selected_last_native_attempts'] == 0 and
                 row['selected_last_kind'] == 2 and row['selected_last_width'] == 64 and row['selected_last_destination'] == 4,
                 'RSP refused before sample')
        else:
            need(native['exit'] == 0 and native['stdout'] == bytes(32) and row['last_syscall'] == 13, 'native reserved-query success vs exact refusal')
        return
    need(row['forwarded'] == row['syscalls'] and row['last_syscall'] == 60, 'genuine exit forwarding')
    if spec['kind']:
        need(row['selected_last_kind'] == spec['kind'] and row['selected_last_width'] == spec['width'] and
             row['selected_last_destination'] == 7 and row['selected_last_status'] == 0 and
             row['selected_last_phase'] == 4 and row['selected_last_native_attempts'] == 1, 'retained genuine sample')
        value, carry = row['selected_last_value'], row['selected_last_carry']
        need(value < 2**spec['width'] and carry in (0, 1), 'exact sampled width/CF')
        if spec['kind'] == 4:
            need(value == hardware['rdpid'] and value < 2**32 and carry == 0 and native['exit'] == (value&255), 'independent pinned native RDPID')
        else:
            need(carry or value == 0, 'actual failed random sample is zero; never retry')
        expected_out = ((row['selected_last_input_destination'] & ~65535) | value) if spec['width'] == 16 else value
        need(row['selected_last_output_destination'] == expected_out and row['status'] == (expected_out&0xffffffff) and
             command['exit'] == (value&255), 'actual destination -> raw exit kernel result')
        need(stdout == native['stdout'] == b'', 'selected stream output')
    else:
        need(command['exit'] == native['exit'] == row['status'] == spec['exit'], 'deterministic native/gated result')
        need(stdout == native['stdout'] == (bytes(32) if spec['category'] == 'query' else b''), 'actual query output/header baseline')



def publish(path, record):
    """Write compact typed evidence; private commands and raw captures stay in target."""
    commands = []
    for command in record['commands']:
        commands.append({k: command.get(k) for k in ('name', 'exit', 'timed_out', 'reaped', 'duration_ns', 'bounds')} | {
            'command_sha256': hashlib.sha256(json.dumps(command['argv'], separators=(',', ':')).encode()).hexdigest(),
            'error_type': (command.get('error') or '').split(':')[0] or None,
            'cleanup_error_count': len(command.get('cleanup_errors', [])),
            'captures': {stream: {k: command[stream][k] for k in ('bytes', 'sha256')} for stream in ('stdout', 'stderr') if stream in command}})
    public = {k: record.get(k) for k in ('schema', 'status', 'scope', 'expected_revision', 'started_utc', 'cpu', 'environment',
              'reproduce', 'source', 'source_unchanged', 'hardware', 'hardware_before', 'hardware_after', 'bounds', 'archive', 'bridge_elf', 'cases', 'toolchain')}
    public.update(commands=commands, failure_type=(record.get('error') or '').split(':')[0] or None,
                  final_error_count=len(record['final_errors']),
                  input_manifest_sha256=hashlib.sha256(json.dumps(record['inputs_before'], sort_keys=True).encode()).hexdigest(),
                  artifact_manifest_sha256=hashlib.sha256(json.dumps(record['binaries_before'], sort_keys=True).encode()).hexdigest(),
                  tool_hashes={k: {f: v[f] for f in ('bytes', 'sha256')} for k, v in record.get('tools', {}).items()})
    text = json.dumps(public, indent=2, sort_keys=True, allow_nan=False)+'\n'
    need(not any(value and len(value)>1 and value in text for value in (str(Path.home()), str(REPO), platform.node(), '/home/')), 'private location in public receipt')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output: output.write(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--library-root', action='append', type=Path)
    args = ap.parse_args()
    need(len(args.expect_revision) == 40 and all(c in '0123456789abcdef' for c in args.expect_revision), 'exact revision')
    need(len(os.sched_getaffinity(0)) == 1, 'one externally reserved CPU')
    args.cpu = next(iter(os.sched_getaffinity(0)))
    args.library_root = args.library_root or [Path('/usr/lib64')]
    os.chdir(REPO)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-page-selected-'+args.expect_revision[:12]
    output = REPO/'target/evaluation/inprocess'/name
    output.mkdir(parents=True, exist_ok=False)
    public = ROOT/'results'/(name+'.json')
    record = {'schema': 1, 'status': 'failed', 'scope': '16 finite original-entry cases; no full ABI/B2/real-ls success claim',
              'cpu': args.cpu, 'environment': ENV, 'expected_revision': args.expect_revision, 'started_utc': stamp,
              'reproduce': ['python3', 'evaluation/inprocess/page_selected.py', '--expect-revision', args.expect_revision, *[x for p in args.library_root for x in ('--library-root', str(p))]],
              'source': None, 'source_unchanged': False, 'commands': [], 'cases': [], 'error': None,
              'bounds': {'cpu_seconds_per_process': 3, 'wall_seconds_per_command': 15, 'memory_bytes': 512 << 20,
                         'file_bytes': 16 << 20, 'parallel_commands': 1}, 'final_errors': []}
    pins = {}; binaries = {}

    def pin(path):
        path = Path(path).resolve(); observed = fact(path)
        need(str(path) not in pins or pins[str(path)] == observed, 'pinned input changed')
        pins[str(path)] = observed; return path

    def run(name, argv, expected=0, build=False):
        need(all(fact(path) == value for path, value in pins.items()), 'input changed before command')
        need(all(fact(path) == value for path, value in binaries.items()), 'binary changed before command')
        row = {'name': name, 'argv': list(map(str, argv))}
        if build:
            row['bounds'] = (120, 2 << 30, 128 << 20, 150)
            row['environment'] = dict(ENV, CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='1', CARGO_NET_OFFLINE='true', CARGO_TARGET_DIR=str(REPO/'target'),
                                      LI2_CC=str(tools['cc']), LI2_CARGO=str(tools['cargo']), RUSTC=str(tools['rustc']))
            for key in ('HOME', 'CARGO_HOME', 'RUSTUP_HOME'):
                if key in os.environ: row['environment'][key] = os.environ[key]
        record['commands'].append(row)
        out, err = invoke(row, output, args.cpu)
        need((row['exit'] == expected) if expected is not None else (type(row['exit']) is int and 0 <= row['exit'] <= 255), 'exit mismatch: '+name)
        return row, out, err

    try:
        record['source'] = source()
        need(record['source']['revision'] == args.expect_revision, 'revision differs')
        record['hardware'] = host_hardware(args.cpu)
        paths = subprocess.check_output(['git', 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'], cwd=REPO, timeout=5).split(b'\0')
        for path in paths:
            if path and not os.fsdecode(path).startswith('evaluation/inprocess/results/'):
                pin(REPO/os.fsdecode(path))
        python = pin(sys.executable)
        tools = {name: pin(shutil.which(name, path=ENV['PATH'])) for name in ('cc', 'sh', 'nm')}
        tools['python3'] = python
        rustup = shutil.which('rustup')
        need(rustup is not None, 'installed Rust toolchain resolver')
        pin(rustup)
        for name in ('cargo', 'rustc'):
            actual = subprocess.check_output([rustup, 'which', name], text=True, timeout=5).strip()
            need(Path(actual).is_absolute(), 'absolute installed Rust tool')
            tools[name] = pin(actual)
        record['tools'] = {name: {'path': str(path), **pins[str(path)]} for name, path in tools.items()}
        record['kernel'] = platform.release()
        record['revision'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True, timeout=5).strip()
        _, version, err = run('compiler-version', [tools['cc'], '--version']); need(not err, 'compiler version stderr'); record['compiler_version'] = version.decode()
        run('build', [tools['sh'], SELECTED/'build.sh'], build=True)
        archive = pin(BUILD/'decoder.a')
        bridge, observe = BUILD/'bridge-selected.so', BUILD/'observe'
        record['archive'] = fact(archive)
        dep = pin(BUILD/'decoder.d').read_text()
        need(all(str(SELECTED/'decoder/src'/name) in dep for name in ('lib.rs', 'abi.rs', 'arena.rs', 'decode.rs', 'scan.rs')), 'exact decoder source dep-info')
        for name in ('decoder-rustc.txt', 'decoder-cargo.txt'):
            record.setdefault('toolchain', {})[name] = pin(BUILD/name).read_text().strip()
        for path in (bridge, observe): binaries[str(path)] = fact(path)
        _, out, err = run('undefined', [tools['nm'], '-u', bridge]); need(out == err == b'', 'no unresolved bridge symbols')
        record['bridge_elf'] = bridge_check(bridge)
        _, out, err = run('hardware-before', [observe]); need(not err, 'hardware observation stderr')
        hardware = json.loads(out); need(hardware['cpu'] == args.cpu, 'actual hardware CPU'); record['hardware_before'] = hardware
        image_dir = output/'images'; run('images', [python, ROOT/'page_selected_images.py', image_dir])
        specs = json.loads((image_dir/'images.json').read_text()); need(len(specs) == 15, 'exact generated cohort')
        binaries[str(image_dir/'images.json')] = fact(image_dir/'images.json')
        for spec in specs:
            original, interp = Path(spec['original']), Path(spec['interpreter'])
            need(fact(original)['sha256'] == spec['original_sha256'] and fact(interp)['sha256'] == spec['interpreter_sha256'], 'generated exact images')
            need(interpreter(original) == interp, 'real original PT_INTERP association')
            code, h, ph = elf(interp)
            need(h[1] == 3 and h[4] == spec['entry_vaddr'] and not any(p[0] == 3 for p in ph), 'unchained exact ET_DYN interpreter')
            stream = bytes.fromhex(spec['exact_stream_hex'])
            need(code[spec['entry_file_offset']:spec['entry_file_offset']+len(stream)] == stream, 'actual entry stream bytes')
            for path in (original, interp, Path(spec['library_root'])/'li2-stream.so'): binaries[str(path)] = fact(path)
            carrier = original.parent/'carrier'
            run('make-'+spec['name'], [python, PRODUCT/'carrier.py', 'make', original, bridge, carrier]); binaries[str(carrier)] = fact(carrier)
            native = None
            if spec['name'] != 'rsp_refusal':
                cmd, out, err = run('native-'+spec['name'], [original], None)
                need(not err, 'native stream stderr'); native = {'exit': cmd['exit'], 'stdout': out}
            namespace = output/('namespace-'+spec['name'])
            cmd, out, err = run('gated-'+spec['name'], [python, PRODUCT/'carrier.py', 'exec-loader', '--library-root',
                               spec['library_root'], '--namespace', namespace, carrier, original, '--', original], None)
            row = object_row(err); check_stream(spec, row, cmd, out, native, hardware)
            ns = json.loads((namespace/'namespace.json').read_text())
            need(len(ns['objects']) == 1 and ns['objects'][0]['sha256'] == spec['interpreter_sha256'] and ns['objects'][0]['seals'] == 15, 'actual sealed exact interpreter dependency')
            for name in ('namespace.json', 'launch.json'): binaries[str(namespace/name)] = fact(namespace/name)
            record['cases'].append({'name': spec['name'], 'result': row, 'status': 'passed'})
        # This is deliberately an unsupported program control, never ls
        # execution credit. Require the supported first MOV, then exact CALL refusal.
        ls = pin('/bin/ls'); loader = pin(interpreter(ls)); pc, bytes_ = entry_bytes(loader)
        _, out, err = run('ls-entry-decode', [observe, 'decode', str(pc), bytes_.hex()]); need(not err, 'entry decode stderr')
        first = json.loads(out)
        need(bytes_[:3] == bytes.fromhex('4889e7') and first['abi'] == 1 and first['decode_status'] == 0 and first['kind'] == 0 and
             first['step_disposition'] == 1 and first['length'] == 3 and first['next_pc'] == pc+3, 'actual ld.so initial MOV RDI,RSP')
        _, out, err = run('ls-call-decode', [observe, 'decode', str(pc+3), bytes_[3:].hex()]); need(not err, 'call decode stderr')
        decoded = json.loads(out)
        need(bytes_[3] == 0xe8 and decoded['abi'] == 1 and decoded['decode_status'] == 0 and decoded['kind'] == 0 and
             decoded['length'] == 5 and decoded['step_disposition'] != 1, 'actual ld.so next near CALL unsupported')
        record['ls_entry'] = {'source': str(loader), 'bytes': bytes_.hex(), 'first': first, 'decoded': decoded}
        carrier = output/'ls-carrier'; run('make-ls', [python, PRODUCT/'carrier.py', 'make', ls, bridge, carrier]); binaries[str(carrier)] = fact(carrier)
        _, out, err = run('native-ls', [ls, '-d', '.']); need(out == b'.\n' and not err, 'real native ls baseline')
        argv = [python, PRODUCT/'carrier.py', 'exec-loader']
        for path in args.library_root: argv += ['--library-root', path.resolve()]
        namespace = output/'namespace-ls'
        argv += ['--namespace', namespace, carrier, ls, '--', ls, '-d', '.']
        _, out, err = run('gated-ls-unsupported', argv, 125); need(not out, 'no pretend ls output')
        row = object_row(err)
        need(row['failure_code'] == 632 and row['detail_abs'] == decoded['code'] and row['detail_negative'] == 0 and
             row['selected_steps'] == 1 and row['source_syscalls'] == row['syscalls'] == row['forwarded'] == 0 and
             row['nx_faults'] == 2 and row['status'] == 125, 'exact original unsupported opcode refusal')
        need(all(row[key] == 0 for key in KEYS if key.startswith('selected_last_')) and
             row['rdrand'] == row['rdseed'] == row['rdpid'] == 0, 'no selected execution credit for ls refusal')
        for name in ('namespace.json', 'launch.json'): binaries[str(namespace/name)] = fact(namespace/name)
        ns = json.loads((namespace/'namespace.json').read_text())
        for item in ns['objects']:
            need(item['seals'] == 15 and fact(item['source'])['sha256'] == item['sha256'], 'actual sealed ls dependency source'); pin(item['source'])
        record['cases'].append({'name': 'ls-unsupported', 'result': row, 'status': 'expected_refusal'})
        _, out, err = run('hardware-after', [observe]); need(not err, 'hardware final stderr')
        record['hardware_after'] = json.loads(out); need(record['hardware_after'] == hardware, 'same pinned native ID/features')
        need(len(record['cases']) == 16, 'full finite cohort')
        record['source_unchanged'] = source() == record['source']
        need(record['source_unchanged'], 'committed source changed')
        record['status'] = 'passed'
    except BaseException as exc:
        record['error'] = type(exc).__name__+': '+str(exc)
    finally:
        record['inputs_before'] = pins; record['binaries_before'] = binaries
        for name, before in (('inputs_after', pins), ('binaries_after', binaries)):
            observed = {}; record[name] = observed
            for path, expected in before.items():
                try:
                    observed[path] = fact(path)
                    need(observed[path] == expected, 'changed')
                except BaseException as exc:
                    record['final_errors'].append(path+': '+repr(exc))
        if record['final_errors']:
            record['status'] = 'failed'
            if record['error'] is None: record['error'] = 'final exact input/artifact closure failed'
        save(output/'receipt.json', record)
        publish(public, record)
    print(json.dumps({'status': record['status'], 'cases': len(record['cases']), 'error': record['error']}))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
