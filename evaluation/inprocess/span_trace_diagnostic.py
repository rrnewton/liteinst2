#!/usr/bin/env python3
"""Bounded diagnosis of a retained finite-TRACE artifact; never qualification.

Reserve one CPU before invoking this script. Perf and snapshots use separate
subjects. Snapshot fields are unsynchronized observations, not coherent state.
The collector revision may differ from the authenticated artifact revision.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import resource
import select
import signal
import stat
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ENV = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1')
SUBJECT = [10, 512 << 20, 16 << 20, 20]
TOOL = [10, 256 << 20, 16 << 20, 20]
INSPECT = [10, 256 << 20, 4 << 20, 20]
GIT_READS = []
LAUNCH = 'tools/page-entry/selected/tests/scalar_span_trace_app/launch.py'
LAUNCH_SOURCES = (
    'evaluation/admission/backing_cleanup.py', 'evaluation/admission/backing_cleanup_query.py',
    'evaluation/admission/core_5cda_inventory.py', 'evaluation/admission/core_813_inventory.py',
    'evaluation/admission/core_cc846_inventory.py', 'evaluation/admission/dynamic_admission.py',
    'evaluation/admission/dynamic_matrix.py', 'evaluation/admission/inventory_copy.py',
    'evaluation/admission/inventory_digest.py', 'evaluation/admission/inventory_splice.py',
    'evaluation/admission/inventory_syntax.py', 'evaluation/admission/native_fixtures.py',
    'evaluation/admission/parsing.py', 'evaluation/admission/precontext_native.py',
    'evaluation/admission/processes.py', 'evaluation/admission/recorder_shards_inventory.py',
    'evaluation/admission/run.py', 'evaluation/precontext/verify.py', 'evaluation/inprocess/checks.py',
    'evaluation/inprocess/page_selected.py', 'evaluation/inprocess/page_selected_process.py',
    'evaluation/inprocess/run.py', 'tools/page-entry/carrier.py', 'tools/page-entry/namespace.py', LAUNCH,
    'evaluation/admission/core_5cda_inventory.json', 'evaluation/admission/core_813_inventory.json',
    'evaluation/admission/core_cc846_inventory.json', 'evaluation/admission/recorder_shards_inventory.json')
EXPRESSIONS = tuple('selected_scalar_span.' + x for x in (
    'offers', 'closed', 'resumed', 'hash_misses', 'candidates', 'source_misses',
    'plan_misses', 'capacity_misses', 'publications', 'hits', 'entries', 'completed',
    'events', 'plan_checks', 'rseq_checks', 'current.ingress.frame.greg[16]',
    'current.before.frame.greg[16]', 'current.transfer.pc')) + (
    'selected_chain.steps', 'selected_chain.fallbacks', 'selected_chain.event_id') + tuple(
    'selected_scalar_span.refusals[' + str(i) + ']' for i in range(4))


def need(ok, code):
    if not ok:
        raise ValueError(code)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def fact_bytes(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def fact(path):
    path = Path(path)
    need(path.is_file(), 'missing_regular_input')
    return fact_bytes(path.read_bytes())


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')


def hardware(cpu):
    rows = [dict((k.strip(), v.strip()) for line in block.splitlines()
                 for k, sep, v in [line.partition(':')] if sep)
            for block in Path('/proc/cpuinfo').read_text().split('\n\n')]
    row = next(x for x in rows if x.get('processor') == str(cpu))
    release = platform.release()
    return {k: row.get(k) for k in ('vendor_id', 'model name', 'cpu family', 'model', 'stepping', 'microcode')} | dict(
        architecture=platform.machine(), kernel_version=re.match(r'[0-9.]+', release)[0],
        kernel_release_sha256=hashlib.sha256(release.encode()).hexdigest(), cpu=cpu,
        isa_flags=row.get('flags', '').split())


def git(root, *args):
    argv = ['/usr/bin/git', '--no-replace-objects', '-C', str(root),
            '-c', 'core.fsmonitor=false', '-c', 'maintenance.auto=false', *args]
    row = dict(argv=argv, timeout_seconds=20, start_ns=time.monotonic_ns(), exit=None)
    GIT_READS.append(row)
    try:
        value = subprocess.run(argv, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        row.update(exit=value.returncode, stdout=fact_bytes(value.stdout), stderr=fact_bytes(value.stderr))
        need(value.returncode == 0 and not value.stderr, 'git_metadata_read')
        return value.stdout
    except BaseException as exc:
        row['error'] = type(exc).__name__
        raise
    finally:
        row['duration_ns'] = time.monotonic_ns() - row['start_ns']


class Child:
    """One process group; retain the leader until group cleanup and wait4."""
    def __init__(self, name, argv, bounds, directory, cpu, commands, children, env=ENV, record=False):
        self.p = None
        self.pidfd = None
        self.paths = {k: directory / (name + '.' + k) for k in ('stdout', 'stderr')}
        self.row = dict(name=name, argv=argv, bounds=bounds, environment=env, exit=None, launched=False,
                        timed_out=False, reaped=False, cleanup_errors=[], error=None,
                        start_ns=time.monotonic_ns())
        commands.append(self.row)
        children.append(self)
        descriptors = []
        try:
            if record:
                self.paths['record'] = directory / (name + '.record')
                fd = os.open(self.paths['record'], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                descriptors.append(fd)
                need(fd == 3, 'observer_must_be_actual_fd3')
            def limits():
                os.sched_setaffinity(0, {cpu})
                for kind, value in ((resource.RLIMIT_CPU, bounds[0]), (resource.RLIMIT_AS, bounds[1]),
                                    (resource.RLIMIT_FSIZE, bounds[2]), (resource.RLIMIT_CORE, 0)):
                    resource.setrlimit(kind, (value, value))
            with self.paths['stdout'].open('xb') as out, self.paths['stderr'].open('xb') as err:
                self.p = subprocess.Popen(argv, cwd=directory, env=env, stdout=out, stderr=err,
                    start_new_session=True, pass_fds=tuple(descriptors), preexec_fn=limits)
            self.row.update(pid=self.p.pid, launched=True)
            self.pidfd = os.pidfd_open(self.p.pid)
        except BaseException as exc:
            self.row['error'] = repr(exc)
            self.finish()
            raise
        finally:
            for fd in descriptors:
                os.close(fd)

    def ready(self, seconds=0):
        return bool(select.select([self.pidfd], [], [], max(0, seconds))[0])

    def finish(self, interrupt=False):
        if self.row['reaped']:
            return self.row
        try:
            if self.p is not None:
                if interrupt and self.pidfd is not None and not self.ready():
                    os.killpg(self.p.pid, signal.SIGINT)
                    self.row['stop_requested'] = 'SIGINT_after_observation_interval'
                remaining = self.row['bounds'][3] - (time.monotonic_ns() - self.row['start_ns']) / 1e9
                if self.pidfd is not None and not self.ready(remaining):
                    self.row['timed_out'] = True
                # Do not poll()/wait() first: an unreaped leader pins the PGID.
                try:
                    os.killpg(self.p.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 3
                pid, status, usage = os.wait4(self.p.pid, os.WNOHANG)
                while pid == 0 and time.monotonic() < deadline:
                    select.select([], [], [], .02)
                    pid, status, usage = os.wait4(self.p.pid, os.WNOHANG)
                need(pid == self.p.pid, 'killed_child_not_reaped')
                self.p.returncode = os.waitstatus_to_exitcode(status)
                self.row.update(exit=self.p.returncode, reaped=True,
                    user_cpu_ns=round(usage.ru_utime * 1e9), system_cpu_ns=round(usage.ru_stime * 1e9),
                    max_rss_kib=usage.ru_maxrss)
        except BaseException as exc:
            self.row['cleanup_errors'].append(repr(exc))
        finally:
            if self.pidfd is not None:
                os.close(self.pidfd)
                self.pidfd = None
            self.row['duration_ns'] = time.monotonic_ns() - self.row['start_ns']
            self.row['captures'] = {k: fact(p) for k, p in self.paths.items() if p.is_file()}
        return self.row


def clean(child, exits):
    row = child.finish()
    need(row['reaped'] and not row['timed_out'] and not row['error'] and not row['cleanup_errors']
         and row['exit'] in exits, 'diagnostic_tool_failed')
    return row


def context(root, public_path, revision, directory):
    public = json.loads(public_path.read_bytes())
    private_path = root / 'target/evaluation/inprocess' / public_path.stem / 'receipt.json'
    need(fact(private_path) == public['private_receipt'], 'closed_receipt_identity')
    prior = json.loads(private_path.read_bytes())
    need(re.fullmatch('[0-9a-f]{40}', revision) and
         public['expected_revision'] == prior['expected_revision'] == prior['source']['revision'] == revision,
         'exact_artifact_revision')
    need(git(root, 'rev-parse', revision + '^{tree}').decode().strip() == prior['source']['tree'],
         'historical_committed_tree')
    need(public['profile'] == prior['profile'] == 'scalar-span-trace-finite-v1' and
         public['status'] == prior['status'] and public['status'] in ('passed', 'failed') and
         public['cleanup_complete'] is prior['cleanup_complete'] is True and
         public['source_unchanged'] is prior['source_unchanged'] is True and not prior['final_errors'] and
         prior['source'] == prior['source_after'] and prior['source']['tracked_clean'] is True and
         prior['source']['head_sources_match'] is True, 'closed_finite_receipt')
    for key in ('inputs', 'artifacts', 'aliases'):
        need(prior[key] == prior[key + '_before'] == prior[key + '_after'], 'original_closed_' + key)
    for key, field in (('inputs', 'input_manifest_sha256'), ('artifacts', 'artifact_manifest_sha256'),
                       ('commands', 'commands_sha256')):
        need(digest(prior[key]) == public[field], 'public_private_' + key)
    need(public['command_count'] == len(prior['commands']) and public['final_error_count'] == 0,
         'original_command_closure')
    need(all(x['reaped'] is True and not x['cleanup_errors'] for x in prior['commands']),
         'all_original_children_closed')
    need(fact(public_path.with_suffix('.csv')) == {k: public['csv'][k] for k in ('bytes', 'sha256')},
         'public_csv_identity')
    rows = [x for x in prior['commands'] if x['name'] == 'subject-gated-0-0']
    need(len(rows) == 1, 'one_retained_mode0')
    row = rows[0]
    need(row['bounds'] == [30, 512 << 20, 16 << 20, 60] and row['environment'] == ENV,
         'original_subject_bounds_environment')
    argv = row['argv'].copy()
    fixed = ['--root', str(root), '--role', 'gated', '--mode', '0', '--control', '0']
    need(argv[1:3] == ['-B', str(root / LAUNCH)] and argv[3:11] == fixed and
         argv[-2:] == ['--record-fd', '3'] and len(argv) == 25, 'exact_mode0_launch_shape')
    need([argv[i] for i in (11, 13, 15, 17, 19, 21)] ==
         ['--original', '--preparation', '--library-root', '--library-root', '--carrier', '--namespace'],
         'exact_retained_option_positions')
    launch_root = directory / 'launch-root'
    pinned = {}
    def pin(path, expected):
        path = Path(path)
        value = fact(path)
        need(value == {k: expected[k] for k in ('bytes', 'sha256')}, 'actual_input_identity')
        if str(path) in prior['aliases']:
            need(str(path.resolve(strict=True)) == prior['aliases'][str(path)], 'actual_input_alias')
        if 'mode' in expected:
            need(stat.S_IMODE(path.stat().st_mode) == expected['mode'], 'actual_input_mode')
        pinned[str(path)] = dict(value, mode=stat.S_IMODE(path.stat().st_mode),
                                 resolved=str(path.resolve(strict=True)))
        return path
    # Snapshot the exact historical Python import closure, including its four
    # import-time JSON inventories. No current admission policy is substituted.
    historical = {}
    for name in LAUNCH_SOURCES:
        raw = git(root, 'show', revision + ':' + name)
        expected = fact_bytes(raw)
        # The original input inventory includes imported Python, while these
        # four JSON files are bound by its whole committed source/tree closure
        # and by the unchanged modules' literal import-time SHA checks.
        if name == 'evaluation/admission/run.py':
            # checks.py loads this exact historical module dynamically. The
            # old ordinary input list omits it; the committed tree binds it.
            need(expected['sha256'] == 'd9462b5ec03f3085564907d0fa1d42e882d49900651e05899d5b3f4122ddab3f',
                 'exact_historical_admission_loader')
        elif name == 'evaluation/precontext/verify.py':
            # This dynamic import is absent from the old input list. The exact
            # committed blob and the input-pinned importer's literal SHA bind it.
            verify_sha = '9336515811ee0a9867e5cfbb14336a87bba63874b3489e6cda8a62bc882599fe'
            need(expected['sha256'] == verify_sha and
                 (launch_root / 'evaluation/admission/precontext_native.py').read_bytes().count(
                     ("VERIFY_SHA256 = '" + verify_sha + "'").encode()) == 1,
                 'exact_historical_dynamic_import')
        elif name.endswith('.py'):
            need(expected == prior['inputs'][str(root / name)], 'historical_launch_source_identity')
        historical[name] = expected
        path = launch_root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        pin(path, expected)
    executable = pin(argv[0], prior['inputs'][str(Path(argv[0]).resolve())])
    # Preserve every observed Python runtime input, not Cargo/compiler inputs
    # that will not participate in this no-build diagnostic.
    python_prefix = str(executable.resolve().parent.parent) + '/'
    for name, expected in prior['inputs'].items():
        if name.startswith(python_prefix) or '/site-packages/' in name or (
                not name.startswith(str(root) + '/') and re.search(r'\.so(?:\.[0-9]+)*$', name)):
            pin(name, expected)
    for key, path in (('original', argv[12]), ('carrier', argv[20]),
                      ('bridge', prior['release_build']['argv'][-1])):
        pin(path, prior['artifacts'][path])
        need({k: prior['artifacts'][path][k] for k in ('bytes', 'sha256')} == prior['subject_artifacts'][key],
             'retained_subject_artifact_join')
    for value in prior['runtime_libraries'].values():
        pin(value['path'], value)
    pin('/etc/ld.so.cache', prior['inputs']['/etc/ld.so.cache'])
    pin(private_path, public['private_receipt'])
    pin(public_path.with_suffix('.csv'), public['csv'])
    need(argv[12] == prior['namespace_plan']['original'] and argv[16:19:2] == prior['namespace_plan']['roots'],
         'original_namespace_roots')
    argv[2] = str(launch_root / LAUNCH)
    argv[4] = str(launch_root)
    argv[14] = str(directory / 'preparation.json')
    argv[22] = str(directory / 'namespace')
    return prior, argv, Path(prior['release_build']['argv'][-1]), pinned, dict(
        public=fact(public_path), private=fact(private_path), source=prior['source'],
        prior_status=prior['status'], prior_subject_exit=row['exit'],
        original_command_sha256=digest(row), original_bounds=row['bounds'],
        historical_launch_manifest_sha256=digest(historical), historical_launch_files=len(historical),
        launch_relocations=['exact historical launcher/import root', 'fresh preparation', 'fresh namespace'])


def perf_counts(path):
    data = path.read_bytes()
    need(len(data) >= 104 and data[:8] == b'PERFILE2', 'perf_file_header')
    start, size = struct.unpack_from('<QQ', data, 40)
    need(start >= 104 and start <= len(data) and size <= len(data) - start, 'perf_data_extent')
    cursor, end, samples, lost = start, start + size, 0, 0
    kinds = {}
    while cursor < end:
        need(cursor + 8 <= end, 'perf_record_header')
        kind, _, extent = struct.unpack_from('<IHH', data, cursor)
        need(extent >= 8 and cursor + extent <= end and kind != 81, 'perf_record_extent_or_compression')
        kinds[str(kind)] = kinds.get(str(kind), 0) + 1
        if kind == 9:
            samples += 1
        elif kind == 2:
            need(extent >= 24, 'perf_lost_record')
            lost += struct.unpack_from('<Q', data, cursor + 16)[0]
        elif kind == 13:
            need(extent >= 16, 'perf_lost_samples_record')
            lost += struct.unpack_from('<Q', data, cursor + 8)[0]
        cursor += extent
    need(cursor == end and samples > 0, 'perf_actual_samples')
    return dict(samples=samples, lost=lost, record_types=kinds, data_bytes=size)


def elf_loads(path):
    data = path.read_bytes()
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (3, 62, 1) and
         h[8:10] == (64, 56) and 1 <= h[10] <= 32 and h[5] + h[10] * 56 <= len(data), 'bridge_elf')
    return [p for i in range(h[10]) for p in [struct.unpack_from('<IIQQQQQQ', data, h[5] + i * 56)] if p[0] == 1]


def offsets(bridge, directory, cpu, commands, children, pin):
    script = directory / 'offsets.py'
    script.write_text('import gdb,json\nitems=' + repr(EXPRESSIONS) + '\nprint(json.dumps({x:{"address":int(gdb.parse_and_eval("&"+x)),"size":int(gdb.parse_and_eval("sizeof("+x+")"))} for x in items},sort_keys=True))\n')
    pin(script)
    pin(Path('/usr/bin/gdb'))
    argv = ['/usr/bin/gdb', '-q', '-nx', '-batch', '-iex', 'set auto-load off',
        '-iex', 'set debuginfod enabled off', '-iex', 'set index-cache enabled off',
        '-iex', 'maint set worker-threads 1', '--readnow', '--se=' + str(bridge), '-x', str(script)]
    child = Child('offsets', argv, INSPECT, directory, cpu, commands, children)
    clean(child, (0,))
    need(not child.paths['stderr'].read_bytes(), 'offsets_stderr')
    values = json.loads(child.paths['stdout'].read_bytes())
    need(set(values) == set(EXPRESSIONS) and all(type(x['size']) is int and x['size'] == 8 and
         type(x['address']) is int and x['address'] > 0 for x in values.values()), 'exact_typed_offsets')
    loads = elf_loads(bridge)
    need(all(sum(p[1] == 6 and p[3] <= x['address'] and x['address'] + 8 <= p[3] + p[6]
                 for p in loads) == 1 for x in values.values()), 'offsets_in_actual_rw_load')
    return values, loads


def snapshot(child, bridge, values, loads, directory, samples):
    original = bridge.stat()
    for i in range(5):
        due = child.row['start_ns'] + (i + 1) * 1_000_000_000
        if child.ready((due - time.monotonic_ns()) / 1e9):
            break
        begin = time.monotonic_ns()
        raw = Path('/proc/' + str(child.p.pid) + '/maps').read_bytes()
        need(len(raw) <= 1 << 20, 'snapshot_maps_bound')
        (directory / ('maps-' + str(i))).write_bytes(raw)
        maps = [line.split(maxsplit=5) for line in raw.decode().splitlines()]
        starts = [int(row[0].split('-')[0], 16) - p[3] for row in maps for p in loads
                  if p[2] == 0 and int(row[2], 16) == 0 and int(row[4]) == original.st_ino and
                  tuple(int(x, 16) for x in row[3].split(':')) ==
                  (os.major(original.st_dev), os.minor(original.st_dev)) and
                  len(row) == 6 and row[5] == str(bridge)]
        need(len(starts) == 1, 'actual_bridge_mapping_bias')
        bias = starts[0]
        memory = os.open('/proc/' + str(child.p.pid) + '/mem', os.O_RDONLY | os.O_CLOEXEC)
        observed = {}
        try:
            for key in EXPRESSIONS:
                address = bias + values[key]['address']
                need(sum('r' == row[1][0] and int(row[0].split('-')[0], 16) <= address and
                     address + 8 <= int(row[0].split('-')[1], 16) for row in maps) == 1,
                     'snapshot_actual_readable_interval')
                data = os.pread(memory, 8, address)
                need(len(data) == 8, 'snapshot_exact_read')
                observed[key] = int.from_bytes(data, 'little')
        finally:
            os.close(memory)
        samples.append(dict(begin_ns=begin - child.row['start_ns'],
                            end_ns=time.monotonic_ns() - child.row['start_ns'], values=observed))
        save(directory / ('snapshot-' + str(i) + '.json'), samples[-1])
    need(samples, 'no_snapshot_observation')
    return samples


def symbols(path, sample_count, pinned):
    """Join every rendered sample to the binary count; publish no raw IP/path."""
    counts = {}
    known = {name: value for name, value in pinned.items() if Path(name).suffix != '.py'}
    lines = path.read_text().splitlines()
    for line in lines:
        if not line.strip():
            continue
        match = re.fullmatch(r'\s*[0-9a-fA-F]+\s+(.+?)\s+\((.*)\)\s*', line)
        need(match is not None, 'perf_sample_rendering')
        symbol, dso = match.groups()
        if not re.fullmatch(r'[A-Za-z0-9_.$@+:\[\]-]{1,192}', symbol) or re.fullmatch(r'(?:0x)?[0-9a-fA-F]+', symbol):
            symbol = 'unresolved-symbol-' + hashlib.sha256(symbol.encode()).hexdigest()[:16]
        if dso in known:
            label = Path(dso).name
            need(re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}', label), 'public_module_label')
            identity = known[dso]['sha256']
        else:
            label = 'unresolved-module'
            identity = hashlib.sha256(dso.encode()).hexdigest()
        key = label, identity, symbol
        counts[key] = counts.get(key, 0) + 1
    need(sum(counts.values()) == sample_count, 'all_rendered_samples_join_binary_count')
    return [dict(module=k[0], module_identity_sha256=k[1], symbol=k[2], samples=v)
            for k, v in sorted(counts.items(), key=lambda x: (-x[1], x[0]))]


def preparation(directory, subject, prior, cpu):
    paths = [directory / 'preparation.json', directory / 'namespace/namespace.json',
             directory / 'namespace/launch.json']
    prep, namespace, launch = [json.loads(p.read_bytes()) for p in paths]
    need((prep['role'], prep['mode'], prep['control'], prep['pid'], prep['cpu'], prep['reset_mask'],
          prep['observer']['fd']) == ('gated', 0, 0, subject.p.pid, [cpu], 0, 3), 'actual_launch_preparation')
    need([x['signal'] for x in prep['dispositions']] == [n for n in range(1, 65) if n not in (9, 19)]
         and all(x['after'] == 0 for x in prep['dispositions']), 'actual_launch_signal_reset')
    expected = sorted((x['path'], x['bytes'], x['sha256']) for x in prior['runtime_libraries'].values())
    need(sorted((x['source'], x['size'], x['sha256']) for x in namespace['objects']) == expected and
         all(x['seals'] == 15 for x in namespace['objects']) and
         namespace['original_sha256'] == prior['subject_artifacts']['original']['sha256'] and
         namespace['interpreter_sha256'] == prior['subject_artifacts']['interpreter']['sha256'] and
         launch['carrier_sha256'] == prior['subject_artifacts']['carrier']['sha256'], 'actual_namespace_preparation')
    return {p.name: fact(p) for p in paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--expect-artifact-revision', required=True)
    parser.add_argument('--kind', choices=('perf', 'snapshot'), required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    cpu_set = sorted(os.sched_getaffinity(0))
    need(len(cpu_set) == 1, 'reserve_exactly_one_caller_cpu')
    cpu = cpu_set[0]
    revision = git(root, 'rev-parse', 'HEAD').decode().strip()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem = stamp + '-span-trace-diagnostic-' + revision[:12]
    directory = root / 'target/evaluation/inprocess' / stem
    directory.mkdir(mode=0o700)
    public_dir = root / 'evaluation/inprocess/results'
    commands, children, pinned = [], [], {}
    receipt = dict(schema=1, profile='scalar-span-diagnostic-v1', diagnostic_only=True,
        qualification_credit=False, performance_credit=False, kind=args.kind, status='failed',
        collector_revision=revision, artifact_revision=args.expect_artifact_revision,
        cpu=cpu, hardware=hardware(cpu), commands=commands, git_metadata=GIT_READS,
        errors=[], final_errors=[], observations={}, tools={}, collector_committed=False)
    def pin(path):
        path = Path(path)
        pinned[str(path)] = dict(fact(path), mode=stat.S_IMODE(path.stat().st_mode),
                                 resolved=str(path.resolve(strict=True)))
    try:
        canonical = root / 'evaluation/inprocess/span_trace_diagnostic.py'
        need(Path(__file__).resolve() == canonical and not canonical.is_symlink(), 'canonical_collector_path')
        need(canonical.read_bytes() == git(root, 'show', revision + ':evaluation/inprocess/span_trace_diagnostic.py'),
             'committed_collector_bytes')
        receipt['collector_committed'] = True
        pin(Path(__file__).resolve())
        receipt['tools']['collector'] = fact(Path(__file__).resolve())
        pin(Path(sys.executable).resolve())
        receipt['tools']['collector_python'] = fact(Path(sys.executable).resolve())
        pin(Path('/usr/bin/git'))
        public_path = args.receipt.resolve(strict=True)
        prior, argv, bridge, original_pins, origin = context(
            root, public_path, args.expect_artifact_revision, directory)
        pinned.update(original_pins)
        pin(public_path)
        receipt['origin'] = origin
        receipt['tools']['python'] = fact(argv[0])
        if args.kind == 'snapshot':
            values, loads = offsets(bridge, directory, cpu, commands, children, pin)
            receipt['tools']['gdb'] = fact('/usr/bin/gdb')
        else:
            pin(Path('/usr/bin/perf'))
            receipt['tools']['perf'] = fact('/usr/bin/perf')
        subject = Child('subject', argv, SUBJECT, directory, cpu, commands, children, record=True)
        if args.kind == 'snapshot':
            receipt['observations'] = dict(snapshots=[], requested_points=5, coherent_state=False,
                observation='sequential unsynchronized read-only 8-byte observations')
            snapshot(subject, bridge, values, loads, directory, receipt['observations']['snapshots'])
        else:
            need(not subject.ready(.4), 'subject_exited_before_attach')
            private_env = dict(ENV, PERF_CONFIG_NOSYSTEM='1', PERF_CONFIG_NOGLOBAL='1', DEBUGINFOD_URLS='')
            for key, name in (('PERF_BUILDID_DIR', 'buildids'), ('XDG_CACHE_HOME', 'cache'), ('TMPDIR', 'tmp')):
                (directory / name).mkdir()
                private_env[key] = str(directory / name)
            perf_argv = ['/usr/bin/perf', 'record', '--no-buildid', '--no-buildid-cache',
                '-e', 'cpu-clock', '-F', '99', '-m', '16', '-o', str(directory / 'perf.data'), '-p', str(subject.p.pid)]
            profiler = Child('perf', perf_argv, TOOL, directory, cpu, commands, children, private_env)
            profiler.ready(5)
            clean_row = profiler.finish(interrupt=True)
            need(clean_row.get('stop_requested') == 'SIGINT_after_observation_interval', 'full_perf_attach_interval')
            clean(profiler, (0, -signal.SIGINT))
            receipt['observations'] = perf_counts(directory / 'perf.data')
            receipt['observations'].update(requested_hz=99, attach_delay_ns=400000000,
                                            requested_attach_ns=5000000000, requested_mmap_pages=16)
            receipt['observations']['perf_data'] = fact(directory / 'perf.data')
            pin(directory / 'perf.data')
        subject.finish()
        need(subject.row['reaped'] and not subject.row['cleanup_errors'] and not subject.row['error']
             and not subject.row['timed_out'], 'diagnostic_subject_cleanup')
        receipt['preparation'] = preparation(directory, subject, prior, cpu)
        if args.kind == 'perf':
            # Symbol resolution is a bounded read of retained perf/ELF data,
            # after the subject has been reaped. Its output stays private.
            script = Child('perf-symbols', ['/usr/bin/perf', 'script', '-i', str(directory / 'perf.data'),
                '-F', 'ip,sym,dso'], TOOL, directory, cpu, commands, children, private_env)
            clean(script, (0,))
            need(not script.paths['stderr'].read_bytes(), 'perf_symbols_stderr')
            receipt['observations']['symbols'] = symbols(
                script.paths['stdout'], receipt['observations']['samples'], pinned)
            need(any(x['module'] == bridge.name and x['module_identity_sha256'] ==
                     prior['subject_artifacts']['bridge']['sha256'] for x in receipt['observations']['symbols']),
                 'actual_retained_bridge_sample')
        receipt['status'] = 'diagnostic_completed'
    except BaseException as exc:
        receipt['errors'].append(dict(type=type(exc).__name__, detail=str(exc)))
    finally:
        for child in reversed(children):
            child.finish()
        receipt['inputs_before'] = pinned
        after = {}
        for name in pinned:
            try:
                p = Path(name)
                after[name] = dict(fact(p), mode=stat.S_IMODE(p.stat().st_mode), resolved=str(p.resolve(strict=True)))
            except BaseException as exc:
                receipt['final_errors'].append(type(exc).__name__ + ': ' + str(exc))
        receipt['inputs_after'] = after
        receipt['inputs_unchanged'] = pinned == after
        receipt['cleanup_complete'] = all((not c.row['launched'] or c.row['reaped']) and
                                          not c.row['cleanup_errors'] for c in children)
        try:
            receipt['collector_unchanged'] = git(root, 'rev-parse', 'HEAD').decode().strip() == revision
        except BaseException as exc:
            receipt['collector_unchanged'] = False
            receipt['final_errors'].append(type(exc).__name__ + ': ' + str(exc))
        if not receipt['inputs_unchanged'] or not receipt['cleanup_complete'] or not receipt['collector_unchanged']:
            receipt['final_errors'].append('diagnostic_final_closure')
        if receipt['errors'] or receipt['final_errors']:
            receipt['status'] = 'failed'
        receipt['artifacts'] = {}
        receipt['aliases'] = {}
        for p in sorted(directory.rglob('*')):
            name = str(p.relative_to(directory))
            if p.is_symlink():
                receipt['aliases'][name] = os.readlink(p)
            elif p.is_file():
                receipt['artifacts'][name] = dict(fact(p), mode=stat.S_IMODE(p.stat().st_mode))
        save(directory / 'receipt.json', receipt)
        # Public evidence is an explicit projection. No command argv, raw maps,
        # process text, namespace, hostname, memory address, or private path.
        public = {k: receipt[k] for k in ('schema', 'profile', 'diagnostic_only', 'qualification_credit',
            'performance_credit', 'kind', 'status', 'collector_revision', 'artifact_revision', 'cpu',
            'hardware', 'inputs_unchanged', 'cleanup_complete', 'collector_unchanged', 'collector_committed')}
        observations = json.loads(json.dumps(receipt['observations']))
        if 'symbols' in observations:
            all_symbols = observations.pop('symbols')
            observations.update(top_symbols=all_symbols[:32], symbol_groups=len(all_symbols),
                                other_samples=sum(x['samples'] for x in all_symbols[32:]))
        if 'snapshots' in observations:
            for point in observations['snapshots']:
                # Full address observations stay private. These public fields
                # are counters only and still have no coherent-state claim.
                point['values'] = {k: v for k, v in point['values'].items()
                                   if '.current.' not in k}
        public.update(private_receipt=fact(directory / 'receipt.json'), input_manifest_sha256=digest(pinned),
            artifacts_sha256=digest(receipt['artifacts']), tools=receipt['tools'],
            git_metadata_count=len(GIT_READS), git_metadata_sha256=digest(GIT_READS),
            error_types=[x['type'] for x in receipt['errors']], final_error_count=len(receipt['final_errors']),
            observations=observations, command_count=len(commands), commands_sha256=digest(commands),
            commands=[{k: row.get(k) for k in ('name', 'bounds', 'exit', 'timed_out', 'reaped',
                'duration_ns', 'user_cpu_ns', 'system_cpu_ns', 'max_rss_kib', 'stop_requested', 'captures')}
                for row in commands], origin=receipt.get('origin'),
            reproduce=['python3', '-B', 'evaluation/inprocess/span_trace_diagnostic.py', '--receipt',
                'evaluation/inprocess/results/' + args.receipt.name, '--expect-artifact-revision',
                args.expect_artifact_revision, '--kind', args.kind],
            scope='Diagnostic observations only; original finite cohort outcome remains unchanged. '
                  'Perf perturbs execution; snapshot reads are sequential and unsynchronized. '
                  'Process-group cleanup does not claim custody of escaped descendants.')
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(('command', 'exit', 'wall_ns', 'user_cpu_ns', 'system_cpu_ns', 'timed_out', 'reaped'))
        for row in commands:
            writer.writerow(tuple(row.get(k) for k in ('name', 'exit', 'duration_ns', 'user_cpu_ns',
                                                     'system_cpu_ns', 'timed_out', 'reaped')))
        csv_path = public_dir / (stem + '.csv')
        with csv_path.open('x') as stream:
            stream.write(output.getvalue())
        public['csv'] = dict(fact(csv_path), file=csv_path.name)
        encoded = json.dumps(public, sort_keys=True)
        need(str(root) not in encoded and '/home/' not in encoded and platform.node() not in encoded,
             'public_projection_privacy')
        save(public_dir / (stem + '.json'), public)
    print(json.dumps(dict(status=receipt['status'], result=stem + '.json', qualification_credit=False)))
    return 0 if receipt['status'] == 'diagnostic_completed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
