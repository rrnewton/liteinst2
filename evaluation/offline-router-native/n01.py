#!/usr/bin/env python3
"""Fixed complete-program native population, gated on final package admission.

Never run by import. No producer/build/ptrace action exists in this population.
The actual new-profile path is called only by the separately pinned final launcher.
"""
import csv
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import stat
from types import SimpleNamespace

PROGRAMS = ('checksum', 'rle-roundtrip')
DATASETS = ('empty', 'single-zero', 'single-ff', 'all-bytes', 'run-255', 'run-256',
            'runs-boundary', 'mixed-4096', 'long-run', 'long-alternating')
LANES = ('original', 'candidate')
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
# Filled from exact pre-existing files when the private source proposal closes.
CORPUS_SHA = '007e529b3716061d8b7f11f3e33541ee80292027165703663db2f72a81e35b07'
COLLECTOR_SHA = 'b8e61360056220b1e2a60f93f32844b36e483d08a354bccbf6b03f1a8288c4a3'
PACKAGE_SHA = '13a5e8655f23c933a016908e3a875a089368a7a4be8a1891d4409f36b0d99bd2'
FILE_CAP = 16 * 1048576


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, why):
    if not ok:
        raise ValueError(why)


def write(path, value):
    raw = value if type(value) is bytes else (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    with Path(path).open('xb') as stream:
        stream.write(raw)


def load_pinned(path, expected, name):
    raw = Path(path).read_bytes()
    need(len(raw) <= 1048576 and sha(raw) == expected, 'source module identity')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Use the verified bytes, rather than a later pathname read by exec_module.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def planned_rows():
    rows = [dict(program=p, dataset=d, lane=lane, status='UNRUN', attempted=False,
                 exit=None, actual_sha256=None, stderr_sha256=None, expected_sha256=None,
                 input_sha256=None, output_bytes=None, closure_complete=False, reason='not dispatched')
            for p in PROGRAMS for d in DATASETS for lane in LANES]
    need(len(rows) == 40, 'fixed invocation count')
    return rows


def compare_output(exit_code, stdout, stderr, expected, *, candidate, original):
    """Independent exact expected bytes AND independently successful baseline."""
    okay = type(exit_code) is int and exit_code == 0 and stdout == expected and stderr == b''
    if candidate:
        okay = okay and original is not None and stdout == original
    return okay


class PrefixReader:
    """One persistent 64 MiB reader per PROGRAM, not one fresh budget per case."""
    def __init__(self, reader, prefix):
        self.reader, self.prefix = reader, prefix
    def _path(self, relative):
        need(relative.startswith('importer/'), 'fixed helper subtree')
        return self.prefix + '/' + relative
    def bytes(self, relative, cap=1048576):
        return self.reader.bytes(self._path(relative), cap)
    def read(self, relative, cap=FILE_CAP, keep=0):
        return self.reader.read(self._path(relative), cap, keep)
    def verify(self):
        self.reader.verify()


def completed(collector, view, request, command):
    # Cache complete bytes first, so the inherited reader/check_closed keep=1024
    # request never attempts an invalid uncached larger reread for long RLE.
    stdout = view.bytes('importer/stdout.txt', FILE_CAP)
    stderr = view.bytes('importer/stderr.txt', FILE_CAP)
    helper_stdout = view.bytes('importer/helper.stdout', FILE_CAP)
    code, _ = collector.check_closed(view, request, HELPER_SHA, command)
    receipt = collector.json_value(view.bytes('importer/receipt.json'))
    need(math.isfinite(receipt['elapsed_seconds'])
         and 0 <= receipt['elapsed_seconds'] <= 30, 'strict helper wall bound')
    terminal = dict(exit=code, wall_timeout=False, absence_proof='ECHILD',
                    descendants=0, success=code == 0)
    need(helper_stdout == (json.dumps(terminal) + '\n').encode(), 'exact terminal helper response')
    # check_closed already authenticates parent wait/error, exact request/command,
    # receipt hashes, empty helper stderr, ECHILD, and empty cleanup/descendants.
    return code, stdout, stderr


def pairs(rows):
    need(len(rows) == 40, 'all 40 invocation rows remain')
    identity = [(r['program'], r['dataset'], r['lane']) for r in rows]
    need(identity == [(p, d, lane) for p in PROGRAMS for d in DATASETS for lane in LANES],
         'fixed order/no missing, extra, duplicate or substituted cases')
    return [dict(program=p, dataset=d,
                 status='PASS' if all(r['status'] == 'PASS' for r in rows[i:i+2]) else
                        'UNRUN' if all(r['status'] == 'UNRUN' for r in rows[i:i+2]) else 'FAILED')
            for i, (p, d) in zip(range(0, 40, 2), ((p,d) for p in PROGRAMS for d in DATASETS))]


def run_final(repo, output, session, profile_reference):
    """Internal trusted-caller path after actual final_admission.open_session.

    Session is a same-process checked result, not a cryptographic capability.
    The pinned native_launch CLI is the unsafe authority boundary. Every child
    remains a normal untraced exec with exact empty environment and full outputs.
    """
    repo, output = Path(repo).resolve(), Path(output).resolve()
    need(output.is_relative_to(repo/'ignored') and not output.exists(), 'new private output')
    output.mkdir()
    rows = planned_rows()
    write(output/'final-profile.json', profile_reference)
    write(output/'planned.json', dict(programs=list(PROGRAMS), datasets=list(DATASETS),
                                     invocations=rows, pairs=20, attempts_per_invocation=1))
    package = load_pinned(Path(__file__).with_name('package.py'), PACKAGE_SHA, 'n01_package_authority')
    custody = package.Custody()
    report = dict(schema=1, profile='offline-router-N01-full-output-v1',
                  native_correctness_complete=False, route_coverage_complete=False,
                  qualification_complete=False, performance_eligible=False,
                  final_profile=profile_reference, hardware='AMD EPYC Zen 5 dev host',
                  invocation_count=40, pair_count=20, producer_dispatches=0,
                  build_dispatches=0, ptrace_dispatches=0, fatal=None)
    readers = {}
    retained = []
    try:
        source_pin=session.check_source('evaluation/offline-router-native/n01.py')
        need(sha(Path(__file__).read_bytes())==source_pin,'actual pinned N01 caller')
        session.stable()
        need(tuple(session.programs)==PROGRAMS,'complete admitted two-program roster')
        manifest=dict(programs=[dict(name=name) for name in PROGRAMS])
        report['revision']=session.profile['native_revision']
        execution=session.execution_inputs()
        tools={name:execution['tools'][name] for name in ('python','timeout','helper')}
        launch=load_pinned(Path(__file__).with_name('native_launch.py'),
            session.check_source('evaluation/offline-router-native/native_launch.py'),'n01_checked_launcher')
        need(set(tools) == {'python', 'timeout', 'helper'}, 'exact execution tool roster')
        for record in tools.values():
            custody.retain(record, FILE_CAP)
        need(tools['helper']['sha256'] == HELPER_SHA
             and tools['helper']['path'] == str(repo/'tools/unwind-oracle/bounded_command.py'),
             'unchanged bounded helper')
        corpus_path = repo/'evaluation/offline-corpus/corpus.py'
        collector_path = repo/'evaluation/offline-corpus/adjacent_whole.py'
        for path, pin in ((corpus_path, CORPUS_SHA), (collector_path, COLLECTOR_SHA)):
            raw = path.read_bytes()
            need(sha(raw) == pin, 'exact retained source')
            custody.retain(dict(path=str(path), bytes=len(raw), sha256=pin,
                                stat=package.stamp(path.stat())), 1048576)
        corpus = load_pinned(corpus_path, CORPUS_SHA, 'n01_frozen_corpus')
        collector = load_pinned(collector_path, COLLECTOR_SHA, 'n01_frozen_collector')
        data = corpus.datasets()
        need(tuple(data) == DATASETS and tuple(corpus.PROGRAMS) == PROGRAMS
             and all(type(raw) is bytes and len(raw) <= 65536 for raw in data.values()),
             'exact ten mandatory datasets and both programs')
        inputs = output/'datasets'; inputs.mkdir()
        for name, raw in data.items():
            path = inputs/name; write(path, raw)
            custody.retain(dict(path=str(path), bytes=len(raw), sha256=sha(raw),
                                stat=package.stamp(path.stat())), 65536)
        # Freeze the whole population's data/expected bytes and executable copies
        # before the first invocation. Package bootstrap paths remain unchanged.
        runnable = {}
        for p in manifest['programs']:
            folder = output/p['name']; folder.mkdir()
            runnable[p['name']] = {}
            for lane, role in (('original','original'), ('candidate','main')):
                raw = session.programs[p['name']]['original_bytes' if lane=='original' else 'main_bytes']
                path = folder/('run-'+lane)
                write(path, raw); path.chmod(0o700)
                execution_pin=dict(path=str(path),bytes=len(raw),sha256=sha(raw),stat=package.stamp(path.stat()))
                custody.retain(execution_pin,FILE_CAP)
                if lane=='candidate':session.bind_main_copy(p['name'],execution_pin)
                runnable[p['name']][lane] = path
            expected_dir = folder/'expected'; expected_dir.mkdir()
            for name, raw in data.items():
                want = corpus.expected(p['name'], raw)
                need(len(want) == 24 if p['name'] == 'checksum' else len(want) <= 196616,
                     'existing exact output bounds')
                path = expected_dir/name; write(path, want)
                custody.retain(dict(path=str(path), bytes=len(want), sha256=sha(want),
                                    stat=package.stamp(path.stat())), 196616)
                for row in rows:
                    if (row['program'],row['dataset']) == (p['name'],name):
                        row.update(input_sha256=sha(raw),expected_sha256=sha(want))
            readers[p['name']] = collector.OutputReader(folder)
        write(output/'population.json', rows)
        def stable():
            session.stable()
            custody.verify()
            for reader, relative, directories in retained:
                current = reader.directory(relative)
                try:
                    need(collector.stamp(os.fstat(current)) == directories['stat'],
                         'previous case directory identity changed')
                finally:
                    os.close(current)
                need(reader.names(relative) == directories['members'], 'previous case membership changed')
                reader.verify()
        for row in rows:
            stable()
            program, name, lane = row['program'], row['dataset'], row['lane']
            folder = output/program/(name+'-'+lane); folder.mkdir()
            importer = folder/'importer'; importer.mkdir()
            launch.child_signals()
            env = {}
            ctx = SimpleNamespace(ROOT=folder, B=SimpleNamespace(write=write))
            row.update(status='FAILED', attempted=True, reason='invocation or checks incomplete')
            request, command = collector.invoke(ctx, importer,
                [str(runnable[program][lane]), str(inputs/name)], env, tools)
            reader = readers[program]
            view = PrefixReader(reader, name+'-'+lane)
            code, actual, stderr = completed(collector, view, request, command)
            # Signal/timeout is not a stable semantic result. The inherited
            # closure rejects timeouts; a signal always stops subsequent dispatch.
            need(code >= 0, 'signal termination: stop fixed campaign')
            want = custody.files[str(output/program/'expected'/name)][2]
            original_row = next(r for r in rows if (r['program'],r['dataset'],r['lane']) == (program,name,'original'))
            baseline = None
            if lane == 'candidate' and original_row['status'] == 'PASS':
                baseline = reader.bytes(name+'-original/importer/stdout.txt', FILE_CAP)
            good = compare_output(code, actual, stderr, want, candidate=lane == 'candidate', original=baseline)
            session.stable(); custody.verify(); reader.verify()
            rel = name+'-'+lane+'/importer'
            fd = reader.directory(rel)
            try: held = dict(stat=collector.stamp(os.fstat(fd)), members=reader.names(rel))
            finally: os.close(fd)
            retained.append((reader,rel,held))
            row.update(status='PASS' if good else 'FAILED', exit=code, actual_sha256=sha(actual),
                       stderr_sha256=sha(stderr),output_bytes=len(actual),closure_complete=True,
                       reason=None if good else 'exact expected/empty stderr/exit0/successful original equality failed')
        stable()
        report['native_correctness_complete'] = all(r['status'] == 'PASS' for r in rows)
    except BaseException as error:
        report['fatal'] = type(error).__name__ + ': ' + str(error)
    finally:
        # Finish every owner, including final Session stability, before sealing
        # aggregate completion. The outer launcher keeps only an idempotent fallback.
        for owner in [*readers.values(), custody, session]:
            try: owner.close()
            except BaseException as error:
                report['fatal'] = (report['fatal'] or '') + '; close: ' + str(error)
                report['native_correctness_complete'] = False
    result_pairs = pairs(rows)
    report['counts'] = {s: sum(r['status'] == s for r in rows) for s in ('PASS','FAILED','UNRUN')}
    report['attempted'] = sum(r['attempted'] for r in rows)
    write(output/'invocations.json', rows); write(output/'pairs.json', result_pairs)
    write(output/'summary.json', report)
    with (output/'invocations.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    write(output/'closed.json', dict(summary_sha256=sha((output/'summary.json').read_bytes()),
          invocations_sha256=sha((output/'invocations.json').read_bytes()), pairs_sha256=sha((output/'pairs.json').read_bytes()),
          native_correctness_complete=report['native_correctness_complete'], performance_eligible=False))
    return 0 if report['native_correctness_complete'] and report['fatal'] is None else 1


def run(_repo, _output, _manifest_raw, _tools):
    """The old unknown-authority entry point never starts a child."""
    raise ValueError('NO_SUPPORTED_SAFE_AUTHORITY: use the explicitly accepted pinned final launcher')
