#!/usr/bin/env python3
"""Fixed fresh-leg study: empirical gaps and configuration contrasts, not accuracy."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')

import argparse
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import traceback

MIB = 1048576
MASTER = '29c5ca7ec521d0d3e63adb24d9e493b63ae0e9c99ee5bd9d4a49b4791e227b48'
KEY = ('process', 'phase', 'trial', 'leg', 'seed', 'position')
ENDPOINT = ('process', 'call', 'reference_start_offset', 'reference_end_offset',
    'start_offset', 'end_offset')
IDENTITY = ('base', 'aux', 'pid', 'tid', 'generation')
FILES = (('request', 'request.json'), ('stdout', 'stdout.txt'), ('stderr', 'stderr.txt'),
    ('receipt', 'receipt.json'), ('closure', 'parent-closed.json'))
PROFILE = dict(opt_level='3', debuginfo=0, test=False, debug_assertions=True, overflow_checks=True)
SCOPE = ('Descriptive empirical boundary-gap coverage and whole-configuration reference-enclosed '
    'contrast in TSC ticks. No body-only accuracy, callback-only cost, bare-native overhead, '
    'confidence interval or full-A5 claim. Setup can affect CALL caches; setup elapsed is outside R. '
    'Deterministic hash scheduling does not establish independent hardware observations. '
    'All prior failed2ms campaigns remain failed.')


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
        allow_nan=False)+'\n').encode('ascii')


def content(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def digest(path):
    return content(path.read_bytes())


def retain(pins, path, expected):
    # An expected digest is authority; never adopt changed bytes as a new pin.
    if path in pins:
        assert pins[path] == expected
    assert digest(path) == expected
    pins.setdefault(path, dict(expected))


def pinned_unchanged(pins):
    assert all(digest(path) == expected for path, expected in pins.items())


def retain_parent_log(pins, path, closed):
    data = path.read_bytes()
    expected = content(data)
    assert expected['sha256'] == closed['private_log_sha256']
    retain(pins, path, expected)
    return data


def record_files(row, directory, pins):
    for name, filename in FILES:
        path = directory/filename
        if path.exists():
            value = digest(path)
            if path in pins:
                assert value == pins[path]
                value = pins[path]
            fields = {name+'_bytes': value['bytes'], name+'_sha256': value['sha256']}
            for key, expected in fields.items():
                if key in row:
                    assert row[key] == expected
            row.update(fields)


def bind_cases(result, path, pins):
    expected = pins[path]
    assert digest(path) == expected
    result['cases'] = dict(expected)


def read_json(path):
    return json.loads(path.read_bytes())


def save(path, value):
    # Atomic progress updates; immutable authority files use freeze() instead.
    temporary = path.with_name(path.name+'.tmp')
    temporary.write_bytes(encoded(value))
    temporary.replace(path)


def freeze(path, data):
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    assert path.read_bytes() == data
    return content(data)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def closed_ok(closed):
    assert type(closed['exit_code']) is int and closed['exit_code'] == 0
    assert closed['termination'] is None and closed['cleanup_complete'] is True
    assert type(closed['reaped_descendants']) is int and closed['reaped_descendants'] == 0


def join_owned(expected_request, actual_request, request_hash, helper_hash,
        receipt, closed, parent, stdout, stderr):
    """Actual bounded-helper joins; fabricated controls grant no native custody."""
    assert encoded(actual_request) == encoded(expected_request)
    closed_ok(closed)
    assert type(receipt['exit']) is int and receipt['exit'] == 0
    assert receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
    assert receipt['absence_proof'] == 'ECHILD'
    assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
    assert receipt['cleanup_error'] is receipt['aborted'] is None
    assert receipt['request_sha256'] == request_hash
    assert receipt['helper_sha256'] == helper_hash
    assert type(parent['exit']) is int and type(parent['descendants']) is int
    assert parent == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
    assert parent['wall_timeout'] is False and parent['success'] is True
    for name, data in (('stdout', stdout), ('stderr', stderr)):
        assert type(data) is bytes and len(data) <= expected_request['file_bytes']
        assert receipt[name+'_sha256'] == content(data)['sha256']


def prerequisite_ok(result, revision, names):
    assert result['revision'] == revision and result['status'] == 'PASS' and result['stage'] == 'complete'
    assert len(names) == 30 and tuple(row['name'] for row in result['stages']) == tuple(names)
    assert all(row['status'] == 'PASS' for row in result['stages'])
    assert result['closure'] == dict(owned_stages=30, nested_normal_helpers=46,
        nested_outer_owners=48, rescues=0)
    for name, count in (('reference_exact', 13), ('reference_work', 3), ('reference_leg', 4)):
        group = result[name]
        assert group['status'] == 'PASS' and len(group['stages']) == count
        assert all(row['status'] == 'PASS' for row in group['stages'])
        assert group['closure'] == dict(owned_stages=count, normal_helpers=count, outer_owners=count, rescues=0)
    assert result['reference_exact']['old_exact']['status'] == result['reference_exact']['reference']['status'] == 'PASS'
    assert result['reference_exact']['complete_populations'] == dict(old_exact_pairs=4,
        reference_pairs=4, children=16, old_exact_comparisons=1696, reference_comparisons=1736,
        reference_reader_checks=32, reference_output_stores=96, reference_returned_cells=16)
    assert {name: result['native'][name] for name in ('pairs', 'stable_pairs', 'crossed_pairs',
        'children', 'target_calls', 'target_returns', 'outer_returns', 'helper_joins')} == dict(
            pairs=17, stable_pairs=16, crossed_pairs=1, children=34, target_calls=68,
            target_returns=68, outer_returns=34, helper_joins=1)
    assert result['reference_work']['collector']['status'] == 'PASS'
    legs = result['reference_leg']['legs']
    assert [(c['phase'], c['trial'], c['leg'], c['calls'], c['status']) for c in legs] == [
        ('qualification', 1, 'original', 24, 'PASS'), ('qualification', 1, 'installed', 24, 'PASS')]


class Progress:
    """A fixed prefix, not a scheduler: FAILED may never be retried or skipped."""
    def __init__(self, catalog):
        assert len(catalog) == 400 and [k['process'] for k in catalog] == list(range(1, 401))
        assert all(set(k) == set(KEY) for k in catalog)
        self.catalog = [dict(k) for k in catalog]
        self.rows = [dict(k, status='UNRUN') for k in catalog]
        self.observations = []
        self.budget = None

    def start(self, key):
        index = len(self.observations)
        assert index < 400 and key == self.catalog[index]
        assert self.rows[index]['status'] == 'UNRUN'
        assert all(row['status'] == 'FUNCTIONAL_PASS' for row in self.rows[:index])
        assert index < 100 or self.budget is not None
        self.rows[index]['status'] = 'FAILED'

    def finish(self, key, observation):
        index = len(self.observations)
        assert index < 400 and key == self.catalog[index]
        assert self.rows[index]['status'] == 'FAILED'
        assert {name: observation[name] for name in KEY} == key
        assert len(observation['rows']) == 24
        self.rows[index].update({name: observation[name] for name in IDENTITY}, status='FUNCTIONAL_PASS')
        self.observations.append(observation)

    def frozen_budget(self, budget, data, analysis):
        assert len(self.observations) == 100 and self.budget is None
        assert budget == analysis.calibrate(self.observations)
        assert data == analysis.canonical(budget)
        self.budget = bytes(data)

    def complete(self):
        assert len(self.observations) == 400 and self.budget is not None
        assert all(row['status'] == 'FUNCTIONAL_PASS' for row in self.rows)


def exports(directory, progress, source_hash):
    fields = (*KEY, 'status', *IDENTITY, 'source_sha256',
        *(name+suffix for name, _ in FILES for suffix in ('_bytes', '_sha256')))
    with (directory/'processes.csv').open('w', newline='', encoding='ascii') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n')
        writer.writeheader()
        for row in progress.rows:
            writer.writerow({name: source_hash if name == 'source_sha256' else row.get(name)
                for name in fields})
    with (directory/'endpoints.csv').open('w', newline='', encoding='ascii') as stream:
        writer = csv.DictWriter(stream, fieldnames=ENDPOINT, lineterminator='\n')
        writer.writeheader()
        for observation in progress.observations:
            for row in observation['rows']:
                assert set(row) == set(ENDPOINT)
                writer.writerow(row)


def main():
    deadline = time.monotonic()+1200
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'):
        ap.add_argument('--'+name, type=Path, required=True)
    args = ap.parse_args()
    repo = Path(__file__).resolve().parents[3]
    assert Path(__file__).resolve() == repo/'tools/rapid-profiler/normal-work/reference_study.py'
    assert re.fullmatch('[0-9a-f]{40}', args.revision)
    for path in (repo, args.toolchain, args.user_home, args.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert args.raw.is_absolute() and args.raw.is_relative_to(repo/'ignored') and not args.raw.exists()
    assert args.raw.parent.resolve(strict=True) == args.raw.parent
    env = dict(HOME=str(args.user_home), CARGO_HOME=str(args.cargo_home),
        PATH=str(args.toolchain/'bin')+':/usr/bin:/bin', RUSTC=str(args.toolchain/'bin/rustc'),
        CC=str(Path('/usr/bin/gcc').resolve(strict=True)), CARGO_TARGET_DIR=str(repo/'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true',
        CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    args.raw.mkdir(mode=0o700)
    public = args.raw/'public'; public.mkdir()
    result = dict(schema=1, status='FAILED', stage='bootstrap', revision=args.revision,
        master=MASTER, master_origin='Deterministic SHA256 of ASCII li2core-normal-reference-study-20261028-v1; not random hardware sampling.',
        protocol_sha256='4d1da58ceae96aafa74ed618f941e9728ceb63f8c8b9b21f775fdc06c2abd1a8',
        scope=SCOPE, warmups=0, required_processes=400, required_calls=9600)
    progress = None
    sources = {}
    artifacts = {}
    tool_paths = {}
    result['controls'] = []

    def remaining():
        left = deadline-time.monotonic()
        assert left > 0, 'whole-study1200s deadline'
        return left

    def git(*items):
        data = subprocess.check_output(['/usr/bin/git', '-C', str(repo), *items],
            env=env, timeout=min(15, remaining()))
        assert len(data) <= MIB
        return data

    def unchanged():
        remaining()
        assert git('rev-parse', 'HEAD').decode().strip() == args.revision
        assert git('status', '--porcelain', '--untracked-files=no') == b''
        assert {name: digest(repo/name) for name in sources} == sources
        pinned_unchanged(artifacts)
        if tool_paths:
            assert {name: digest(path) for name, path in tool_paths.items()} == result['tools']

    def persist():
        if progress is not None:
            result['processes'] = progress.rows
        save(args.raw/'result.json', result)

    try:
        assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
        assert git('rev-parse', 'HEAD').decode().strip() == args.revision
        assert git('status', '--porcelain', '--untracked-files=no') == b''
        required = {'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py',
            'tests/call_tree_truth.rs', 'tools/rapid-profiler/verify_normal_interval.py',
            'tools/rapid-profiler/selected-work/provenance.py'}
        required.update('tools/rapid-profiler/normal-work/'+name for name in (
            'reference_study.py', 'test_reference_study.py', 'reference_study_analysis.py',
            'test_reference_study_analysis.py', 'reference_leg.py', 'reference_work.py', 'exact_fixture.py'))
        names = git('ls-files', '-z', '--', 'src', 'tests/support', 'tools/rapid-profiler',
            'Cargo.toml', 'Cargo.lock', 'README.md', 'build.rs', ':(glob)**/Cargo.toml',
            *sorted(required)).decode().rstrip('\0').split('\0')
        assert all(names) and len(names) == len(set(names)) and required.issubset(names)
        sources = {name: digest(repo/name) for name in names}
        for name in names:
            assert (repo/name).read_bytes() == git('show', args.revision+':'+name)
        freeze(args.raw/'sources-before.json', encoded(sources))
        result['sources'] = digest(args.raw/'sources-before.json')
        # No project import precedes complete source and transitive-source authentication.
        folder = repo/'tools/rapid-profiler/normal-work'
        analysis = load('study_analysis', folder/'reference_study_analysis.py')
        parser = load('study_leg_parser', folder/'reference_leg.py')
        fixture = load('study_exact_fixture', folder/'exact_fixture.py')
        recipe = load('study_normal_recipe', repo/'tools/rapid-profiler/verify_normal_interval.py')
        processes = load('study_processes', repo/'evaluation/admission/processes.py')
        catalog = analysis.catalog(MASTER)
        progress = Progress(catalog)
        catalog_bytes = analysis.canonical(catalog)
        freeze(public/'catalog.json', catalog_bytes)
        artifacts[public/'catalog.json'] = digest(public/'catalog.json')
        freeze(public/'cases.json', analysis.canonical([parser.work._expected(i) for i in range(24)]))
        artifacts[public/'cases.json'] = digest(public/'cases.json')
        bind_cases(result, public/'cases.json', artifacts)
        cpus = sorted(os.sched_getaffinity(0))
        assert len(cpus) == 4, 'launch inside one externally reserved four-CPU set'
        result['affinity'] = dict(prerequisite=cpus, study=[min(cpus)],
            claim='inherited reservation, not an exclusive host or realtime guarantee')
        logs_root = repo/'target/evaluation'; logs_root.mkdir(parents=True, exist_ok=True)
        assert logs_root.resolve(strict=True) == logs_root
        logs = Path(tempfile.mkdtemp(prefix='reference-study-', dir=logs_root))
        nested = args.raw/'prerequisite'
        argv = [sys.executable, '-B', str(repo/'tools/rapid-profiler/verify_normal_interval.py'),
            '--revision', args.revision, '--raw', str(nested), '--toolchain', str(args.toolchain),
            '--user-home', str(args.user_home), '--cargo-home', str(args.cargo_home),
            '--reference-exact', '--reference-work', '--reference-leg']
        result['stage'] = 'fresh-prerequisite'; persist()
        freeze(args.raw/'prerequisite-command.json', encoded(dict(argv=argv, env=env, affinity=cpus,
            whole_wall_seconds=1200)))
        closed = processes.run_command(argv, env, logs/'prerequisite.log', remaining(), 8*MIB)
        (args.raw/'prerequisite.log').write_bytes((logs/'prerequisite.log').read_bytes())
        freeze(args.raw/'prerequisite-closed.json', encoded(closed)); closed_ok(closed); unchanged()
        assert closed['private_log_sha256'] == digest(args.raw/'prerequisite.log')['sha256']
        assert (args.raw/'prerequisite.log').read_bytes() == b'normal-interval PASS stage=complete\n'
        old = read_json(nested/'result.json')
        stages = (*recipe.STAGES, *recipe.REFERENCE_STAGES, *recipe.REFERENCE_WORK_STAGES, *recipe.REFERENCE_LEG_STAGES)
        prerequisite_ok(old, args.revision, stages)
        prior_sources = read_json(nested/'sources-before.json')
        assert prior_sources == read_json(nested/'sources-after.json')
        assert all(sources[name] == value for name, value in prior_sources.items())
        assert old['sources'] == dict(count=len(prior_sources), manifest=digest(nested/'sources-before.json'))
        private = read_json(nested/'strnlen-prerequisite/private-environment.json')
        assert private['env'] == env and private['affinity'] == cpus
        tool_paths = {name: Path(path) for name, path in private['tools'].items()}
        assert set(tool_paths) == {'cargo', 'rustc', 'python', 'git', 'gcc', 'readelf', 'strip',
            'cc1', 'collect2', 'as', 'ld'}
        assert all(path.is_absolute() and path.resolve(strict=True) == path for path in tool_paths.values())
        assert tool_paths['python'] == Path(sys.executable).resolve(strict=True)
        result['tools'] = old['tools']
        assert {name: digest(path) for name, path in tool_paths.items()} == result['tools']
        assert old['hardware']['architecture'] == 'x86_64'
        assert old['hardware']['vendor'] in ('AuthenticAMD', 'GenuineIntel')
        assert all(type(old['hardware'][key]) is int and old['hardware'][key] >= 0
            for key in ('family', 'model', 'stepping'))
        result['hardware'] = {key: old['hardware'][key]
            for key in ('architecture', 'vendor', 'family', 'model', 'stepping')}
        def public_argument(value):
            for name, path in tool_paths.items():
                if value == str(path):
                    return '$'+name.upper()
            for path, token in ((nested, '$RAW'), (repo, '$REPO'), (args.toolchain, '$TOOLCHAIN'),
                    (args.cargo_home, '$CARGO_HOME'), (args.user_home, '$USER_HOME')):
                if value == str(path) or value.startswith(str(path)+'/'):
                    return token+value[len(str(path)):]
            assert not value.startswith('/') and '/home/' not in value and '@' not in value
            return value
        # Rejoin every fresh top-level command/receipt rather than trusting a PASS label.
        for row in old['stages']:
            directory = nested/row['name']
            request = read_json(directory/'request.json')
            assert request['cwd'] == str(repo) and request['env'] == dict(env, TMPDIR=str(directory/'tmp'))
            assert request['stdout'] == str(directory/'stdout.txt') and request['stderr'] == str(directory/'stderr.txt')
            assert (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == (
                row['cpu_seconds'], row['wall_seconds'], row['file_bytes'])
            assert [public_argument(item) for item in request['argv']] == row['command']
            for key, filename in (*FILES, ('closed', 'parent-closed.json')):
                if key == 'closure':
                    continue
                assert row[key] == digest(directory/filename)
                artifacts[directory/filename] = digest(directory/filename)
            retain_parent_log(artifacts, directory/'parent.log', read_json(directory/'parent-closed.json'))
            join_owned(request, read_json(directory/'request.json'), digest(directory/'request.json')['sha256'],
                sources['tools/unwind-oracle/bounded_command.py']['sha256'],
                read_json(directory/'receipt.json'), read_json(directory/'parent-closed.json'),
                read_json(directory/'parent.log'), (directory/'stdout.txt').read_bytes(),
                (directory/'stderr.txt').read_bytes())
        # The authenticated fresh recipe owns its unchanged nested chain and Cargo joins.
        # Pin that exact chain result and its owned parent closure as the handoff.
        chain = read_json(nested/'strnlen-prerequisite/result.json')
        assert chain['revision'] == args.revision and chain['status'] == 'PASS' and chain['stage'] == 'complete'
        assert old['prerequisite']['result'] == digest(nested/'strnlen-prerequisite/result.json')
        assert old['prerequisite']['closed'] == digest(nested/'prerequisite-closed.json')
        assert old['prerequisite']['command'] == digest(nested/'prerequisite-command.json')
        closed_ok(read_json(nested/'prerequisite-closed.json'))
        assert chain['closure'] == old['prerequisite']['closure'] == dict(
            owned_stages=24, nested_owned_stages=22, normal_helpers=46, outer_owners=48, rescues=0)
        for filename in ('result.json', 'sources-before.json', 'sources-after.json',
                'strnlen-prerequisite/result.json', 'strnlen-prerequisite/private-environment.json',
                'prerequisite-command.json', 'prerequisite-closed.json'):
            artifacts[nested/filename] = digest(nested/filename)
        binary = repo/'target/release/ordinary-interval'
        assert binary.resolve(strict=True) == binary
        assert chain['artifacts']['ordinary-interval']['profile'] == PROFILE
        assert digest(binary) == chain['artifacts']['ordinary-interval']['binary'] == old['artifacts']['ordinary-interval']
        artifacts[binary] = digest(binary)
        exact = old['reference_exact']['subject']
        helper = old['reference_exact']['caller']
        candidate, final = nested/'reference-exact-candidate.so', nested/'reference-exact-final.so'
        caller_candidate, caller_final = nested/'reference-caller-candidate.so', nested/'reference-caller.so'
        selection = nested/'reference-exact-selection.json'
        authority = nested/'reference-caller-authority.json'
        for path, expected in ((candidate, exact['candidate']), (final, exact['final']),
                (caller_candidate, helper['candidate']), (caller_final, helper['final']),
                (selection, exact['manifest']), (authority, helper['authority'])):
            assert path.resolve(strict=True) == path
            assert digest(path) == expected
            artifacts[path] = expected
        assert fixture.authenticate(candidate, final, exact['elf_va'], 37, selection, exact['manifest']['sha256']) == {
            key: value for key, value in exact.items() if key not in ('status', 'candidate', 'manifest', 'source')}
        assert read_json(selection)['revision'] == args.revision
        assert caller_candidate.read_bytes() == caller_final.read_bytes()
        assert (caller_candidate.stat().st_dev, caller_candidate.stat().st_ino) != (caller_final.stat().st_dev, caller_final.stat().st_ino)
        assert read_json(authority) == dict(schema=1, revision=args.revision, final=helper['final'],
            source=sources['tools/rapid-profiler/normal-work/reference_caller.S'],
            geometry_source=sources['tools/rapid-profiler/normal-work/reference_bytes.rs'],
            build_stage='reference-caller-build', symbol='normal_reference_caller', closed_body_bytes=295,
            required_labels=32, scope='Complete independently built ELF authority; actual owner must authenticate body, all labels and live mapping before invocation.')
        result['prerequisite'] = dict(result=digest(nested/'result.json'),
            command=digest(args.raw/'prerequisite-command.json'), closure=digest(args.raw/'prerequisite-closed.json'),
            owned_stages=30, nested_helpers=46, nested_outer_owners=48, rescues=0)
        result['artifacts'] = dict(binary=digest(binary), subject=exact, caller=helper, profile=PROFILE)
        helper_path = repo/'tools/unwind-oracle/bounded_command.py'

        def invoke(directory, request):
            unchanged()
            assert (directory/'request.json').read_bytes() == encoded(request)
            parent = [str(tool_paths['python']), '-B', str(helper_path),
                '--request', str(directory/'request.json'), '--receipt', str(directory/'receipt.json')]
            closed = processes.run_command(parent, env, logs/(directory.name+'.log'), min(55, remaining()), MIB)
            (directory/'parent.log').write_bytes((logs/(directory.name+'.log')).read_bytes())
            freeze(directory/'parent-closed.json', encoded(closed))
            stdout, stderr = (directory/'stdout.txt').read_bytes(), (directory/'stderr.txt').read_bytes()
            parent_log = retain_parent_log(artifacts, directory/'parent.log', closed)
            receipt_bytes = (directory/'receipt.json').read_bytes()
            assert (directory/'request.json').read_bytes() == encoded(request)
            join_owned(request, read_json(directory/'request.json'), content(encoded(request))['sha256'],
                sources['tools/unwind-oracle/bounded_command.py']['sha256'],
                json.loads(receipt_bytes), closed, json.loads(parent_log), stdout, stderr)
            for filename, data in (('request.json', encoded(request)), ('stdout.txt', stdout),
                    ('stderr.txt', stderr), ('receipt.json', receipt_bytes),
                    ('parent-closed.json', encoded(closed))):
                retain(artifacts, directory/filename, content(data))
            unchanged()
            return stdout, stderr

        def request_for(directory, argv):
            directory.mkdir(); (directory/'tmp').mkdir()
            return dict(argv=[str(item) for item in argv], cwd=str(repo), env=dict(env, TMPDIR=str(directory/'tmp')),
                stdout=str(directory/'stdout.txt'), stderr=str(directory/'stderr.txt'),
                cpu_seconds=20, wall_seconds=30, file_bytes=MIB)

        os.sched_setaffinity(0, {min(cpus)})
        assert sorted(os.sched_getaffinity(0)) == [min(cpus)]
        for name, count in (('test_reference_study_analysis.py', 15),
                ('test_reference_study.py', 10)):
            result['stage'] = name
            directory = args.raw/name.removesuffix('.py')
            request = request_for(directory, [tool_paths['python'], '-B', folder/name])
            freeze(directory/'request.json', encoded(request))
            control = dict(name=name, status='FAILED', methods=count); result['controls'].append(control); persist()
            stdout, stderr = invoke(directory, request)
            assert stdout == b'' and re.fullmatch(rb'\.{'+str(count).encode()+rb'}\n-+\nRan '+str(count).encode()+
                rb' tests in [0-9]+\.[0-9]+s\n\nOK\n', stderr)
            record_files(control, directory, artifacts); control['status'] = 'PASS'
        tail = [candidate, final, str(exact['elf_va']), '37', caller_candidate, caller_final]
        requests = []
        for key in catalog:
            directory = args.raw/('process-%03d' % key['process'])
            request = request_for(directory, [binary, 'normal-reference-leg',
                key['phase'], str(key['trial']), key['leg'], *tail])
            freeze(directory/'request.json', encoded(request))
            requests.append((directory, request))
            record_files(progress.rows[key['process']-1], directory, artifacts)
        frozen = encoded([dict(key, request=digest(directory/'request.json'))
            for key, (directory, _) in zip(catalog, requests)])
        freeze(args.raw/'requests.json', frozen); artifacts[args.raw/'requests.json'] = content(frozen)
        result['catalog'] = digest(public/'catalog.json'); result['requests'] = content(frozen)
        result['stage'] = 'study'; persist()
        for key, (directory, request) in zip(catalog, requests):
            unchanged()
            assert sorted(os.sched_getaffinity(0)) == [min(cpus)]
            assert (public/'catalog.json').read_bytes() == catalog_bytes
            assert (args.raw/'requests.json').read_bytes() == frozen
            assert digest(directory/'request.json') == read_json(args.raw/'requests.json')[key['process']-1]['request']
            if key['process'] > 100:
                assert (public/'budget.json').read_bytes() == progress.budget
            progress.start(key); result['stage'] = 'process-%03d' % key['process']; persist()
            try:
                stdout, stderr = invoke(directory, request)
                checked = parser.check(stdout, stderr, key['phase'], key['trial'], key['leg'])
                assert checked['status'] == 'FUNCTIONAL_PASS' and checked['calls'] == 24
                observation = analysis.project(key, checked['rows'])
                progress.finish(key, observation)
            finally:
                record_files(progress.rows[key['process']-1], directory, artifacts); persist()
            if key['process'] == 100:
                budget = analysis.calibrate(progress.observations)
                data = analysis.canonical(budget)
                freeze(public/'budget.json', data)
                progress.frozen_budget(budget, data, analysis)
                artifacts[public/'budget.json'] = content(data)
                result['budget'] = content(data); persist()
        progress.complete(); unchanged()
        assert sorted(os.sched_getaffinity(0)) == [min(cpus)]
        summary = analysis.summarize(catalog, progress.observations, read_json(public/'budget.json'))
        summary_bytes = analysis.canonical(summary)
        exports(public, progress, result['sources']['sha256'])
        freeze(args.raw/'sources-after.json', encoded({name: digest(repo/name) for name in sources}))
        assert (args.raw/'sources-after.json').read_bytes() == (args.raw/'sources-before.json').read_bytes()
        assert sum(len(row['rows']) for row in progress.observations) == 9600
        assert sum(2 if row['leg'] == 'original' else 4 for row in progress.observations)*24 == 33600
        unchanged()
        freeze(public/'summary.json', summary_bytes)
        result.update(status='COMPLETE', stage='complete', processes_completed=400,
            calls=9600, timestamp_endpoints=33600, summary=digest(public/'summary.json'))
    except BaseException as error:
        result.update(status='FAILED', error_type=type(error).__name__)
        if (public/'summary.json').exists():
            (public/'summary.json').replace(args.raw/'incomplete-summary.json')
        (args.raw/'failure.txt').write_text(traceback.format_exc())
    finally:
        if progress is not None and result['status'] != 'COMPLETE':
            exports(public, progress, result['sources']['sha256'])
        if progress is not None:
            result['exports'] = {name: digest(public/name) for name in ('processes.csv', 'endpoints.csv')}
        persist()
        # A closed subset only: no private paths, argv, traceback, PIDs in receipts,
        # duplicated raw observations, tool output blobs or filesystem identities.
        receipt = {key: value for key, value in result.items() if key not in ('processes',)}
        freeze(public/'receipt.json', encoded(receipt))
    print('reference-study '+result['status']+' stage='+result['stage'])
    return 0 if result['status'] == 'COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
