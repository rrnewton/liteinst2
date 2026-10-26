#!/usr/bin/env python3
"""Project reviewed, closed failed production records; never execute a product."""
import argparse
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SELF = 'evaluation/e9-common-app/collect_production.py'
RECIPE = 'evaluation/e9-common-app/produce.py'
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
CAP = 64 * 1024 * 1024
LANES = ('stock-algorithm', 'bootstrap-patched-reference')
CELLS = [(h, s, v) for h in ('null', 'journal') for s in ('jump-site', 'heap-write')
         for v in ('unstripped', 'stripped')]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def loads(data):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            assert k not in result, 'duplicate JSON key'
            result[k] = v
        return result
    def invalid(value):
        raise AssertionError('non-JSON constant: ' + value)
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid)


def read(path):
    path = Path(path)
    assert path.is_absolute() and '..' not in path.parts
    assert path.parent.resolve(strict=True) == path.parent
    fields = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_size <= CAP
        data = f.read(CAP + 1)
        assert len(data) == before.st_size and fields(before) == fields(os.fstat(f.fileno()))
    return data, fields(before)


def git(repo, *args):
    result = subprocess.run(['/usr/bin/git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
        '-C', str(repo), *args], env=ENV, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
    assert not result.stderr and len(result.stdout) <= CAP
    return result.stdout


def csv_bytes(rows, fields):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=fields, lineterminator='\n')
    writer.writeheader()
    writer.writerows({k: row.get(k) for k in fields} for row in rows)
    return out.getvalue().encode()


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'inputs', 'new-output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--inputs-sha256', required=True)
    args = parser.parse_args()
    repo, output = args.repo, args.new_output
    assert repo.is_absolute() and repo.resolve(strict=True) == repo
    assert output.is_absolute() and output.parent.resolve(strict=True) == output.parent
    assert output.is_relative_to(repo / 'ignored') and not output.exists() and not output.is_symlink()
    assert Path(__file__).absolute() == repo / SELF
    self_before, self_owner = read(repo / SELF)
    reporter = git(repo, 'rev-parse', 'HEAD').decode().strip()
    assert re.fullmatch('[0-9a-f]{40}', reporter)
    assert git(repo, 'show', reporter + ':' + SELF) == self_before
    assert not git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--binary', 'HEAD', '--')
    input_bytes, input_owner = read(args.inputs)
    assert sha(input_bytes) == args.inputs_sha256 and re.fullmatch('[0-9a-f]{64}', args.inputs_sha256)
    envelope = loads(input_bytes)
    assert envelope.keys() == {'schema', 'authority', 'raw', 'launch', 'review_binding',
                               'review_sha256', 'roles', 'privacy_literals'}
    assert type(envelope['schema']) is int and envelope['schema'] == 1
    assert envelope['authority'] == 'CALLER_SELECTED_CLOSED_FAILED_PRODUCTION_RECORDS'
    raw, launch, review_path = (Path(envelope[k]) for k in ('raw', 'launch', 'review_binding'))
    roots = (raw, launch, review_path.parent)
    assert len(set(roots)) == 3
    for p in roots:
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
        assert p.is_relative_to(repo / 'ignored') and not output.is_relative_to(p)
    assert all(not p.is_relative_to(q) for p in roots for q in roots if p != q)
    assert review_path.name == 'binding.json' and re.fullmatch('[0-9a-f]{64}', envelope['review_sha256'])
    blobs, owners = {}, {}
    def remember(path):
        key = str(path)
        if key not in blobs:
            blobs[key], owners[key] = read(path)
            assert len(blobs) <= 1024 and sum(map(len, blobs.values())) <= 128 * 1024 * 1024
        return blobs[key]
    review_data = remember(review_path)
    assert sha(review_data) == envelope['review_sha256']
    review = loads(review_data)
    assert review['verdict'] == 'CLOSED_FAILED_PRODUCTION_RECORDS_VERIFIED'
    assert review['record_integrity_findings'] == [] and review['goalpost_moves'] is False
    assert review['raw_directory'] == str(raw) and review['launch_directory'] == str(launch)
    assert review['qualification_complete'] is review['full_a3'] is False
    assert review['ordinary_executions'] == review['native_executions'] == review['architectural_comparisons'] == 0
    refs_data = remember(review_path.parent / 'references.json')
    assert review['files']['references.json'] == dict(bytes=len(refs_data), sha256=sha(refs_data))
    refs = loads(refs_data)
    assert len(refs) == review['reference_count']
    def bound(path):
        assert path.is_relative_to(raw) or path.is_relative_to(launch)
        assert path.suffix in ('.json', '.tsv', '.txt') or path.name in ('COMPLETE', 'helper.stdout', 'helper.stderr')
        assert not {'artifacts', 'target', 'captures'}.intersection(path.parts)
        data = remember(path)
        assert refs[str(path)]['sha256'] == sha(data) and refs[str(path)]['bytes'] == len(data)
        return data
    def obj(path):
        return loads(bound(path))
    roles = envelope['roles']
    assert 3 <= len(roles) <= 32 and len(set(roles.values())) == len(roles)
    assert roles['${REPO}'] == str(repo) and roles['${RAW}'] == str(raw) and roles['${LAUNCH}'] == str(launch)
    assert all(re.fullmatch(r'\$\{[A-Z][A-Z0-9_]*\}', k) and len(k) <= 64 and
               isinstance(v, str) and 1 < len(v) <= 4096 and v.startswith('/') for k, v in roles.items())
    tokens = re.compile('|'.join(re.escape(k) for k in roles))
    locations = re.compile('|'.join(re.escape(v) for v in sorted(roles.values(), key=len, reverse=True)))
    inverse = {v: k for k, v in roles.items()}
    def normalize(value):
        if isinstance(value, str):
            assert not tokens.search(value), 'literal role collision'
            result = locations.sub(lambda m: inverse[m[0]], value)
            assert tokens.sub(lambda m: roles[m[0]], result) == value
            return result
        if isinstance(value, list):
            return [normalize(v) for v in value]
        if isinstance(value, dict):
            result = {normalize(k): normalize(v) for k, v in value.items()}
            assert len(result) == len(value), 'normalized key collision'
            return result
        return value
    index_data = bound(raw / 'raw-files.json')
    assert sha(index_data) == review['raw_index_sha256']
    index = loads(index_data)
    assert len(index) == review['raw_files'] and sum(r['bytes'] for r in index.values()) == review['raw_bytes']
    for name, pin in index.items():
        p = Path(name)
        assert not p.is_absolute() and '..' not in p.parts and str(p) == name
        prior = refs[str(raw / p)]
        assert all(pin[k] == prior[k] for k in ('sha256', 'bytes', 'stat'))
    def artifact(name):
        # A reviewed index fact, not a new product read or current owner admission.
        pin = index.get(name)
        return None if pin is None else {k: pin[k] for k in ('sha256', 'bytes')}
    summary, results, saved_cells = (obj(raw / n) for n in ('summary.json', 'results.json', 'cells.json'))
    for name, key in (('summary.json', 'summary_sha256'), ('results.json', 'results_sha256')):
        assert sha(bound(raw / name)) == review[key]
    source = obj(raw / 'source-before.json')
    assert source == obj(raw / 'source-after.json')
    revision = source['revision']
    assert re.fullmatch('[0-9a-f]{40}', revision) and revision == summary['revision'] == review['tested_revision']
    source_hash = sha(json.dumps(source['files'], sort_keys=True, separators=(',', ':')).encode())
    assert source_hash == review['source_files_sha256'] and len(source['files']) == review['source_files']
    recipe_sha = sha(git(repo, 'show', revision + ':' + RECIPE))
    assert recipe_sha == review['producer_source_sha256'] == source['files'][RECIPE]['sha256']
    assert summary['successful'] is False and summary['completed_traversal'] is True and summary['fatal'] is None
    assert summary['qualification_complete'] is False and summary['ordinary_dataset_executions'] == summary['native_executions'] == 0
    hardware = obj(raw / 'hardware.json')
    assert hardware.keys() == {'host_label', 'architecture', 'cpu_model', 'kernel_release', 'libc', 'logical_cpus'}
    assert hardware['host_label'] == 'AMD EPYC Zen 5 dev host' and hardware['architecture'] == 'x86_64'
    inputs = obj(raw / 'inputs.json')
    assert sha(bound(raw / 'inputs.json')) == review['input_index_sha256']
    assert len(inputs['files']) == review['input_files']
    keys = ['-'.join(cell) for cell in CELLS]
    planned = []
    for i, key in enumerate(keys):
        if i == 4:
            planned += ['hook-compile', 'hook-link']
        planned += [key + '-core']
        planned += [key + '-' + lane + '-' + phase for lane in LANES
                    for phase in ('transport', 'producer', 'adapter', 'compare')]
    assert obj(raw / 'stage-inventory.json') == planned == [r['name'] for r in results]
    assert len(planned) == summary['planned_stages'] == 74 and set(saved_cells) == set(keys)
    assert summary['core_cells'] == summary['reference_cells_per_lane'] == 8
    counts = {status: sum(r['status'] == status for r in results) for status in ('PASS', 'FAILED', 'UNRUN')}
    assert sum(counts.values()) == 74 and counts['FAILED'] > 0
    assert review['stages'] == dict(planned=74, attempted=74-counts['UNRUN'], passed=counts['PASS'],
                                  failed=counts['FAILED'], unrun=counts['UNRUN'])
    assert summary['attempted_stages'] == review['strict_receipts'] == 74-counts['UNRUN']
    contexts, stage_rows, terminal_lines = [], [], []
    helper_sha = source['files']['tools/unwind-oracle/bounded_command.py']['sha256']
    for number, row in enumerate(results, 1):
        name, status = row['name'], row['status']
        context = dict(final_result=row, request=None, outer_command=None, receipt=None,
                       outer_wait=None, command_result=None, postcheck=None)
        flat = dict(ordinal=number, **row)
        if status == 'UNRUN':
            assert row.keys() == {'name', 'status', 'reason'}
            assert not any(n.startswith(name + '/') for n in index), 'UNRUN stage has records'
        else:
            d = raw / name
            request, command, receipt, outer, result = (obj(d / n) for n in
                ('request.json', 'command.json', 'receipt.json', 'outer.json', 'result.json'))
            assert command['request'] == request and receipt['request_sha256'] == sha(bound(d / 'request.json'))
            assert receipt.keys() == {'request_sha256', 'helper_sha256', 'exit', 'wall_timeout', 'unexpected_descendants',
                'absence_proof', 'stdout_sha256', 'stderr_sha256', 'elapsed_seconds', 'cleanup_events',
                'cleanup_error', 'aborted', 'inputs_unchanged'}
            assert type(receipt['exit']) is int and receipt['helper_sha256'] == helper_sha
            assert receipt['wall_timeout'] is False and receipt['absence_proof'] == 'ECHILD'
            assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['cleanup_error'] is receipt['aborted'] is None and receipt['inputs_unchanged'] is True
            assert result['exit'] == row['exit'] == receipt['exit']
            assert result['receipt_sha256'] == row['receipt_sha256'] == sha(bound(d / 'receipt.json'))
            assert outer['parent_timeout'] is result['parent_timeout'] is row['parent_timeout'] is False
            assert outer['parent_exit'] == result['parent_exit'] == row['parent_exit'] == (0 if receipt['exit'] == 0 else 1)
            assert result['status'] == ('PASS' if receipt['exit'] == 0 else 'FAILED')
            assert outer['operational_seconds'] == result['operational_seconds'] == row['operational_seconds']
            for value in (receipt['elapsed_seconds'], row['operational_seconds']):
                assert type(value) in (int, float) and math.isfinite(value) and value >= 0
            for stream in ('stdout', 'stderr'):
                assert request[stream] == str(d / (stream + '.txt'))
                assert receipt[stream + '_sha256'] == index[name + '/' + stream + '.txt']['sha256']
            terminal = dict(exit=receipt['exit'], wall_timeout=False, absence_proof='ECHILD',
                            descendants=0, success=receipt['exit'] == 0)
            assert bound(d / 'helper.stdout') == (json.dumps(terminal) + '\n').encode()
            assert not bound(d / 'helper.stderr')
            post = obj(d / 'postcheck.json') if name + '/postcheck.json' in index else None
            assert status == ('PASS' if result['status'] == 'PASS' and (post is None or post['pass_'] is True) else 'FAILED')
            compiler = name in ('hook-compile', 'hook-link')
            assert (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == (
                60 if compiler else 20, 90 if compiler else 30, (128 if compiler else 16) * 1024 * 1024)
            assert command['parent_timeout_seconds'] == (115 if compiler else 55)
            assert command['outer_env'] == ENV and command['cwd'] == request['cwd']
            assert request['env'] == dict(ENV, TMPDIR=request['env']['TMPDIR'])
            assert command['outer_argv'] == [inputs['tools']['timeout'], '--signal=TERM', '--kill-after=10s',
                '100s' if compiler else '40s', inputs['tools']['helper_python'], '-B',
                request['cwd'] + '/tools/unwind-oracle/bounded_command.py', '--request', str(d / 'request.json'),
                '--receipt', str(d / 'receipt.json')]
            context.update(request=request, outer_command=command, receipt=receipt,
                           outer_wait=outer, command_result=result, postcheck=post)
            flat.update(cpu_seconds=request['cpu_seconds'], wall_seconds=request['wall_seconds'],
                        file_bytes=request['file_bytes'], helper_seconds=receipt['elapsed_seconds'],
                        command_status=result['status'], postcheck_pass=None if post is None else post['pass_'])
            terminal_lines.append(f'{name} {result["status"]} {result["exit"]}\n')
        contexts.append(context)
        stage_rows.append(flat)
    launch_command, started, closed = (obj(launch / n) for n in ('command.json', 'started.json', 'closed.json'))
    assert started['command_sha256'] == sha(bound(launch / 'command.json'))
    assert closed['pid'] == started['pid'] and closed['parent_wait_returned'] is True
    assert type(closed['exit']) is int and closed['exit'] == review['parent_exit'] == 1
    assert closed['operational_seconds'] == review['parent_wait_seconds']
    assert sha(bound(launch / 'closed.json')) == review['parent_closed_sha256']
    assert bound(launch / 'stdout.txt') == ''.join(terminal_lines).encode()
    assert not bound(launch / 'stderr.txt')
    for stream in ('stdout', 'stderr'):
        assert sha(bound(launch / (stream + '.txt'))) == closed[stream + '_sha256']
    assert launch_command['recipe_sha256'] == recipe_sha and launch_command['source_revision'] == revision
    assert launch_command['env'] == ENV and launch_command['cwd'] == str(repo)
    assert launch_command['argv'] == [inputs['tools']['python'], '-B', str(repo / RECIPE), '--inputs',
        launch_command['argv'][4], '--inputs-sha256', review['input_index_sha256'], '--raw', str(raw)]
    cell_rows, cell_details = [], []
    for key, (hook, style, variant) in zip(keys, CELLS):
        cell = saved_cells[key]
        policy = obj(raw / key / 'comparison-policy.json')
        selection = bound(raw / key / 'core/selection.txt')
        assert sha(selection) == policy['selection_sha256']
        selected = [line.split() for line in selection.decode().splitlines() if line.startswith('site ')]
        geometry = [[int(r[1]), int(r[2]), int(r[4]), int(r[3])] for r in selected]
        assert len(geometry) == (9 if style == 'jump-site' else 1) and len({r[0] for r in geometry}) == len(geometry)
        original = inputs['files'][inputs['preparation']['originals'][variant]]
        assert original['sha256'] == policy['original_sha256']
        failure_name = key + '/core/input-failure.tsv'
        failure = None
        if failure_name in index:
            lines = bound(raw / failure_name).decode().splitlines()
            assert lines[:5] == ['LI2INPUTFAIL\t1', 'selection_sha256\t' + policy['selection_sha256'],
                'observed_original_sha256\t' + policy['original_sha256'], 'qualification_complete\tfalse',
                'site\tpc\tfile_offset\tlength\tstage\tdetail_hex']
            failure = list(csv.DictReader(io.StringIO('\n'.join(lines[4:])), delimiter='\t'))
            assert [[int(r[k]) for k in ('site', 'pc', 'file_offset', 'length')] for r in failure] == geometry
            for r in failure:
                r['detail'] = bytes.fromhex(r['detail_hex']).decode()
        details = dict(name=key, hook=hook, style=style, variant=variant, policy=policy,
            selected_sites=len(geometry), original=original, core=cell['core'], core_input_failure=failure,
            core_candidate=artifact(key + '/core/candidate.elf'), references={})
        flat = dict(name=key, hook=hook, style=style, variant=variant, selected_sites=len(geometry),
                    core_status=results[planned.index(key + '-core')]['status'],
                    core_candidate_present=details['core_candidate'] is not None)
        for lane in LANES:
            ref = cell['references'][lane]
            adapter = ref.get('adapter')
            sites, projected = None, None
            candidate = artifact(key + '/' + lane + '/candidate.elf')
            if adapter is not None:
                site_data = bound(raw / key / lane / 'inventory/sites.tsv')
                assert sha(site_data) == adapter['site_inventory_sha256']
                assert obj(raw / key / lane / 'inventory/producer-binding.json') == adapter
                lines = site_data.decode().splitlines()
                assert lines[:7] == ['LI2E9SITES\t1', 'original_sha256\t' + policy['original_sha256'],
                    'selection_sha256\t' + policy['selection_sha256'], 'e9_revision\t' + policy['e9_revision'],
                    'instrumentation\t' + policy['instrumentation'], 'selection_style\t' + style,
                    'site\tpc\tfile_offset\tlength\toutcome\treason_hex']
                sites = list(csv.DictReader(io.StringIO('\n'.join(lines[6:])), delimiter='\t'))
                assert [[int(r[k]) for k in ('site', 'pc', 'file_offset', 'length')] for r in sites] == geometry
                assert adapter['selected_sites'] == len(geometry) and adapter['candidate_sha256'] == candidate['sha256']
                assert adapter['qualification_complete'] is adapter['architectural_equivalence_proved'] is False
                assert adapter['runtime_executed_by_adapter'] is adapter['transport_witness_is_patch_success'] is False
                projected = {k: v for k, v in adapter.items() if k not in ('input_files', 'input_owners', 'ownership')}
                for r in sites:
                    r['reason'] = loads(bytes.fromhex(r['reason_hex']))
            details['references'][lane] = dict(result={k: v for k, v in ref.items() if k != 'adapter'},
                candidate=candidate, growth_bytes=None if candidate is None else candidate['bytes']-original['bytes'],
                adapter=projected, site_rows=sites)
            flat[lane + '_status'] = ref['status']
            flat[lane + '_phase'] = ref.get('phase')
            flat[lane + '_candidate_bytes'] = None if candidate is None else candidate['bytes']
            flat[lane + '_admitted_sites'] = None if adapter is None else len(sites)
        cell_details.append(details)
        cell_rows.append(flat)
    report = dict(schema=1, tested_revision=revision, recipe_sha256=recipe_sha,
        reporting_revision=reporter, collector_sha256=sha(self_before), hardware=hardware,
        production=summary, stage_counts=counts, actual_helper_commands=74-counts['UNRUN'],
        actual_recipe_launches=1, command_context_rows=75, cells=8,
        source_files=len(source['files']), source_files_sha256=source_hash,
        raw_index=dict(sha256=sha(index_data), files=len(index), bytes=review['raw_bytes']),
        review_sha256=sha(review_data), preserved_failures=review['preserved_failures'],
        parent={k: v for k, v in closed.items() if k != 'pid'},
        hook_artifact=artifact('hook/e9_hook'), qualification_complete=False, full_a3=False,
        ordinary_executions=0, native_executions=0, architectural_comparisons=0,
        limits=['Saved-record reporting only; artifact hashes come from the reviewed raw index, not new product reads.',
                'Historical source map and byte/owner checks retain the named independent review authority.',
                'Unavailable site inventories and unrun command contexts stay null; no success is inferred.',
                'All durations are operational diagnostics, not benchmarks. No loader, runtime or state-equivalence credit.'])
    commands = dict(recipe=dict(command=launch_command, parent=report['parent']), stages=contexts,
                    scope='Full actual argv/env/cwd/limits and saved outcomes; unrun contexts are null.')
    public_objects = {'summary.json': report, 'cells.json': cell_details, 'commands.json': commands,
                      'source-files.json': dict(tested_revision=revision, files=source['files'])}
    public = {name: encode(normalize(value)) for name, value in public_objects.items()}
    stage_fields = ['ordinal', 'name', 'status', 'reason', 'exit', 'parent_exit', 'parent_timeout',
        'command_status', 'postcheck_pass', 'cpu_seconds', 'wall_seconds', 'file_bytes',
        'operational_seconds', 'helper_seconds', 'receipt_sha256', 'result_scope']
    public['stages.csv'] = csv_bytes(normalize(stage_rows), stage_fields)
    public['cells.csv'] = csv_bytes(normalize(cell_rows), list(cell_rows[0]))
    literals = envelope['privacy_literals']
    assert isinstance(literals, list) and 1 <= len(literals) <= 32
    assert all(isinstance(s, str) and 3 <= len(s) <= 4096 for s in literals)
    for data in public.values():
        assert len(data) <= CAP
        text = data.decode()
        assert '/home/' not in text and '/Users/' not in text
        assert all(s not in text for s in literals), 'private identity in public projection'
    public['files.json'] = encode({n: dict(bytes=len(b), sha256=sha(b)) for n, b in sorted(public.items())})
    # Reauthenticate every consumed saved record and the reporting source before any output write.
    for name, data in blobs.items():
        assert read(Path(name)) == (data, owners[name])
    assert read(args.inputs) == (input_bytes, input_owner)
    assert read(repo / SELF) == (self_before, self_owner)
    assert git(repo, 'rev-parse', 'HEAD').decode().strip() == reporter
    assert not git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--binary', 'HEAD', '--')
    private = encode(dict(schema=1, authority='Saved-record transformation, not a new production review',
        collector_revision=reporter, collector_sha256=sha(self_before), collector_owner=self_owner,
        inputs_sha256=sha(input_bytes), input_owner=input_owner, review_sha256=sha(review_data), roles=roles,
        raw_command_contexts=commands, read_inputs={n: dict(bytes=len(b), sha256=sha(b), stat=owners[n])
            for n, b in sorted(blobs.items())}, public_files=loads(public['files.json']),
        actual_reporting_parent_closure=None, qualification_complete=False))
    assert len(private) <= CAP and sum(map(len, public.values())) + len(private) <= 256 * 1024 * 1024
    output.mkdir(mode=0o700)
    (output / 'public').mkdir(mode=0o700)
    for name, data in public.items():
        with (output / 'public' / name).open('xb') as f:
            f.write(data)
    with (output / 'private-binding.json').open('xb') as f:
        f.write(private)
    assert read(repo / SELF) == (self_before, self_owner)
    assert git(repo, 'rev-parse', 'HEAD').decode().strip() == reporter
    assert not git(repo, 'diff', '--no-ext-diff', '--no-textconv', '--binary', 'HEAD', '--')
    print('Reported 74 failed-campaign stage rows and 8 cells; qualification_complete=false')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
