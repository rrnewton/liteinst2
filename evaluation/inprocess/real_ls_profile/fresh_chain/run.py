#!/usr/bin/env python3
"""One reserved CPU: fresh cold9, then native41, then the unchanged real probe."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
STAGES = (
    ('cold9', 'cold_admission_loop', 'persistent-cold-admission-finite-v1', 'passed'),
    ('native41', 'direct_frontier_loop', 'persistent-direct-frontier-finite-v1', 'passed'),
    ('program', 'direct_frontier_program', 'direct-frontier-program-probe-v1', 'completed_unqualified'),
)
REQUIRED = ['same-revision original392 and cross-pair522 qualification with their original prerequisites',
            'ten-run same-host native and DR comparison']
CONTROLS = dict(terminal_controls=73, repeat_tls_controls=33, native_probe_controls=22,
                subentry_controls=19, effect_controls=12)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def decode(raw):
    def pairs(items):
        need(len(items) == len(dict(items)), 'duplicate JSON key')
        return dict(items)
    return json.loads(raw, object_pairs_hook=pairs)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def fact(path):
    need(path.is_file() and not path.is_symlink(), 'regular file required: '+str(path))
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def source_file(path):
    return dict(fact(path), mode=stat.S_IMODE(path.stat().st_mode))


def case_projection(cases):
    rows = [{k: c[k] for k in ('lane', 'mode', 'status', 'expected_exit', 'exit', 'whole_process_ns',
        'timed_out', 'launched', 'captures', 'pair', 'owner_summary', 'error_type') if k in c} for c in cases]
    for row, actual in zip(rows, cases, strict=True):
        row['controls'] = {key: dict(count=len(actual[key]['refusals']), sha256=digest(actual[key]))
            for key in ('application_controls', 'owner_reader_controls', 'pair_controls', *CONTROLS) if key in actual}
    return rows


def finite_cases(actual, public, stage):
    cold = stage == 'cold9'
    qualification = ('passed unchanged native41/original392/522 cohorts plus this finite cold-admission cohort, exact same source/CPU/archive/hardware'
        if cold else 'passed original392 and522 cohorts plus this finite41 cohort, exact same source/CPU/archive/hardware')
    need(actual['required_qualification'] == public['required_qualification'] == qualification,
         'original whole-profile gates remain mandatory')
    expected = [(lane, mode, 0) for mode in (range(3) if cold else (0,))
                for lane in ('native', 'maintained', 'differential')]
    need([(c['lane'], c['mode'], c['control']) for c in actual['cases']] == expected,
         'complete ordered finite subjects')
    for c in actual['cases']:
        status = ('observed_native_cold_admission' if c['lane'] == 'native' else
                  'observed_generated_cold_admission_'+c['lane']) if cold else (
                  'observed_native_direct_frontier' if c['lane'] == 'native' else
                  'observed_generated_direct_frontier_'+c['lane'])
        need(c['status'] == status and c['exit'] == c['expected_exit'] == 0 and
             c['launched'] is True and c['timed_out'] is False, 'completed finite subject')
        wanted = dict(application_controls=40) if c['lane'] == 'native' else dict(
            CONTROLS, owner_reader_controls=270 if cold else 404, pair_controls=32 if cold else 28)
        present = {k for k in ('application_controls', 'owner_reader_controls', 'pair_controls', *CONTROLS) if k in c}
        need(present == set(wanted), 'exact per-lane finite control domains')
        for key, count in wanted.items():
            names = c[key]['refusals']
            need(type(names) is list and all(type(n) is str and n for n in names) and
                 len(names) == len(set(names)) == count, 'exact finite control population: '+key)
    need(public['cases'] == case_projection(actual['cases']), 'whole finite case projection')
    keys = ('capture_codec_component', 'subentry_component', 'empty_namespace_component',
            'cross_page_handoff_component', 'direct_frontier_component')
    for key in keys + (('cold_direct_handoff_component', 'cold_seed_plan_component') if cold else ()):
        need(actual[key]['status'] == public[key]['status'] == 'passed' and actual[key]['exit'] == 0 and
             all(value == actual[key][name] for name, value in public[key].items()),
             'mandatory actual finite component: '+key)


def receipt(root, stdout, stage, revision, cpu, fresh_after):
    key, module, profile, success = stage
    answer = decode(stdout)
    need(set(answer) == {'status', 'receipt'}, 'exact child result envelope')
    path = Path(answer['receipt'])
    pattern = r'[0-9]{8}T[0-9]{6}\.[0-9]{6}Z-'+module.replace('_', '-')+'-'+revision[:12]+r'\.json'
    need(path.parent == Path('evaluation/inprocess/results') and re.fullmatch(pattern, path.name),
         'exact child-selected canonical receipt')
    timestamp = path.name.split('-')[0]
    need(timestamp >= fresh_after, 'receipt predates this stage; no replay')
    public_path = root/path
    need(public_path.resolve(strict=True) == public_path and public_path.stat().st_size <= 32768,
         'bounded public receipt without path aliases')
    public = decode(public_path.read_bytes())
    private_path = root/'target/evaluation/inprocess'/path.stem/'receipt.json'
    need(private_path.resolve(strict=True) == private_path and fact(private_path) == public['receipt'],
         'whole private receipt selected by actual public receipt')
    actual = decode(private_path.read_bytes())
    common = ('schema', 'profile', 'status', 'revision', 'source', 'source_unchanged', 'cleanup_complete',
              'cpu', 'bounds', 'scope', 'whole_profile_qualified')
    need(all(public[k] == actual[k] for k in common) and actual['schema'] == 1 and
         actual['profile'] == profile and actual['revision'] == revision and actual['cpu'] == cpu and
         actual['source']['revision'] == revision and actual['source']['tracked_clean'] is True and
         actual['source']['head_sources_match'] is True and actual['whole_profile_qualified'] is False and
         answer['status'] == actual['status'], 'exact public/private source profile CPU and status')
    hw = dict(actual['hardware'])
    if key == 'program':
        flags = hw.pop('isa_flags'); hw.update(isa_flags_count=len(flags), isa_flags_sha256=digest(flags))
        need(actual['qualification_credit'] is public['qualification_credit'] is False and
             actual['performance_credit'] is public['performance_credit'] is False and
             actual['required_unmet'] == public['required_unmet'] == REQUIRED, 'unmet whole qualification remains explicit')
    need(public['hardware'] == hw and actual['hardware']['probe_cpu'] == cpu and
         actual['hardware']['affinity_cpu_count'] == 1, 'actual public/private hardware and reserved CPU')
    need(actual['bounds']['program'] == [30, 512 << 20, 16 << 20, 60] and
         all(actual['bounds'][p] == [5, 512 << 20, 16 << 20, 15] for p in ('finite', 'seed')),
         'unchanged finite and program bounds')
    commands = actual['commands']
    need(public['command_count'] == len(commands) and public['commands_sha256'] == digest(commands) and
         len({c['name'] for c in commands}) == len(commands), 'whole ordered command identity')
    need(all(c['bounds'] == actual['bounds'][c['profile']] for c in commands), 'original per-command bounds')
    archive = actual['build']['artifacts']['decoder.a']
    archive_path = Path(archive['path'])
    archive_fact = {k: archive[k] for k in ('bytes', 'sha256')}
    need(archive_path.is_relative_to(private_path.parent) and archive_path.resolve(strict=True) == archive_path and
         source_file(archive_path) == dict(archive_fact, mode=archive['mode']) and archive_fact == public['archive'] and
         actual['build']['status'] == 'passed' and actual['build']['command_completed'] is True,
         'complete actual fresh decoder archive')
    if key == 'program':
        need(actual['archive'] == archive_fact, 'program archive fact')
    refs = {str(p.relative_to(root)): fact(p) for p in (public_path, private_path, public_path.with_suffix('.csv'), archive_path)}
    if key != 'program':
        table = io.StringIO(); writer = csv.writer(table, lineterminator='\n')
        writer.writerow(('revision', 'command', 'exit', 'duration_ns', 'status'))
        for c in commands:
            writer.writerow((revision, c['name'], c.get('exit'), c.get('duration_ns'), actual['status']))
        need(public_path.with_suffix('.csv').read_bytes() == table.getvalue().encode(), 'whole finite command CSV')
    if actual['status'] == success:
        need(actual['error'] is None and actual['final_errors'] == [] and actual['source_unchanged'] is True and
             actual['cleanup_complete'] is True and commands and all(c.get('reaped') is True and
             c.get('cleanup_errors') == [] and all(d.get('closed') is True for d in c['descriptors'])
             for c in commands), 'complete successful source and process closure')
        if key != 'program':
            finite_cases(actual, public, key)
        else:
            need([(c['program'], c['lane']) for c in actual['cases']] ==
                 [(p, lane) for p in ('ls', 'true') for lane in ('native', 'counted')] and
                 all(c['exit'] == 0 and c['launched'] is True and c['timed_out'] is False and
                 c['stdout_equal'] is True and c['status'] == ('completed_native_reference' if c['lane'] == 'native'
                 else 'completed_unqualified') for c in actual['cases']), 'all four real program subjects complete')
    return public_path, public, actual, archive_fact, refs


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}', args.expect_revision), 'exact revision with assertions')
    root = Path.cwd().resolve(); cpu_set = os.sched_getaffinity(0)
    need(len(cpu_set) == 1, 'one externally reserved CPU for the whole chain')
    cpu = next(iter(cpu_set)); here = Path(__file__).resolve().parent
    plan = decode((here/'SOURCE.json').read_bytes())
    need(source_file(here/'run.py') == plan['script'], 'reviewed chain script identity')
    pinned = {str(here/name): source_file(here/name) for name in ('run.py', 'SOURCE.json', 'README.md')}
    for row in plan['installed_sources']:
        path = root/row['destination']
        need(source_file(path) == row['fact'], 'exact reviewed installed stage source')
        pinned[str(path)] = row['fact']
    env_git = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    def git(*args_):
        return subprocess.check_output(['/usr/bin/git', '--no-replace-objects', '-C', str(root),
            '-c', 'core.fsmonitor=false', *args_], env=env_git)
    def stable():
        need(git('rev-parse', 'HEAD').decode().strip() == args.expect_revision and
             not git('status', '--porcelain', '--untracked-files=no'), 'exact clean source throughout chain')
        need(os.sched_getaffinity(0) == cpu_set and all(source_file(Path(p)) == v for p, v in pinned.items()),
             'same reserved CPU and all chain/stage source bytes and modes')
    stable()
    out = args.output.resolve()
    need(out.is_relative_to(root/'target/evaluation/inprocess') and not out.exists(), 'fresh private chain output')
    out.mkdir(parents=True, exist_ok=False)
    record = dict(schema=1, profile='direct-cold-program-chain-v1', status='failed', revision=args.expect_revision,
        cpu=cpu, stages=[], source_unchanged=False, receipts_unchanged=False, whole_profile_qualified=False,
        qualification_credit=False, performance_credit=False, required_unmet=REQUIRED, error=None)
    held = {}; baseline = None; native_path = None; native_receipt = None; result = 1
    try:
        for stage in STAGES:
            key, module, _, success = stage
            stable(); need(all(fact(root/p) == v for p, v in held.items()), 'prior stage receipts/archive unchanged')
            argv = [sys.executable, '-B', 'evaluation/inprocess/'+module+'.py', '--expect-revision', args.expect_revision]
            if key == 'program':
                need(native_path is not None and native_receipt is not None, 'fresh native41 prerequisite retained')
                argv += ['--direct-receipt', str(native_path.relative_to(root))]
            started = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
            child = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (out/(key+'.stdout')).write_bytes(child.stdout); (out/(key+'.stderr')).write_bytes(child.stderr)
            sys.stdout.buffer.write(child.stdout); sys.stdout.buffer.flush()
            sys.stderr.buffer.write(child.stderr); sys.stderr.buffer.flush()
            row = dict(stage=key, argv=argv, exit=child.returncode, status='failed', started_utc=started,
                stdout=fact(out/(key+'.stdout')), stderr=fact(out/(key+'.stderr')))
            record['stages'].append(row)
            path, public, actual, archive, refs = receipt(root, child.stdout, stage, args.expect_revision, cpu, started)
            join = {k: actual[k] for k in ('source', 'hardware', 'bounds')}; join['archive'] = archive
            if baseline is None:
                baseline = join
                need(actual['source']['tree'] == git('rev-parse', 'HEAD^{tree}').decode().strip(), 'actual exact source tree')
            else:
                need(join == baseline, 'same exact source CPU hardware archive and all bounds across stages')
            if key == 'native41':
                native_path = path; native_receipt = public['receipt']
            if key == 'program':
                prior = actual['direct_prerequisite']
                need(prior == public['direct_prerequisite'] and prior['status'] == 'passed' and
                     prior['file'] == str(native_path.relative_to(root)) and
                     {k: prior[k] for k in ('bytes', 'sha256')} == fact(native_path) and
                     prior['receipt'] == native_receipt and prior['archive'] == archive,
                     'unchanged program gate consumed this exact fresh native41 prerequisite')
            held.update(refs)
            row.update(status=actual['status'], public_receipt=str(path.relative_to(root)),
                public=fact(path), private_receipt=public['receipt'], archive=archive, cases=len(actual['cases']))
            stable()
            need(child.returncode == 0 and actual['status'] == success, 'stage failed; later stages remain unexecuted: '+key)
        record['status'] = 'completed_unqualified'; result = 0
    except BaseException as error:
        record['error'] = type(error).__name__+': '+str(error)
    finally:
        try:
            stable(); record['source_unchanged'] = True
            record['receipts_unchanged'] = all(fact(root/p) == v for p, v in held.items())
            need(record['receipts_unchanged'], 'retained stage receipts/archive changed')
        except BaseException as error:
            record['final_error'] = type(error).__name__+': '+str(error)
            record['status'] = 'failed'; result = 1
        record['unexecuted'] = [stage[0] for stage in STAGES[len(record['stages']):]]
        record['inputs'] = pinned; record['retained'] = held
        raw = (json.dumps(record, indent=2, sort_keys=True, allow_nan=False)+'\n').encode()
        need(len(raw) < 32768, 'compact private chain receipt')
        (out/'receipt.json').write_bytes(raw)
    return result


if __name__ == '__main__':
    raise SystemExit(main())
