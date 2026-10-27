#!/usr/bin/env python3
"""Project closed cross-function validation records; execute no validation."""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys

REVISION = 'be886cc1637630985bef497ad2d6376facdb883f'
DRIVER_SHA = '138dac66abdfe8cd41f1345c4e7faee468d54a6fd6302d0a673b9b9a64353aae'
PHASES = ('targeted', 'required', 'serial', 'parallel-library', 'parallel-prefixed')
COMMANDS = {
    'targeted': (['cargo', 'test', '-p', 'liteinst2', '--test', 'cross_function_neighbor',
                 '--test', 'foreign_neighbor_engine', '--test', 'neighbor_eviction_contract',
                 '--test', 'search_eviction_evidence'], 180, 4),
    'serial': (['cargo', 'test', '-p', 'liteinst-launch', '--tests', '--',
                '--test-threads=1', '--nocapture'], 180, 4),
    'parallel-library': (['cargo', 'test', '-p', 'liteinst2', '--lib'], 360, 8),
    'parallel-prefixed': (['cargo', 'test', '-p', 'liteinst2', '--test', 'prefixed_pun_oracle'], 360, 8),
}
GATES = (('fmt', ['cargo', 'fmt', '--check'], 180),
         ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 180),
         ('test', ['cargo', 'test', '--workspace'], 360),
         ('check', ['cargo', 'check', '--workspace', '--all-features', '--all-targets'], 180))
COUNT_KEYS = ('passed', 'failed', 'ignored', 'measured', 'filtered_out')
HARDWARE = 'AMD EPYC Zen 5 dev host'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def loads(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def csv_bytes(rows, fields):
    output = io.StringIO(newline='')
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator='\n')
    writer.writeheader()
    writer.writerows({k: r.get(k) for k in fields} for r in rows)
    return output.getvalue().encode()


def read(path):
    assert path.is_absolute() and '..' not in path.parts and path.parent.resolve(strict=True) == path.parent
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= 16 * 1024 * 1024
        data = stream.read(before.st_size + 1)
        fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        assert fields(before) == fields(os.fstat(stream.fileno())) == fields(path.lstat()) and len(data) == before.st_size
    return data


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--inputs', type=Path, required=True)
    ap.add_argument('--inputs-sha256', required=True)
    ap.add_argument('--new-output', type=Path, required=True)
    args = ap.parse_args()
    ib = read(args.inputs); assert sha(ib) == args.inputs_sha256
    spec = loads(ib)
    assert set(spec) == {'schema', 'repo', 'raw', 'driver', 'parser', 'phases', 'files', 'roles', 'privacy_literals'}
    assert spec['schema'] == 1 and set(spec['phases']) == set(PHASES)
    repo, raw, out = Path(spec['repo']), Path(spec['raw']), args.new_output
    assert raw.is_relative_to(repo / 'ignored') and out.is_relative_to(repo / 'ignored')
    assert not out.exists() and out.parent.resolve(strict=True) == out.parent and not out.is_relative_to(raw)
    facts, inverses = {}, []

    def bound(path):
        path = Path(path)
        assert not path.is_relative_to(repo / 'target')
        expected = spec['files'][str(path)]
        assert set(expected) == {'sha256', 'bytes'}
        data = read(path)
        assert expected == dict(sha256=sha(data), bytes=len(data))
        facts[str(path)] = expected
        return data

    def obj(path):
        return loads(bound(path))

    assert sha(bound(spec['driver'])) == DRIVER_SHA
    parser_path = Path(spec['parser'])
    assert parser_path == repo / 'evaluation/admission/parsing.py'
    parser_bytes = bound(parser_path)
    # The authenticated public parser contains definitions only; it launches nothing.
    parser = runpy.run_path(str(parser_path), run_name='cross_function_report_parser')
    assert read(parser_path) == parser_bytes
    roles = spec['roles']
    assert roles['${REPO}'] == str(repo) and roles['${RAW}'] == str(raw)
    assert 2 <= len(roles) <= 16 and len(set(roles.values())) == len(roles)
    assert all(re.fullmatch(r'\$\{[A-Z][A-Z0-9_]*\}', k) and isinstance(v, str) and v.startswith('/') for k, v in roles.items())
    token = re.compile('|'.join(re.escape(k) for k in roles))
    locations = re.compile('|'.join(re.escape(v) for v in sorted(roles.values(), key=len, reverse=True)))
    inverse = {v: k for k, v in roles.items()}

    def normalize(value):
        if isinstance(value, str):
            assert not token.search(value)
            normalized = locations.sub(lambda m: inverse[m[0]], value)
            assert token.sub(lambda m: roles[m[0]], normalized) == value
            return normalized
        if isinstance(value, list): return [normalize(x) for x in value]
        if isinstance(value, dict):
            result = {normalize(k): normalize(v) for k, v in value.items()}
            assert len(result) == len(value)
            return result
        assert value is None or type(value) in (bool, int, float)
        return value

    cases, groups, terminals, parsing = [], [], [], []

    def inventory(phase, command_id, data, exit_code, description):
        pattern = re.compile(rb'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;')
        terminals.extend(dict(command=command_id, byte_offset=m.start(), text=m[0].decode(),
                              attribution='literal observation; not additive') for m in pattern.finditer(data))
        if description is None:
            assert exit_code != 0, 'successful tests require their complete reviewed inventory'
            return None
        assert set(description) == {'binding', 'checks', 'groups'}
        binding_path = Path(description['binding']); review = obj(binding_path)
        checks = obj(description['checks']); observed = obj(description['groups'])
        assert review.get('revision', review.get('source_revision')) == REVISION and review['findings'] == []
        assert checks['raw_log_sha256'] == sha(data) and checks['nested_passes_aggregated'] is False
        for key in ('checks', 'groups'):
            p = Path(description[key]); entry = review['files'][p.name]
            expected_sha = entry if isinstance(entry, str) else entry['sha256']
            assert facts[str(p)]['sha256'] == expected_sha
        assert len(observed) == checks['outer_groups']
        text = data.decode(); lines = text.splitlines(); expected = {}; local_cases = []
        for group in observed:
            gid = parser['harness_id'](group['header']); assert gid is not None and gid not in expected
            assert lines[group['start_line']-1] == group['header']
            first, last = group['start_line'], group['end_line']
            block = '\n'.join(lines[first-1:last])
            counts = dict(zip(COUNT_KEYS, group['summary'][1]))
            assert len(group['cases']) == sum(counts[k] for k in ('passed', 'failed', 'ignored'))
            assert counts['measured'] == counts['filtered_out'] == 0
            statuses = {'ok': 0, 'FAILED': 0, 'ignored': 0}
            for name, value in group['cases'].items():
                status = value['status']; assert status in statuses
                assert 'test ' + name + ' ... ' in block
                statuses[status] += 1
                local_cases.append(dict(command=command_id, group=gid, name=name, status=status))
            assert statuses == {'ok': counts['passed'], 'FAILED': counts['failed'], 'ignored': counts['ignored']}
            expected[gid] = dict(tests=len(group['cases']), ignored=counts['ignored'])
            groups.append(dict(command=command_id, group=gid, counts=counts,
                               nested_terminal_observations=len(group['nested_summaries']), review_sha256=facts[str(binding_path)]['sha256']))
        totals = {k: sum(g['counts'][k] for g in groups if g['command'] == command_id) for k in COUNT_KEYS}
        assert totals == checks['outer_counts'] and len(local_cases) == checks['outer_named_cases']
        assert len({(x['group'], x['name']) for x in local_cases}) == len(local_cases)
        cases.extend(local_cases)
        try:
            parser['parse_harnesses'](text, expected, exit_code)
            parser_result = 'COMPLETE'
        except parser['InvalidEvidence'] as error:
            # Preserve public-parser limitations; exact reviewed inventory remains separate authority.
            parser_result = error.code
        parsing.append(dict(command=command_id, public_parser=parser_result, reviewed_inventory=True,
                            log_sha256=sha(data), review_sha256=facts[str(binding_path)]['sha256']))
        return totals

    rows, phases, source_files, hardware = [], [], None, None
    for phase in PHASES:
        root, launch = raw / phase, raw / (phase + '-launch')
        selected = spec['phases'][phase]
        if selected is None:
            assert not root.exists() and not launch.exists(), 'unclosed/partial phase must not become UNRUN'
            phases.append(dict(phase=phase, status='UNRUN'))
            rows.append(dict(id=phase, scope='required-dispatch' if phase == 'required' else 'validation', status='UNRUN', exit=None, seconds=None, counts=None, context=None))
            if phase == 'required':
                rows.extend(dict(id='required/' + name, scope='required-gate', status='UNRUN', exit=None, seconds=None, counts=None, context=None) for name, _, _ in GATES)
            continue
        assert set(selected) == {'inventory'}
        caller, started, closed = (obj(launch / n) for n in ('command.json', 'started.json', 'closed.json'))
        assert closed['parent_wait_returned'] is True and closed['pid'] == started['pid']
        assert closed['stdout_sha256'] == sha(bound(launch / 'stdout.txt')) and closed['stderr_sha256'] == sha(bound(launch / 'stderr.txt'))
        assert caller['source_revision'] == REVISION and caller['source_sha256'] == DRIVER_SHA
        assert caller['argv'][:3] == ['/usr/bin/python3.9', '-B', spec['driver']]
        expected_tail = ['--repo', str(repo), '--output', str(root), '--toolchain', roles['${TOOLCHAIN}'],
                         '--user-home', roles['${USER_HOME}'], '--cargo-home', roles['${CARGO_HOME}'], '--phase', phase]
        assert caller['argv'][3:] == expected_tail and caller['cwd'] == str(repo)
        saved = {n: obj(root / n) if (root / n).is_file() else None for n in
                 ('command.json', 'process-result.json', 'summary.json', 'inputs-before.json', 'inputs-after.json', 'hardware.json')}
        command, result, summary = (saved[n] for n in ('command.json', 'process-result.json', 'summary.json'))
        status = 'PASS' if summary is not None and summary['status'] == 'PASS' else 'FAILED'
        if summary is not None:
            assert summary['status'] in ('PASS', 'FAILED') and summary['phase'] == phase and summary['revision'] == REVISION
            assert summary['command'] == result and summary['qualification_complete'] is False
        if status == 'PASS':
            assert all(x is not None for x in saved.values()) and closed['exit'] == 0 and closed['parent_error'] is None
            assert result['exit_code'] == 0 and result['termination'] is None and result['cleanup_complete'] is True and result['reaped_descendants'] == 0
            assert saved['inputs-before.json'] == saved['inputs-after.json'] and summary['source_tools_configs_equal'] is True
        else:
            assert closed['exit'] != 0 or closed['parent_error'] is not None or (result is not None and result['exit_code'] != 0) or summary is not None
        before = saved['inputs-before.json']; phase_source = None
        if before is not None:
            assert before['source']['revision'] == REVISION
            phase_source = {p: {k: v[k] for k in ('sha256', 'bytes', 'mode')} for p, v in before['source']['files'].items()}
            assert phase_source['evaluation/admission/parsing.py']['sha256'] == sha(parser_bytes)
            if source_files is None: source_files = phase_source
            assert source_files == phase_source
        hw = saved['hardware.json']
        if hw is not None:
            assert hw['host_label'] == HARDWARE
            if hardware is None: hardware = hw
            assert hw == hardware
        log = bound(root / 'command.log') if (root / 'command.log').is_file() else None
        counts = None
        if status == 'PASS':
            assert log is not None, 'PASS phase requires complete command.log'
        if command is not None:
            assert command['source_revision'] == REVISION and command['caller_sha256'] == DRIVER_SHA
            assert command['cwd'] == str(repo) and command['max_log_bytes'] == 8 * 1024 * 1024
            env = command['env']
            assert env['CARGO_INCREMENTAL'] == '0' and env['CARGO_BUILD_JOBS'] == '4' and env['CARGO_NET_OFFLINE'] == 'true'
            assert env['CARGO_PROFILE_DEV_DEBUG'] == env['CARGO_PROFILE_TEST_DEBUG'] == '0'
            assert env['RUSTFLAGS'] == env['RUSTDOCFLAGS'] == env['RUSTC_WRAPPER'] == env['RUSTC_WORKSPACE_WRAPPER'] == ''
            assert env['LITEINST_EVALUATION'] == '1' and 'RUST_TEST_THREADS' not in env
            expected_argv, wall, cpus = (['/usr/bin/python3.9', '-B', str(repo / 'evaluation/required-gates.py'), '--repo', str(repo), '--output', str(root / 'gates')], 1000, 4) if phase == 'required' else COMMANDS[phase]
            assert command['argv'] == expected_argv and command['timeout_seconds'] == wall and command['affinity'] == list(range(cpus))
        if result is not None and log is not None:
            assert result['private_log_sha256'] == sha(log)
            if phase != 'required': counts = inventory(phase, phase, log, result['exit_code'], selected['inventory'])
        if status == 'PASS' and phase != 'required':
            assert counts is not None, 'PASS test phase requires complete reviewed inventory'
        context = dict(caller=caller, started=started, parent=closed, command=command, process_result=result, summary=summary)
        inverses.append(context)
        rows.append(dict(id=phase, scope='required-dispatch' if phase == 'required' else 'validation', status=status,
                         exit=result['exit_code'] if result is not None else None, seconds=result['seconds'] if result is not None else None,
                         parent_seconds=closed['seconds'], log_sha256=sha(log) if log is not None else None,
                         counts=counts, context=normalize(context)))
        phases.append(dict(phase=phase, status=status, source_tools_configs_equal=summary['source_tools_configs_equal'] if summary else None,
                           tools={n: {k: v[k] for k in ('sha256', 'bytes')} for n, v in before['tools'].items()} if before else None,
                           rustc_version=command['rustc'] if command else None, other_tool_versions=None,
                           configurations_sha256=sha(encode(before['configurations'])) if before else None))
        if phase == 'required':
            receipt = obj(root / 'gates/commands.json') if (root / 'gates/commands.json').is_file() else None
            records = receipt['records'] if receipt else []
            assert len(records) <= 4 and [x['name'] for x in records] == [x[0] for x in GATES[:len(records)]]
            if receipt:
                assert receipt['head'] == REVISION and receipt['tracked_diff_sha256'] == sha(b'')
                assert receipt['source_sha256'] == {p: v['sha256'] for p, v in source_files.items()}
            if status == 'PASS': assert len(records) == 4 and all(x['exit'] == 0 for x in records)
            for index, (name, argv, wall) in enumerate(GATES):
                row = records[index] if index < len(records) else None; count = None; gate_context = None
                if row:
                    assert row['argv'] == argv and row['timeout_seconds'] == wall
                    gate_log = bound(repo / row['log']); assert row['sha256'] == sha(gate_log)
                    if name == 'test': count = inventory(phase, 'required/test', gate_log, row['exit'], selected['inventory'])
                    gate_env = dict(command['env'], RUST_TEST_THREADS='4', TMPDIR=str(root / 'gates'))
                    gate_context = dict(record=row, cwd=str(repo), env=gate_env, affinity=command['affinity'])
                    inverses.append(gate_context)
                rows.append(dict(id='required/' + name, scope='required-gate', status='UNRUN' if row is None else 'PASS' if row['exit'] == 0 else 'FAILED',
                                 exit=row['exit'] if row else None, seconds=row['seconds'] if row else None,
                                 log_sha256=row['sha256'] if row else None, counts=count, context=normalize(gate_context)))
    assert len(phases) == 5 and len(rows) == 9
    summary = dict(schema=1, tested_revision=REVISION, hardware=hardware, driver_sha256=DRIVER_SHA,
                   collector_sha256=sha(read(Path(__file__).resolve())), phases=phases,
                   status='PASS' if all(x['status'] == 'PASS' for x in rows) else 'FAILED' if any(x['status'] == 'FAILED' for x in rows) else 'INCOMPLETE',
                   planned_validation_commands=8, required_dispatch_rows=1, command_rows=9,
                   debug_information='disabled', debug_assertions='unchanged', operational_durations_not_performance=True,
                   native_t3_qualification=False, full_a3=False, qualification_complete=False,
                   case_totals_not_added_across_repeated_commands=True, raw_terminal_observations_not_additive=True)
    public = {'summary.json': encode(summary), 'commands.json': encode(rows), 'cases.json': encode(cases),
              'groups.json': encode(groups), 'terminal-observations.json': encode(terminals), 'parser-results.json': encode(parsing),
              'source-files.json': encode(source_files), 'files.json': encode(normalize(facts))}
    public['commands.csv'] = csv_bytes(rows, ('id', 'scope', 'status', 'exit', 'seconds', 'parent_seconds', 'log_sha256'))
    public['cases.csv'] = csv_bytes(cases, ('command', 'group', 'name', 'status'))
    for data in public.values():
        text = data.decode()
        assert '/' + 'home' + '/' not in text and all(x not in text for x in spec['privacy_literals'])
        assert not re.search(r'\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|local|internal)\b', text)
    out.mkdir(mode=0o700); (out / 'public').mkdir(); (out / 'private').mkdir(mode=0o700)
    for name, data in public.items(): (out / 'public' / name).write_bytes(data)
    (out / 'private/roles.json').write_bytes(encode(roles))
    (out / 'private/command-inverses.json').write_bytes(encode(inverses))
    (out / 'private/records.json').write_bytes(encode(facts))
    result = dict(completed=True, scope='saved validation reporting only', public={n: dict(sha256=sha(b), bytes=len(b)) for n, b in public.items()})
    (out / 'collection.json').write_bytes(encode(result)); print(encode(result).decode(), end='')


if __name__ == '__main__':
    main()
