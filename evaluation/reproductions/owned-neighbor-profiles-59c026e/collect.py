#!/usr/bin/env python3
"""Project closed synthetic profile controls into sanitized data; execute nothing."""
import argparse
import ast
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sys

REVISION = '59c026e4da35b25dae2e270a5a63aa1b9e8cd41b'
DRIVER_SHA = 'e347afd9326c1d6e232ce4ce72b3abd2217b6a3bba8d19046192189b496bae3d'
PHASES = [('production', 'test_production_profile.py', 'ProductionProfile', 10),
          ('ordinary', 'test_candidate_profile.py', 'CandidateProfile', 11)]


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', type=Path, required=True)
    ap.add_argument('--raw', type=Path, required=True)
    ap.add_argument('--new-output', type=Path, required=True)
    args = ap.parse_args()
    repo, raw, out = args.repo, args.raw, args.new_output
    assert repo.is_absolute() and repo.resolve(strict=True) == repo
    assert raw.is_relative_to(repo / 'ignored') and raw.resolve(strict=True) == raw
    assert out.is_relative_to(repo / 'ignored') and out.parent.resolve(strict=True) == out.parent and not out.exists()
    sha = lambda b: hashlib.sha256(b).hexdigest()
    encode = lambda x: (json.dumps(x, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    facts = {}
    def read(path):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_file()
        before = path.stat()
        assert before.st_size <= 8 * 1024 * 1024
        data = path.read_bytes()
        assert path.stat() == before and len(data) == before.st_size
        facts[str(path)] = dict(sha256=sha(data), bytes=len(data))
        return data
    obj = lambda p: json.loads(read(p))
    def normalize(value):
        if isinstance(value, str):
            assert '${REPO}' not in value
            result = value.replace(str(repo), '${REPO}')
            assert result.replace('${REPO}', str(repo)) == value
            return result
        if isinstance(value, list):
            return [normalize(x) for x in value]
        if isinstance(value, dict):
            result = {normalize(k): normalize(v) for k, v in value.items()}
            assert len(result) == len(value)
            return result
        return value
    rows, cases, contexts = [], [], []
    source_files = hardware = tools = None
    for phase, filename, classname, count in PHASES:
        d, launch = raw / phase, raw / (phase + '-launch')
        before, after = obj(d / 'inputs-before.json'), obj(d / 'inputs-after.json')
        assert before == after and before['source']['revision'] == REVISION
        src = {p: {k: v[k] for k in ('sha256', 'bytes', 'mode')} for p, v in before['source']['files'].items()}
        if source_files is None:
            source_files, tools = src, normalize({k: before[k] for k in ('python', 'helper')})
        assert src == source_files and normalize({k: before[k] for k in ('python', 'helper')}) == tools
        hw = obj(d / 'hardware.json')
        assert hw['host_label'] == 'AMD EPYC Zen 5 dev host'
        if hardware is None:
            hardware = hw
        assert hardware == hw
        outer = {n: obj(launch / (n + '.json')) for n in ('command', 'started', 'closed')}
        inner = {n: obj(d / (n + '.json')) for n in ('command', 'request', 'started', 'closed', 'receipt', 'summary')}
        for root, context, stdout, stderr in [(launch, outer, 'stdout.txt', 'stderr.txt'),
                                               (d, inner, 'helper.stdout', 'helper.stderr')]:
            c = context['closed']
            assert c['exit'] == 0 and c['parent_error'] is None and c['parent_wait_returned'] is True
            assert c['pid'] == context['started']['pid']
            assert c['stdout_sha256'] == sha(read(root / stdout)) and c['stderr_sha256'] == sha(read(root / stderr))
        assert outer['command']['source_revision'] == inner['command']['source_revision'] == REVISION
        assert outer['command']['source_sha256'] == inner['command']['caller_sha256'] == DRIVER_SHA
        assert sha(read(Path(outer['command']['argv'][2]))) == DRIVER_SHA
        assert outer['command']['argv'][3:] == ['--repo', str(repo), '--output', str(d), '--phase', phase]
        request, receipt = inner['request'], inner['receipt']
        path = 'evaluation/e9-common-app/' + filename
        assert request['argv'] == ['/usr/bin/python3.9', '-B', str(repo / path), '-v']
        assert (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == (10, 15, 1048576)
        assert inner['command']['affinity'] == [0, 1, 2, 3] and inner['command']['parent_timeout_seconds'] == 40
        assert inner['command']['request_sha256'] == receipt['request_sha256'] == sha(read(d / 'request.json'))
        assert receipt['exit'] == 0 and receipt['absence_proof'] == 'ECHILD' and not receipt['unexpected_descendants']
        assert receipt['inputs_unchanged'] and not receipt['wall_timeout'] and receipt['cleanup_error'] is None and receipt['aborted'] is None
        stdout, stderr = read(d / 'stdout.txt'), read(d / 'stderr.txt')
        assert not stdout and receipt['stdout_sha256'] == sha(stdout) and receipt['stderr_sha256'] == sha(stderr)
        source = read(repo / path)
        assert sha(source) == source_files[path]['sha256'] == inner['command']['control_sha256']
        classes = [n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == classname]
        assert len(classes) == 1
        names = sorted(n.name for n in classes[0].body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_'))
        assert len(names) == count == inner['command']['planned_test_methods']
        lines = stderr.decode().splitlines()
        assert lines[:count] == [name + ' (__main__.' + classname + ') ... ok' for name in names]
        assert len(lines) == count + 5 and lines[count:count + 2] == ['', '-' * 70]
        duration = re.fullmatch(r'Ran ' + str(count) + r' tests in (\d+\.\d+)s', lines[count + 2])
        assert duration and lines[count + 3:] == ['', 'OK']
        summary = inner['summary']
        assert summary['status'] == 'PASS' and summary['source_tools_equal'] is True
        assert summary['tested_revision'] == REVISION and summary['planned_test_methods'] == count
        assert not summary['actual_production'] and not summary['ordinary_application_execution'] and not summary['native_execution']
        context = dict(outer=outer, inner=inner)
        contexts.append(context)
        rows.append(dict(phase=phase, status='PASS_SYNTHETIC_CONTROLS', passed=count, failed=0, skipped=0,
                         seconds=receipt['elapsed_seconds'], unittest_seconds=float(duration[1]), context=normalize(context)))
        cases.extend(dict(phase=phase, classname=classname, name=n, status='PASS') for n in names)
    summary = dict(tested_revision=REVISION, hardware=hardware, tools=tools, phases=[{k: v for k, v in r.items() if k != 'context'} for r in rows],
                   passed_test_methods=21, failed=0, skipped=0, collector_sha256=sha(Path(__file__).read_bytes()),
                   driver_sha256=DRIVER_SHA, scope='synthetic saved-record profile admission controls only',
                   actual_production=False, ordinary_application_execution=False, native_execution=False,
                   full_a3=False, qualification_complete=False, durations_are_operational_not_performance=True)
    public = {'summary.json': encode(summary), 'commands.json': encode(rows), 'cases.json': encode(cases),
              'source-files.json': encode(source_files), 'records.json': encode(normalize(facts))}
    for name, values, fields in [('cases.csv', cases, ('phase', 'classname', 'name', 'status')),
                                  ('commands.csv', rows, ('phase', 'status', 'passed', 'failed', 'skipped', 'seconds', 'unittest_seconds'))]:
        s = io.StringIO(newline='')
        w = csv.DictWriter(s, fieldnames=fields, lineterminator='\n')
        w.writeheader()
        w.writerows({k: r[k] for k in fields} for r in values)
        public[name] = s.getvalue().encode()
    for data in public.values():
        text = data.decode()
        assert '/' + 'home' + '/' not in text and not re.search(r'\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|local|internal)\b', text)
    out.mkdir()
    (out / 'public').mkdir()
    (out / 'private').mkdir()
    for name, data in public.items():
        (out / 'public' / name).write_bytes(data)
    (out / 'private/command-inverses.json').write_bytes(encode(contexts))
    (out / 'private/roles.json').write_bytes(encode({'${REPO}': str(repo)}))
    (out / 'collection.json').write_bytes(encode({n: dict(sha256=sha(b), bytes=len(b)) for n, b in public.items()}))
    print(json.dumps(dict(public_files=len(public),methods=len(cases),workload_execution=False)))


if __name__ == '__main__':
    main()
