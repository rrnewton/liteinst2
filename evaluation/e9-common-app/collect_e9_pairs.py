#!/usr/bin/env python3
"""Regenerate the fixed eight-cell E9 report from authenticated saved JSON only."""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys

REV = '9884b7a259b4e0ea80d2cca6d726abab4594807a'
HARDWARE = 'AMD EPYC Zen 5 dev host'
RUNNER = '3feea2da3dbc4455af5133caebc87441709a8342caa068f215640d3e3b2a6973'
AUDITORS = ('448d255df8220d2a2503ab13b6a2b02482dbca240986416f4c5444669f0da8ad',
            '5cf71fbe47efccd39517228f51c80513d979575ecabdd5057e179a7daa3b8700')
ORDER = ['null-' + style + '-' + variant + '-' + lane
         for style in ('heap-write', 'jump-site')
         for variant in ('unstripped', 'stripped')
         for lane in ('stock-algorithm', 'bootstrap-patched-reference')]
CASE_KEYS = {'call_intermediate_checks', 'comparisons', 'fault', 'full_stack_bytes',
             'head', 'logical_completion', 'physical_completion', 'state', 'status'}
CAP = 32 * 1024 * 1024


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
        data = f.read(before.st_size + 1)
        assert len(data) == before.st_size and fields(before) == fields(os.fstat(f.fileno()))
    return data


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
    for name in ('inputs', 'new-output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    args = parser.parse_args()
    input_bytes = read(args.inputs)
    assert sha(input_bytes) == args.inputs_sha256 and re.fullmatch('[0-9a-f]{64}', args.inputs_sha256)
    spec = loads(input_bytes)
    assert set(spec) == {'schema', 'authority', 'epoch', 'repo', 'collector_sha256',
                         'admissions', 'failures', 'roles', 'privacy_literals'}
    assert spec['schema'] == 1 and spec['authority'] == 'CALLER_SELECTED_CLOSED_EIGHT_E9_REPORT_RECORDS'
    repo, epoch, out = Path(spec['repo']), Path(spec['epoch']), args.new_output
    assert repo.is_absolute() and epoch == repo/'ignored/a3/common-native-epoch-v1'
    assert repo.resolve(strict=True) == repo and epoch.resolve(strict=True) == epoch
    assert out.is_absolute() and out.is_relative_to(repo/'ignored') and out.parent.resolve(strict=True) == out.parent
    assert not out.exists() and not out.is_symlink() and not out.is_relative_to(epoch)
    self_bytes = read(Path(__file__).absolute())
    assert sha(self_bytes) == spec['collector_sha256']
    assert len(spec['admissions']) == 8 and len(spec['failures']) == 2
    blobs, facts = {}, {}

    def metadata(path, expected):
        p = Path(path)
        assert p.is_relative_to(epoch) and p.suffix == '.json'
        assert not {'captures', 'artifacts', 'target'}.intersection(p.relative_to(epoch).parts)
        assert isinstance(expected, dict) and re.fullmatch('[0-9a-f]{64}', expected['sha256'])
        key = str(p)
        if key not in blobs:
            blobs[key] = read(p)
            assert len(blobs) <= 512 and sum(map(len, blobs.values())) <= 256 * 1024 * 1024
        b = blobs[key]
        assert sha(b) == expected['sha256'] and ('bytes' not in expected or len(b) == expected['bytes'])
        fact = dict(sha256=sha(b), bytes=len(b))
        if key in facts:
            assert facts[key] == fact
        facts[key] = fact
        return loads(b)

    def bound(path, refs):
        return metadata(path, refs[str(path)])

    def local(binding, path, name):
        pin = binding['files'][name]
        return metadata(Path(path).parent/name, dict(sha256=pin) if isinstance(pin, str) else pin)

    def same_record(refs, other, path):
        a, b = refs[str(path)], other[str(path)]
        assert all(a[k] == b[k] for k in ('sha256', 'bytes', 'stat'))

    roles = spec['roles']
    assert 2 <= len(roles) <= 32 and len(set(roles.values())) == len(roles)
    assert roles['${REPO}'] == str(repo) and roles['${EPOCH}'] == str(epoch)
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
        assert value is None or type(value) in (bool, int, float)
        return value

    def namespace(label, refs, expected_exit):
        d = epoch/'runtime-isolation-launch-v7'/label
        command, closed = (bound(d/n, refs) for n in ('command-spec.json', 'closed.json'))
        assert command['scope'] == 'CALLER_PINNED_PRIVATE_CACHE_COMMAND'
        assert closed['exit'] == expected_exit and closed['parent_wait_returned'] is True
        # Complete argv/env/cwd are projected; owners/provider details remain private.
        return dict(command={k: command[k] for k in ('argv', 'env', 'cwd')},
                    command_source_sha256=command['command_source']['sha256'],
                    helper_sha256=command['helper_sha256'], ready_sha256=command['ready_sha256'],
                    closed=closed)

    commands, original_contexts = [], []

    def command_row(cell, kind, d, refs, status, expected_exit, ns=None, script_sha=None):
        request, command, receipt = (bound(d/n, refs) for n in ('request.json', 'command.json', 'receipt.json'))
        parent_name = 'parent-closed.json' if kind.startswith('audit') else 'outer.json'
        parent = bound(d/parent_name, refs)
        assert receipt['request_sha256'] == facts[str(d/'request.json')]['sha256']
        assert receipt['exit'] == expected_exit and receipt['absence_proof'] == 'ECHILD'
        assert receipt['wall_timeout'] is False and receipt['unexpected_descendants'] == []
        assert receipt['cleanup_error'] is receipt['aborted'] is None and receipt['inputs_unchanged'] is True
        assert parent['exit'] == (0 if expected_exit == 0 else 1)
        if parent_name == 'parent-closed.json':
            assert parent['parent_wait_returned'] is True
            assert command['request_sha256'] == receipt['request_sha256']
        else:
            assert parent['parent_timeout'] is False and command['request'] == request
        assert (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == (
            (20, 30, 16*1024*1024) if kind == 'verify' else (60, 90, 64*1024*1024))
        is_script = request['argv'][:2] == ['/usr/bin/python3.9', '-B']
        subject = request['argv'][2] if is_script else request['argv'][0]
        subject_sha = refs[subject]['sha256']
        if script_sha is not None:
            assert is_script and subject_sha == script_sha
        script_sha = subject_sha if is_script else None
        context = dict(request=request, command=command, receipt=receipt, parent=parent, namespace=ns)
        original_contexts.append(context)
        row = dict(ordinal=len(commands)+1, cell=cell, kind=kind, status=status,
                   exit=expected_exit, operational_seconds=receipt['elapsed_seconds'],
                   parent_seconds=parent['operational_seconds'], cpu_seconds_measured=None,
                   cpu_limit=request['cpu_seconds'], wall_limit=request['wall_seconds'],
                   file_limit=request['file_bytes'], script_sha256=script_sha,
                   subject_sha256=subject_sha,
                   helper_sha256=receipt['helper_sha256'], stdout_sha256=receipt['stdout_sha256'],
                   stderr_sha256=receipt['stderr_sha256'], context=normalize(context))
        commands.append(row)

    cells, cases, source_files, obligations = [], [], None, []
    upstream = None
    admission_objects = []
    source_limits = None
    for number, cell in enumerate(ORDER, 1):
        before_paths = set(facts)
        item = spec['admissions'][number-1]
        assert set(item) == {'admission', 'references'}
        ap, mp = Path(item['admission']['path']), Path(item['references']['path'])
        expected_dir = 'e9-first-admission-v1' if number == 1 else 'e9-admission-%03d-v1' % number
        assert ap == epoch/expected_dir/'admission.json' and mp == ap.with_name('references.json')
        refs = metadata(mp, item['references'])
        admission = metadata(ap, item['admission'])
        assert refs[str(ap)]['sha256'] == item['admission']['sha256']
        assert admission['authority'] == 'CALLER_REVIEWED_E9_PAIR_ATTEMPT'
        assert admission['status'] == 'PASS_CONTENT_REVIEWED' and admission['content_audit_passed'] is True
        assert admission['source_revision'] == REV and admission['cell'] == cell
        assert admission['first_failed_audit_retained'] is admission['parent_closed_reaped'] is True
        assert admission['qualification_complete'] is admission['full_a3'] is admission['normal_loader_validation'] is False
        assert admission['attempt_record'] is None
        assert len(admission['evidence_files']) == len(set(admission['evidence_files'])) == (14 if number <= 5 else 21)
        if number >= 6:
            assert admission['failed_audit_006_retained'] is True
        review_path = Path(admission['content_review_binding']);review = bound(review_path, refs)
        assert admission['review_binding'] == str(review_path)
        assert review['verdict'] == 'CLOSED_E9_SAVED_CONTENT_AUDIT_EXECUTION_AND_RECORDS_VERIFIED'
        assert review['source_revision'] == REV and review['cell'] == cell and review['findings'] == []
        assert review['content_audit_passed'] is True and review['mandatory_artifacts'] == 8
        assert review['full_a3'] is review['normal_loader_validation'] is review['qualification_complete'] is False
        review_refs = local(review, review_path, 'references.json')
        assert len(review_refs) == review['references'] and facts[str(review_path.parent/'references.json')]['sha256'] == review['references_sha256']
        audit_binding_path = Path(review['audit_binding']['path'])
        audit_binding = bound(audit_binding_path, refs);same_record(refs, review_refs, audit_binding_path)
        audit_path = audit_binding_path.with_name('audit.json');audit = bound(audit_path, refs);same_record(refs, review_refs, audit_path)
        assert facts[str(audit_path)]['sha256'] == review['audit_sha256'] == audit_binding['audit_sha256']
        assert audit_binding['auditor_sha256'] == review['auditor_sha256'] == AUDITORS[0 if number <= 5 else 1]
        assert audit_binding['completed'] is audit['completed'] is True and audit_binding['status'] == audit['status'] == 'PASS_SAVED_CONTENT'
        assert audit['source_revision'] == REV and audit['cell'] == cell and audit['mandatory_cells'] == ORDER
        if source_limits is None:source_limits = audit['source_attested_not_independently_saved']
        assert audit['source_attested_not_independently_saved'] == source_limits
        assert audit['qualification_complete'] is audit['normal_loader_validation'] is audit['full_a3'] is False
        assert audit['completed_cases'] == review['completed_cases'] == 176 and audit['children'] == review['children'] == 352
        assert audit['comparisons'] == review['comparisons'] == 528
        expanded = audit['call_intermediate_checks'];assert type(expanded) is int and 0 <= expanded <= 12
        assert audit['capture_files'] == review['capture_files'] == 8637+9*expanded
        assert audit['snapshots'] == review['snapshots'] == 880+expanded
        assert expanded == review['call_intermediate_checks'] == sum(x['call_intermediate_checks'] for x in audit['cases'])
        assert audit['cases'] == local(review, review_path, 'cases.json')
        assert len(audit['cases']) == 176
        identities = [(h,s,False) for h in range(87) for s in (0,1)]+[(0,s,True) for s in (0,1)]
        for index, (case, identity) in enumerate(zip(audit['cases'], identities)):
            assert set(case) == CASE_KEYS and (case['head'],case['state'],case['fault']) == identity
            assert case['status'] == 'PASS_SAVED_CONTENT' and case['comparisons'] == 3 and case['full_stack_bytes'] == 65536
            cases.append(dict(cell=cell, case_index=index, **case))
        if source_files is None:source_files = audit['source_files']
        assert audit['source_files'] == source_files and len(source_files) == 1839
        assert sha(json.dumps(source_files, sort_keys=True, separators=(',',':')).encode()) == audit['source_files_sha256']
        hist = audit['recorded_prior_cells'];assert hist == admission_objects
        admission_objects.append(admission)
        ob = audit['recorded_obligations'];assert ob['core_null'] == dict(denominator=704,record=None,status='UNRUN')
        assert ob['recording_pairs'] == dict(denominator=2112,record=None,status='UNRUN') and ob['E9_null']['denominator'] == 1408
        assert ob['E9_null']['status'] == ('UNRUN' if number == 1 else 'PARTIAL')
        assert ob['original']['denominator'] == 16 and ob['original']['status'] == 'CLOSED_REVIEWED'
        assert ob['ordinary']['denominator'] == 192 and ob['ordinary']['status'] == 'FAILED'
        assert ob['production']['denominator'] == 74 and ob['production']['status'] == 'FAILED'
        obligations.append(dict(cell=cell, recorded=normalize(ob)))
        ordinary = audit['recorded_ordinary_status'];production = audit['recorded_production_status']
        oc = {s:sum(x['status']==s for x in ordinary['cases']) for s in ('PASS_ORDINARY_OUTPUT_AND_JOURNAL','FAILED','UNRUN')}
        pc = {s:sum(x['status']==s for x in production['stages']) for s in ('PASS','FAILED','UNRUN')}
        assert oc == {'PASS_ORDINARY_OUTPUT_AND_JOURNAL':160,'FAILED':0,'UNRUN':32} and len(ordinary['cases']) == 192
        assert pc == {'PASS':62,'FAILED':12,'UNRUN':0} and len(production['stages']) == 74
        assert ordinary['summary']['successful'] is production['summary']['successful'] is False
        current_upstream = dict(ordinary=ordinary, production=production)
        if upstream is None:upstream = current_upstream
        assert upstream == current_upstream
        raw = Path(admission['summary']).parent
        summary, results, hardware = (bound(raw/n, refs) for n in ('summary.json','results.json','hardware.json'))
        assert summary == audit['recorded_runner_summary'] and results == audit['recorded_runner_results']
        assert summary['revision'] == REV and summary['recipe_sha256'] == RUNNER and summary['fatal'] is None
        assert summary['cases'] == 176 and summary['planned_children'] == 352 and summary['planned_comparisons'] == 528
        assert hardware['host_label'] == HARDWARE and hardware['architecture'] == 'x86_64'
        assert [x['name'] for x in results] == ['verify','replay'] and all(x['exit']==0 and x['strict_closure'] is True for x in results)
        launch = Path(admission['parent_observation']).parent
        caller, closed = (bound(launch/n, refs) for n in ('command.json','closed.json'))
        assert caller['recipe_sha256'] == RUNNER and caller['affinity'] == [0,1,2,3]
        assert closed['exit'] == 0 and closed['parent_wait_returned'] is True
        label = 'e9-pair-run' if number == 1 else 'e9-pair-run-%03d' % number
        ns = namespace(label, refs, 0);context = dict(command=caller,parent=closed,namespace=ns)
        original_contexts.append(context)
        commands.append(dict(ordinal=len(commands)+1,cell=cell,kind='runner',status='CLOSED_COMMAND_CAPTURE_SCHEMA',exit=0,
                             operational_seconds=closed['operational_seconds'],parent_seconds=ns['closed']['operational_seconds'],
                             cpu_seconds_measured=None,cpu_limit=None,wall_limit=None,file_limit=None,script_sha256=RUNNER,subject_sha256=RUNNER,
                             helper_sha256=None,stdout_sha256=closed['stdout_sha256'],stderr_sha256=closed['stderr_sha256'],context=normalize(context)))
        for result in results:
            stage = result['name'];command_row(cell,stage,raw/stage,refs,result['status'],0,
                script_sha=source_files['tools/elf-rewrite/e9-null-witness.py']['sha256'] if stage=='verify' else None)
        audit_dir = epoch/('e9-audit-launch-v2' if number==1 else 'e9-audit-launch-%03d-v%d' % (number,1 if number<=5 else 2))/'audit'
        audit_label = 'e9-content-audit-v2' if number==1 else 'e9-content-audit-%03d%s' % (number,'' if number<=5 else '-v2')
        command_row(cell,'audit-pass',audit_dir,refs,'PASS_SAVED_CONTENT',0,namespace(audit_label,refs,0),review['auditor_sha256'])
        cells.append(dict(ordinal=number,cell=cell,status=admission['status'],cases=176,children=352,comparisons=528,
            normal_cases=174,fault_cases=2,heads=87,capture_files=audit['capture_files'],snapshots=audit['snapshots'],
            call_intermediate_checks=expanded,generated_page_bytes=audit['generated_page_bytes'],candidate_sha256=audit['candidate_sha256'],
            witness_sha256=audit['witness_sha256'],runner_sha256=RUNNER,auditor_sha256=review['auditor_sha256'],
            admission_sha256=facts[str(ap)]['sha256'],content_review_sha256=facts[str(review_path)]['sha256'],audit_sha256=facts[str(audit_path)]['sha256']))
        for path in set(facts)-before_paths:
            if path in refs and path in review_refs:
                same_record(refs,review_refs,path)
    failures = []
    for item, ordinal in zip(spec['failures'], (1,6)):
        path = Path(item['path']);review = metadata(path,item)
        assert path == epoch/('e9-audit-failure-review-v1' if ordinal==1 else 'e9-audit-failure-review-006-v1')/'binding.json'
        assert review['verdict'] == 'CLOSED_FAILED_E9_CONTENT_AUDIT_RECORDS_VERIFIED' and review['findings'] == []
        assert review['revision'] == REV and review['cell'] == ORDER[ordinal-1]
        assert review['audit_exit'] == -9 and review['audit_failed'] is True and review['content_pending'] is True
        assert review['content_audit_passed'] is review['signal_origin_established'] is review['qualification_complete'] is False
        refs = local(review,path,'references.json');assert len(refs) == review['reference_files']
        d = epoch/('e9-audit-launch-v1' if ordinal==1 else 'e9-audit-launch-006-v1')/'audit'
        label = 'e9-content-audit' if ordinal==1 else 'e9-content-audit-006'
        command_row(ORDER[ordinal-1],'audit-failed',d,refs,'FAILED_SIGNAL_9_ORIGIN_UNPROVEN',-9,namespace(label,refs,1))
        assert commands[-1]['operational_seconds'] == review['audit_elapsed_seconds']
        if 'auditor_sha256' in review:
            assert commands[-1]['script_sha256'] == review['auditor_sha256']
        assert commands[-1]['script_sha256'] == ('3d69c425fee567dace19e72fc1cce3e65bc41ef2b8725ce74ed7b10b4c9e8008' if ordinal==1 else AUDITORS[0])
        failures.append(dict(cell=ORDER[ordinal-1],attempt='initial-audit',exit=-9,status='FAILED',
            operational_seconds=review['audit_elapsed_seconds'],signal_origin_established=False,
            content_result=None,review_sha256=facts[str(path)]['sha256']))
    assert len(cells)==8 and len(cases)==1408 and len(commands)==34 and len(failures)==2
    assert sum(x['comparisons'] for x in cases)==4224 and sum(x['children'] for x in cells)==2816
    summary = dict(schema=1,tested_revision=REV,hardware=HARDWARE,collector_sha256=sha(self_bytes),
        reporter_revision=None,reporter_revision_scope='standalone reporting script identified by its exact SHA; no tested revision transfer',
        input_sha256=args.inputs_sha256,status='ALL_8_CONTROLLED_E9_NULL_CELLS_CONTENT_REVIEWED',
        mandatory_cells=8,completed_cells=8,cases=1408,children=2816,comparisons=4224,
        normal_cases=1392,fault_cases=16,failed_audit_attempts=2,operation_rows=34,
        captures=sum(x['capture_files'] for x in cells),snapshots=sum(x['snapshots'] for x in cells),
        call_intermediate_checks=sum(x['call_intermediate_checks'] for x in cells),
        ordinary=dict(planned=192,passed=160,failed=0,unrun=32,successful=False),
        production=dict(planned=74,passed=62,failed=12,unrun=0,successful=False),
        original_observations=dict(denominator=16,status='CLOSED_REVIEWED'),
        core_null=dict(denominator=704,status='UNRUN'),recording_pairs=dict(denominator=2112,status='UNRUN'),
        full_a3=False,normal_loader_validation=False,qualification_complete=False,
        source_files=1839,source_files_sha256=sha(json.dumps(source_files,sort_keys=True,separators=(',',':')).encode()),
        operational_timings_not_performance=True,product_capture_cache_reads=0,
        source_attested_limits=source_limits,
        recorded_obligations=obligations,
        validation_reproducer='Not supplied by this reporting script; private runner, auditors, input assembly and runtime admission are separate.')
    public = {'summary.json':encode(summary),'cells.json':encode(cells),'cases.json':encode(cases),
              'commands.json':encode(commands),'failed-audits.json':encode(failures),'source-files.json':encode(source_files)}
    public['cells.csv']=csv_bytes(cells,list(cells[0]))
    public['cases.csv']=csv_bytes(cases,list(cases[0]))
    public['commands.csv']=csv_bytes(commands,[k for k in commands[0] if k!='context'])
    public['failed-audits.csv']=csv_bytes(failures,list(failures[0]))
    public['files.json']=encode(normalize(facts))
    forbidden = spec['privacy_literals'];assert isinstance(forbidden,list) and all(isinstance(x,str) and x for x in forbidden)
    for data in public.values():
        text=data.decode();assert '/home/' not in text and all(x not in text for x in forbidden)
        assert not re.search(r'\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|local|internal)\b',text)
    out.mkdir(mode=0o700);(out/'public').mkdir();(out/'private').mkdir(mode=0o700)
    for name,data in public.items():(out/'public'/name).write_bytes(data)
    (out/'private/roles.json').write_bytes(encode(roles))
    (out/'private/command-inverses.json').write_bytes(encode(original_contexts))
    (out/'private/records.json').write_bytes(encode(facts))
    result=dict(completed=True,scope='reporting only; no validation execution',public={n:dict(sha256=sha(b),bytes=len(b)) for n,b in public.items()},
                input_sha256=args.inputs_sha256,collector_sha256=sha(self_bytes),records=len(facts),commands=34,cells=8,cases=1408)
    (out/'collection.json').write_bytes(encode(result));print(encode(result).decode(),end='')


if __name__ == '__main__':
    main()
