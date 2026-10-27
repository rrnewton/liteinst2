#!/usr/bin/python3
"""Project only the stopped 8bb heap-core cohort and its closed prerequisites."""
import argparse, csv, hashlib, io, json, re, sys
from pathlib import Path
REV = '8bbf302e25d3af99dcba0adf465a691204d2ee0c'
AUDITOR = '48fe701eae2574eb84bdd0c575ca4af66cd50ddc07e9cd912bb26f9fe068225d'
RUNNER = '587888965a9729978ed3df9f8f5c9325cb92af64fe502c14ae8ac1e203653486'
CELLS = ['null-heap-write-unstripped', 'null-heap-write-stripped']
HISTORY = {'core-null-audit-failure-001-v1.json': '26c69d67bffb8f14b5f9928e57bce6f7d5b5d95ca75e30b85bb95f0bd60079c9', 'core-null-audit-failure-001-v2.json': 'e2f9a306af777803d543be24cf42fb9cfdfaee04977cf7d97b65d32d900450b0', 'core-null-assembly-failure-002-v1.json': 'd84114978078dc2a9d8e8b751385b0d9e5eec1d6c7a809cacf238d33f0e8c6aa', 'core-null-assembly-failure-003-v1.json': '5e33776bbde7f74b54e971d5ee79161285f7fa25faf52d2195e7932ac4b766a0'}
sha = lambda b: hashlib.sha256(b).hexdigest()

def unique(pairs):
    out = {}
    for k, v in pairs:
        assert k not in out
        out[k] = v
    return out

def main():
    if sys.flags.optimize: raise SystemExit('Assertions must be enabled')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--repo', type=Path, required=True); ap.add_argument('--inputs', type=Path, required=True)
    ap.add_argument('--inputs-sha256', required=True); ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args(); repo = a.repo.resolve(strict=True); seen = {}; inherited = {}; history_paths = set()
    def load(d):
        assert d.keys() == {'path', 'sha256', 'bytes'} and type(d['bytes']) is int and 0 <= d['bytes'] <= 128 * 1048576
        assert re.fullmatch('[0-9a-f]{64}', d['sha256']); p = Path(d['path'])
        assert p.is_absolute() and p.is_relative_to(repo / 'ignored') and p.suffix == '.json' and '/captures/' not in str(p) and p.resolve(strict=True) == p
        with p.open('rb') as f: b = f.read(d['bytes'] + 1)
        assert len(b) == d['bytes'] and sha(b) == d['sha256'] and (str(p) not in seen or seen[str(p)] == d)
        seen[str(p)] = d
        return json.loads(b, object_pairs_hook=unique, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    def mapped(path, refs):
        row = refs[path]; assert set(row) == {'sha256', 'bytes', 'stat'} and len(row['stat']) == 6 and row['stat'][3] == row['bytes']
        return load(dict(path=path, sha256=row['sha256'], bytes=row['bytes']))
    with a.inputs.open('rb') as f: ib = f.read(1048577)
    assert sha(ib) == a.inputs_sha256 and len(ib) <= 1048576
    inp = json.loads(ib, object_pairs_hook=unique)
    assert inp.keys() == {'schema', 'source_revision', 'cells', 'history', 'ordinary'} and type(inp['schema']) is int and inp['schema'] == 1 and inp['source_revision'] == REV
    assert len(inp['cells']) in (1, 2) and [r['cell'] for r in inp['cells']] == CELLS[:len(inp['cells'])]
    rows, receipts = [], []
    for item in inp['cells']:
        assert item.keys() == {'cell', 'admission', 'references', 'audit_receipt'}
        cell = item['cell']; ad = load(item['admission']); refs = load(item['references']); assert mapped(item['admission']['path'], refs) == ad
        for p, d in refs.items():
            assert p not in inherited or inherited[p] == d
            inherited[p] = d
        assert ad['source_revision'] == REV and ad['cell'] == cell and ad['build_profile'] == 'dev-debug0-v1'
        assert ad['authority'] == 'CALLER_REVIEWED_COMPLETE_CORE_PAIR_CELL' and ad['scope'] == 'closed-complete-176-case-content-review'
        assert ad['status'] == 'PASS_CONTENT_REVIEWED' and ad['content_audit_passed'] is ad['parent_closed_reaped'] is True and 'recording_profile' not in ad
        assert ad['verifier_capability'] == 'bounded-journal-v1' and all(ad[k] is False for k in ('full_a3', 'normal_loader_validation', 'qualification_complete'))
        summary = mapped(ad['summary'], refs); review = mapped(ad['content_review_binding'], refs)
        assert summary['revision'] == review['source_revision'] == REV and summary['cell'] == review['cell'] == cell
        assert summary['recipe_sha256'] == RUNNER and summary['command_capture_schema_complete'] is True and summary['fatal'] is None and summary['selected_owners_unchanged'] is True
        assert (summary['cases'], summary['heads'], summary['planned_children'], summary['planned_comparisons'], summary['capture_files']) == (176, 87, 352, 528, 8636)
        assert review['findings'] == [] and review['content_audit_passed'] is True and review['auditor_sha256'] == AUDITOR
        audit = mapped(review['audit_binding'], refs); report_path = str(Path(review['audit_binding']).with_name('audit.json')); report = mapped(report_path, refs)
        assert audit['auditor_sha256'] == AUDITOR and audit['audit_sha256'] == refs[report_path]['sha256'] == review['audit_sha256']
        assert audit['inputs_sha256'] == review['inputs_sha256'] and audit['read_inputs_sha256'] == review['read_inputs_sha256']
        assert all(re.fullmatch('[0-9a-f]{64}', audit[k]) for k in ('inputs_sha256', 'read_inputs_sha256'))
        assert audit['completed'] is report['completed'] is True and audit['status'] == report['status'] == 'PASS_SAVED_CONTENT'
        assert report['source_revision'] == REV and report['cell'] == cell and report['completed_cases'] == 176 and report['comparisons'] == 528 and report['expected_capture_files'] == 8636
        assert len(report['cases']) == 176 and all(c['status'] == 'PASS_SAVED_CONTENT' and c['comparisons'] == 3 for c in report['cases'])
        assert all(report[k] is False for k in ('full_a3', 'normal_loader_validation', 'qualification_complete'))
        for p in (ad['parent_observation'], review['audit_parent_observation']):
            parent = mapped(p, refs); assert parent['exit'] == 0 and parent['parent_wait_returned'] is True
        rp = item['audit_receipt']['path']; receipt = load(item['audit_receipt']); assert mapped(rp, refs) == receipt and rp in ad['evidence_files']
        qp = str(Path(rp).with_name('request.json')); request = mapped(qp, refs)
        assert receipt['request_sha256'] == refs[qp]['sha256'] and receipt['exit'] == 0 and receipt['absence_proof'] == 'ECHILD'
        assert receipt['cleanup_events'] == receipt['unexpected_descendants'] == [] and receipt['cleanup_error'] is receipt['aborted'] is None and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
        assert (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == (60, 90, 67108864)
        argv = request['argv']; assert argv[:2] == ['/usr/bin/python3.9', '-B'] and refs[argv[2]]['sha256'] == AUDITOR
        assert argv[3] == '--inputs' and argv[5:7] == ['--inputs-sha256', audit['inputs_sha256']]
        history_paths.update(ad['history_records'])
        rows.append(dict(cohort='core_null', cell=cell, status='PASS_CONTENT_REVIEWED', unit='native_pairs', count=176, children=352, comparisons=528, capture_files=8636))
        receipts.append(dict(cell=cell, admission_sha256=item['admission']['sha256'], reference_map_sha256=item['references']['sha256'], summary_sha256=refs[ad['summary']]['sha256'], review_sha256=refs[ad['content_review_binding']]['sha256'], audit_sha256=audit['audit_sha256'], read_inputs_sha256=audit['read_inputs_sha256'], strict_receipt_sha256=item['audit_receipt']['sha256'], native_parent_sha256=refs[ad['parent_observation']]['sha256'], audit_parent_sha256=refs[review['audit_parent_observation']]['sha256']))
    failed, names = [], set()
    for d in inp['history']:
        name = Path(d['path']).name; assert name not in names and re.fullmatch('[a-z0-9-]+-failure-[a-z0-9-]+\.json', name); names.add(name)
        f = load(d); assert f['source_revision'] == REV and f['cell_admitted'] is False and f['cell'] in CELLS + ['null-jump-site-unstripped', 'null-jump-site-stripped']
        assert f['status'] in ('FAILED_AUDIT_NO_VERDICT', 'CONTENT_FAILURE', 'FAILED_PRELAUNCH') and type(f['exit']) is int and f['exit'] != 0
        if name in HISTORY: assert d['sha256'] == HISTORY[name]
        if d['path'] in inherited: assert mapped(d['path'], inherited) == f
        assert all(f.get(k) is None or type(f[k]) is int and 0 <= f[k] <= limit for k, limit in [('completed_cases', 176), ('comparisons', 528)])
        if f['exit'] == -9: assert f['signal_origin'] == 'UNPROVEN'
        failed.append(dict(record_role='failed-attempt-'+str(len(failed)+1), sha256=d['sha256'], status=f['status'], exit=f['exit'], completed_cases=f.get('completed_cases'), comparisons=f.get('comparisons'), signal_origin='UNPROVEN' if f['exit'] == -9 else None))
    assert set(HISTORY) <= names and {Path(p).name for p in history_paths if re.fullmatch('[a-z0-9-]+-failure-[a-z0-9-]+\.json', Path(p).name)} <= names
    op = inp['ordinary']; assert op.keys() == {'admission', 'references'}; od = load(op['admission']); om = load(op['references']); assert mapped(op['admission']['path'], om) == od
    assert od['source_revision'] == REV and od['build_profile'] == 'dev-debug0-v1' and od['authority'] == 'CALLER_ADMITTED_COMMON_ORDINARY_CONTENT' and od['scope'] == 'closed-192-case-output-and-journal-records'
    assert od['successful'] is od['ordinary_cohort_complete'] is od['parent_closed_reaped'] is True and od['cases'] == dict(planned=192, attempted=192, passed=192, failed=0, unrun=0)
    ov = mapped(od['review_binding'], om); po = mapped(od['parent_observation'], om); assert ov['findings'] == [] and ov['successful'] is True and ov['tested_revision'] == REV and po['exit'] == 0 and po['parent_wait_returned'] is True
    assert od['prior_partial_cases'] == dict(planned=192, attempted=160, passed=160, failed=0, unrun=32) and od['prior_failed_statuses'] == {'FAILED': 1, 'PASS_ORDINARY_OUTPUT_AND_JOURNAL': 14, 'UNRUN': 177}
    assert od['production_history'] == dict(PASS=74, FAILED=0, UNRUN=0, successful=True)
    for cohort, unit, count in [('ordinary', 'ordinary_cases', 192), ('production', 'production_stages', 74)]: rows.append(dict(cohort=cohort, cell='', status='PASS', unit=unit, count=count, children='', comparisons='', capture_files=''))
    n = len(receipts)
    public = dict(schema=1, status='PARTIAL_STOPPED_8BB_COHORT', source_revision=REV, build_profile='dev-debug0-v1', hardware='AMD EPYC Zen 5 dev host', hardware_authority='Same-host confirmation; not sampled by this generator', admitted_core_cells=n, admitted_core_pairs=176*n, admitted_children=352*n, admitted_comparisons=528*n, core_null=dict(denominator=704, completed_pairs=176*n, status='PARTIAL'), recording_pairs=dict(denominator=2112, completed_pairs=0, status='UNRUN'), E9_null=dict(denominator=1408, status='UNRUN_CURRENT_EPOCH'), ordinary=od['cases'], production=od['production_history'], ordinary_admission_sha256=op['admission']['sha256'], historical_ordinary_partial=od['prior_partial_cases'], historical_ordinary_failed=od['prior_failed_statuses'], failed_attempts=failed, cells=receipts, auditor_sha256=AUDITOR, runner_sha256=RUNNER, generator_sha256=sha(Path(__file__).read_bytes()), input_manifest_sha256=a.inputs_sha256, generator_executed_native=False, generator_opened_capture_bodies=False, generator_refreshed_external_owners=False, performance_measurement=False, full_a3=False, normal_loader_validation=False, qualification_complete=False, scope='Stopped historical validation cohort. Report regeneration is not native reproduction. Fresh public native-V2 recipes require their own new tested source pins and use a different metadata route without historical custody authority.')
    out = a.out.absolute(); assert out.is_relative_to(repo / 'ignored') and out.parent.resolve(strict=True) == out.parent and not out.exists() and not out.is_symlink()
    text = json.dumps(public, sort_keys=True, indent=2, allow_nan=False)+'\n'; table = io.StringIO(); writer = csv.DictWriter(table, fieldnames=list(rows[0]), lineterminator='\n'); writer.writeheader(); writer.writerows(rows)
    assert '/home/' not in text+table.getvalue() and '://' not in text and '@' not in text
    out.mkdir(mode=0o700); (out/'receipt.json').write_text(text); (out/'numbers.csv').write_text(table.getvalue())

if __name__ == '__main__': main()
