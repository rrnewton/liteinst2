#!/usr/bin/env python3
"""Exact leaf coordinates and a finite, non-executing owner-receipt catalog."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import subprocess

if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CATALOG_SOURCES = (
    'evaluation/ordinary-selected-session/accuracy_coordinates.py',
    'evaluation/ordinary-selected-session/accuracy_produce.py',
    'evaluation/ordinary-selected-session/accuracy_functional.py',
    'evaluation/ordinary-selected-session/accuracy_functional_owner.py',
    'evaluation/ordinary-module-session/reproduce.py',
    'evaluation/ordinary-accuracy/truth.py',
)
PROFILE = 'selected-accuracy-coordinate-functional-v1'
FIELDS = ('master', 'population-phase', 'trial', 'workload', 'k', 'period-ms', 'epoch-phase')
PHASES = ('calibration', 'holdout', 'comparison')
WORKLOADS = ('short', 'long', 'alternating', 'late_expensive', 'blocks', 'varied')
KS, PERIODS, EPOCH_PHASES = (1, 10, 100, 1000), (1, 10, 100), ('random', 'locked')
EPOCHS, RECORDS, CELLS = 520, 2048, 43200
DISPATCH_BYTES = 2048
CATALOG_BYTES = CELLS * (DISPATCH_BYTES + 1) + 3
CONTROLS = (
    'test_exact_coordinate_domains_and_canonical_cli',
    'test_all_43200_keys_and_hash_bind_every_axis',
    'test_complete_materials_and_derived_policy_for_every_workload',
    'test_coordinate_plan_recomputes_materials_and_refuses_foreign_cell',
    'test_owner_options_keep_all_old_modes_closed',
    'test_new_argv_ready_and_target_derive_from_coordinate',
    'test_geometry_rejects_other_cell_and_old_acceptance',
    'test_input_write_limit_is_derived_only_for_new_profile',
    'test_absolute_deadline_and_old_caps_remain_exact',
    'test_catalog_keeps_unrun_unknown_failed_and_rejects_duplicates',
    'test_catalog_requires_owner_first_and_complete_closed_population',
    'test_cancelled_or_partial_population_cannot_be_closed_success',
    'test_new_controls_are_mandatory_in_preparation_replay',
    'test_catalog_authenticates_all_code_before_any_import',
    'test_catalog_real_closed_success_binds_coordinate_policy_and_joined',
    'test_old_summaries_remain_byte_identical',
)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')


def checked(value):
    assert type(value) is dict and set(value) == set(FIELDS)
    assert type(value['master']) is str and re.fullmatch('[0-9a-f]{64}', value['master'])
    assert type(value['population-phase']) is str and value['population-phase'] in PHASES
    assert type(value['workload']) is str and value['workload'] in WORKLOADS
    assert type(value['epoch-phase']) is str and value['epoch-phase'] in EPOCH_PHASES
    assert type(value['trial']) is int and 1 <= value['trial'] <= 100
    assert type(value['k']) is int and value['k'] in KS
    assert type(value['period-ms']) is int and value['period-ms'] in PERIODS
    return dict(value)


def options(value):
    assert type(value) is dict and set(value) == set(FIELDS)
    out = dict(value)
    for key in ('trial', 'k', 'period-ms'):
        assert type(out[key]) is str and re.fullmatch('[1-9][0-9]*', out[key])
        out[key] = int(out[key])
    return checked(out)


def authority(truth, coordinate):
    c = checked(coordinate)
    assert (truth.PHASES, truth.WORKLOADS, truth.TRIALS, truth.RECORDS) == (PHASES, WORKLOADS, 100, RECORDS)
    files, manifest = truth.artifacts(c['master'], c['population-phase'], c['trial'], c['workload'])
    choices = [p for p in manifest['policies'] if
        (p['k'], p['period_ms'], p['phase']) == (c['k'], c['period-ms'], c['epoch-phase'])]
    assert len(choices) == 1 and len(manifest['policies']) == 24
    policy = dict(choices[0], epochs=EPOCHS)
    assert policy['phase'] != 'locked' or policy['delay_ns'] == 0
    assert 0 <= policy['delay_ns'] < c['period-ms'] * 1000000
    assert len(files['input.csv'].splitlines()) == RECORDS
    assert 2 * RECORDS <= len(files['input.csv']) <= 65 * RECORDS
    return dict(files, **{'manifest.json': truth.canonical(manifest)}), manifest, policy


def name(coordinate):
    c = checked(coordinate)
    return '{}-trial{}-{}-k{}-period{}-e520-prepared-phase-{}'.format(
        c['population-phase'], c['trial'], c['workload'], c['k'], c['period-ms'], c['epoch-phase'])


def keys(master):
    result = [checked(dict(zip(FIELDS, (master, phase, trial, workload, k, period, epoch_phase))))
        for phase in PHASES for trial in range(1, 101) for workload in WORKLOADS
        for k in KS for period in PERIODS for epoch_phase in EPOCH_PHASES]
    assert len(result) == CELLS and len({canonical(c) for c in result}) == CELLS
    return result


def catalog(master):
    population = keys(master)
    return dict(schema='selected-accuracy-coordinate-catalog-v1', master=master, cells=CELLS,
        keyset_sha256=hashlib.sha256(b''.join(map(canonical, population))).hexdigest(),
        order=list(FIELDS[1:]), phases=list(PHASES), trials=[1, 100], workloads=list(WORKLOADS),
        k=list(KS), period_ms=list(PERIODS), epoch_phase=list(EPOCH_PHASES),
        epochs=EPOCHS, records=RECORDS, profile=PROFILE, attempts_per_cell=1)


def collect(plan, dispatches, observe):
    """Every supplied dispatch is an attempt; unknown closure is never UNRUN.

    observe authenticates one owner/result pair, owner first. No process is run,
    no failed attempt is replaced, and catalog completion is only structural.
    """
    assert type(plan) is dict and plan == catalog(plan['master'])
    assert type(dispatches) is list and len(dispatches) <= CELLS
    universe = {canonical(c): c for c in keys(plan['master'])}
    seen, rows = set(), []
    counts = dict(UNRUN=CELLS, UNKNOWN=0, FAILED=0, STRUCTURAL_PASS=0)
    for event in dispatches:
        assert type(event) is dict and set(event) == {'coordinate', 'attempt', 'owner', 'result'}
        assert len(canonical(event)) <= DISPATCH_BYTES
        key = canonical(checked(event['coordinate']))
        assert key in universe and key not in seen and type(event['attempt']) is int and event['attempt'] == 1
        seen.add(key)
        status = 'UNKNOWN' if event['owner'] is None else observe(event)
        assert status in ('UNKNOWN', 'FAILED', 'STRUCTURAL_PASS')
        counts['UNRUN'] -= 1
        counts[status] += 1
        rows.append(dict(coordinate=event['coordinate'], attempt=1, status=status,
            owner=event['owner'], result=event['result']))
    assert sum(counts.values()) == CELLS
    closed = counts['UNRUN'] == counts['UNKNOWN'] == 0
    return dict(catalog=plan, counts=counts, dispatches=rows,
        structural_dispatch_coverage_complete=closed,
        status='ALL_STRUCTURAL_REPORTS_CLOSED' if closed else 'INCOMPLETE',
        all_reported_structural_pass=closed and counts['FAILED'] == 0,
        phase_status='UNRESOLVED', hardware_status='UNRESOLVED', accuracy_qualified=False,
        scope='Owner-reported structural outcomes only; no A5, phase, metric or performance qualification.')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def catalog_modules(revision):
    # This finite import closure includes owner.commands()/summary()'s helper.
    assert type(revision) is str and re.fullmatch('[0-9a-f]{40}', revision)
    for name in CATALOG_SOURCES:
        path = ROOT/name
        assert path.is_file() and not path.is_symlink() and path.stat().st_size <= 1048576
        assert path.read_bytes() == subprocess.check_output(
            ['/usr/bin/git','-C',ROOT,'show',revision+':'+name], timeout=15)
    return tuple(load('_coordinate_catalog_'+str(i), ROOT/name)
                 for i,name in enumerate(CATALOG_SOURCES[1:]))


def reported_population(joined, coordinate, truth):
    cell = checked(coordinate)
    files, expected_manifest, policy = authority(truth, cell)
    assert canonical(joined['manifest']) == canonical(expected_manifest)
    assert canonical(joined['policy']) == canonical(policy)
    manifest = joined['manifest']
    assert (manifest['master'],manifest['phase'],manifest['trial'],manifest['workload']) == (
        cell['master'],cell['population-phase'],cell['trial'],cell['workload'])
    assert joined['status'] == 'STRUCTURALLY_COMPLETE' and len(joined['calls']) == RECORDS
    assert joined['totals']['calls'] == RECORDS
    assert joined['hardware_status'] == joined['requested_phase_status'] == 'UNRESOLVED'
    for ordinal, row in enumerate(joined['calls'],1):
        assert (row['original']['record'],row['call']['record_id'],row['result']['record_id']) == (ordinal,ordinal,ordinal)
        assert row['call']['index'] == 0
    return files, policy


def closed_report(event, producer, functional, owner, normal_closed, *, truth, revision):
    """Finite projection of existing closed receipts, not an independent rerun."""
    def pinned(ref, cap):
        assert type(ref) is dict and set(ref) == {'path', 'bytes', 'sha256'}
        assert type(ref['bytes']) is int and 0 < ref['bytes'] <= cap
        assert type(ref['sha256']) is str and re.fullmatch('[0-9a-f]{64}', ref['sha256'])
        raw = producer.read(Path(ref['path']), cap)
        assert len(raw) == ref['bytes'] and producer.sha(raw) == ref['sha256']
        return json.loads(raw)
    outer = pinned(event['owner'], 1048576)  # Never read a child before custody closes.
    if outer['closed'] is None:
        return 'UNKNOWN'
    try:
        normal_closed(outer['closed'])
    except (AssertionError, KeyError, TypeError):
        return 'UNKNOWN'
    if not (outer['source_unchanged'] is True and outer['log_archived'] is True):
        return 'UNKNOWN'
    assert outer['base'] == revision
    assert outer['attempts'] == 1 and outer['working_source_sha256'] == {}
    assert (outer['wall_limit_seconds'], outer['output_limit_bytes']) == (1200, 8 * 1048576)
    public = outer['public_owner']
    invocation = public['invocation']
    assert type(invocation) is list and len(invocation) >= 3 and invocation[1] == '-B' and (len(invocation)-3)%2 == 0
    words = invocation[3:]
    assert all(type(k) is str and k.startswith('--') for k in words[::2])
    opts = {k[2:]:v for k,v in zip(words[::2],words[1::2])}
    assert len(opts)*2 == len(words) and opts['phase'] == 'coordinate-functional'
    assert opts['owner'] == event['owner']['path'] and opts['revision'] == outer['base']
    assert options({k:opts[k] for k in FIELDS}) == checked(event['coordinate'])
    expected_invocation, command = owner.commands(opts,invocation[0],invocation[2])
    assert invocation == expected_invocation and command == outer['command']
    assert public['schema'] == owner.SCHEMA and public['phase'] == 'coordinate-functional'
    assert public['revision'] == outer['base'] and public['recipe'] == 'evaluation/ordinary-selected-session/accuracy_functional_owner.py'
    if event['result'] is None:
        return 'FAILED' if outer['closed']['exit_code'] == 1 else 'UNKNOWN'
    result = pinned(event['result'], 32 * 1048576)
    assert result['phase'] == 'coordinate-functional' and result['profile'] == PROFILE
    assert result['revision'] == outer['base'] and result['coordinate'] == checked(event['coordinate'])
    assert all(result[k] == v for k, v in functional.qualifications().items())
    if not (result.get('custody_closed') is result.get('retention_verified') is result.get('source_unchanged') is True):
        return 'UNKNOWN'
    assert opts == dict(result['arguments'], owner=event['owner']['path'])
    assert Path(event['result']['path']) == Path(opts['raw'])/'result.json'
    assert options({k: opts[k] for k in FIELDS}) == event['coordinate']
    source_path = Path(opts['raw'])/'sources-before.json'
    source_after = Path(opts['raw'])/'sources-after.json'
    assert result['retained'][str(source_path)] == result['retained'][str(source_after)]
    sources = pinned(dict(path=str(source_path),**result['retained'][str(source_path)]),16 * 1048576)
    assert pinned(dict(path=str(source_after),**result['retained'][str(source_after)]),16 * 1048576) == sources
    assert outer['public_owner'] == dict(schema=owner.SCHEMA, phase='coordinate-functional',
        revision=outer['base'], recipe='evaluation/ordinary-selected-session/accuracy_functional_owner.py',
        recipe_sha256=sources[str(HERE/'accuracy_functional_owner.py')]['sha256'], invocation=invocation)
    assert outer['command'] == command == result['invocation']
    assert result['cpus'] == outer['reserved_cpus'] and result['hardware'] == outer['hardware']
    log = producer.read(Path(event['owner']['path']).with_suffix('.log'), 8 * 1048576)
    assert producer.sha(log) == outer['closed']['private_log_sha256'] and json.loads(log) == functional.summary(result)
    row = result['functional']
    assert row['name'] == name(event['coordinate']) and row['records'] == RECORDS
    assert type(row['attempts']) is int and row['attempts'] in (0, 1)
    if result['status'] == 'FAILED':
        assert outer['closed']['exit_code'] == 1
        return 'FAILED'
    assert result['status'] == 'COORDINATE_FUNCTIONAL_STRUCTURAL_PASS' and outer['closed']['exit_code'] == 0
    assert row['status'] == 'PASS' and row['attempts'] == 1
    assert Path(row['joined']['path']) == Path(opts['raw'])/'joined.json'
    raw = producer.read(Path(row['joined']['path']), 24 * 1048576)
    assert producer.sha(raw) == row['joined']['sha256']
    joined = json.loads(raw)
    files, policy = reported_population(joined,event['coordinate'],truth)
    facts = result['facts']
    assert canonical(facts['coordinate']) == canonical(event['coordinate'])
    assert canonical(facts['policy']) == canonical(policy)
    assert facts['profile'] == PROFILE and facts['revision'] == result['revision']
    target = producer.prepared_target(policy)
    assert canonical(facts['prepared_phase']) == canonical(target)
    observed = joined['prepared_phase_observations']
    assert canonical({k:observed[k] for k in ('target_epoch','target_ns','original_end_ns')}) == canonical(
        dict(target_epoch=1,target_ns=target['target_ns'],original_end_ns=policy['period_ms']*1000000*EPOCHS))
    assert canonical(joined['phase_observations']['requested']) == canonical(
        dict(phase=policy['phase'],delay_ns=policy['delay_ns']))
    assert set(facts['materials']) == set(files)
    for material, data in files.items():
        assert canonical({k:facts['materials'][material][k] for k in ('bytes','sha256')}) == canonical(
            dict(bytes=len(data),sha256=producer.sha(data)))
    assert joined['totals'] == row['totals'] == row['result']['totals']
    assert row['result']['status'] == 'PASS' and row['producer_exit'] == 0
    assert row['result']['profile'] == PROFILE and row['result']['coordinate'] == event['coordinate']
    assert row['result']['revision'] == result['revision'] and row['result']['attempt'] == 1
    functional.delivery(row['result'], result['facts']['materials']['input.csv']['bytes'])
    return 'STRUCTURAL_PASS'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--master', required=True)
    parser.add_argument('--dispatches', type=Path)
    parser.add_argument('--revision', help='Exact Git source revision; required with dispatches.')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    plan = catalog(args.master)
    if args.dispatches is None:
        value = collect(plan, [], lambda event: None)
    else:
        producer, functional, owner, recipe, truth = catalog_modules(args.revision)
        raw = producer.read(args.dispatches, CATALOG_BYTES)
        dispatches = json.loads(raw)
        assert canonical(dispatches) == raw
        value = collect(plan, dispatches,
            lambda event: closed_report(event, producer, functional, owner, recipe.normal_closed,
                truth=truth,revision=args.revision))
    with args.output.open('xb') as stream:
        stream.write(canonical(value))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
