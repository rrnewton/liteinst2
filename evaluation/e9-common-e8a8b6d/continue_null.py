#!/usr/bin/env python3
"""Eight E9-null cells from one pinned, successfully closed native-v6 preparation."""
import argparse
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import types

BASE_SHA = '3ef4a5cd1a4c625c95aacc2d80adba750056ab686472a2508cf27a681dd72e78'
CELLS = ('null-heap-write-unstripped', 'null-heap-write-stripped', 'null-jump-site-unstripped', 'null-jump-site-stripped')
LANES = ('stock-algorithm', 'bootstrap-patched-reference')


def plan():
    native = [(lane, cell) for cell in CELLS for lane in LANES]
    stages = ['native-' + lane + '-' + cell + '-' + part for lane, cell in native for part in ('witness', 'replay')]
    assert len(native) == 8 and len(stages) == len(set(stages)) == 16
    return stages, native


def closed(row):
    assert set(row) == {'start_utc', 'exit_code', 'termination', 'seconds', 'private_log_sha256', 'cleanup_complete', 'reaped_descendants', 'child_discovery_strategy'}
    assert type(row['exit_code']) is int and row['exit_code'] == 0 and row['termination'] is None
    assert row['cleanup_complete'] is True and row['reaped_descendants'] == 0


def complete(capture, expanded):
    expected = dict(heads='87', normal_pairs='174', fault_pairs='2', children='352', comparisons='528',
        call_intermediate_checks=str(len(expanded)), snapshots=str(880 + len(expanded)), files=str(8637 + 9 * len(expanded)),
        recording_hooks='UNIMPLEMENTED_UNRUN', normal_loader_validation='false', qualification_complete='false')
    assert B.fields(B.read(capture / 'complete.tsv')[0], 'LI2COMMONE9PAIRS\t1') == expected
    for i in range(176):
        directory = capture / ('case-%03d' % i)
        pair = dict(case=str(i), comparisons='3', children='2', call_intermediate_checks=str(int(i in expanded)), normal_loader_validation='false', qualification_complete='false')
        assert B.fields(B.read(directory / 'pair.tsv')[0], 'LI2E9PAIR\t1') == pair
        child = B.fields(B.read(directory / 'candidate/complete.tsv')[0], 'LI2E9PAIRCHILD\t1')
        assert set(child) == {'case', 'steps', 'physical_completion', 'logical_completion', 'fault', 'comparisons', 'call_intermediate_checks', 'reaped_echild', 'qualification_complete'}
        assert child['case'] == str(i) and child['comparisons'] == '3' and child['reaped_echild'] == 'true'
        assert 0 < int(child['steps']) <= 20000 and child['qualification_complete'] == 'false'
        assert child['call_intermediate_checks'] == str(int(i in expanded))
    return dict(pairs=176, children=352, comparisons=528)


def prepare(c, args, prior_plan):
    prior = args.prior_raw
    assert prior.resolve(strict=True) == prior and prior.is_relative_to(c.repo / 'ignored')
    assert not c.raw.is_relative_to(prior) and not prior.is_relative_to(c.raw)
    assert args.prior_parent.resolve(strict=True) == args.prior_parent and args.prior_parent.is_relative_to(c.repo / 'ignored')
    c.aliases.update({str(prior): '$PRIOR_RAW', str(args.prior_parent): '$PRIOR_PARENT', str(Path(__file__).resolve()): '$CONTINUATION'})
    c.keep(Path(__file__).resolve()); c.keep(args.prior_parent)
    def held(path):
        c.keep(path)
        return B.read(path)[0]
    def saved(relative):
        return json.loads(held(prior / relative))
    assert B.sha(held(args.prior_parent)) == args.prior_parent_sha256; closed(json.loads(held(args.prior_parent)))
    assert B.sha(held(prior / 'public/receipt.json')) == args.prior_receipt_sha256
    receipt = saved('public/receipt.json')
    assert receipt['status'] == 'PASS' and receipt['revision'] == B.REVISION and receipt['script_sha256'] == BASE_SHA
    assert receipt['build_profile'] == 'dev-debug0-v1' and receipt['planning_profile'] == B.PROFILE and receipt['recording_profile'] == 'bounded-journal-v1'
    assert receipt['planned'] == dict(stages=357, original_observations=16, ordinary_cases=192, core_null_pairs=704, recording_pairs=2112, native_pairs=2816, native_children=5632, native_comparisons=8448)
    assert receipt['observed'] == dict(passed_stages=357, failed_stages=0, unrun_stages=0, ordinary_passes=192, ordinary_failed=0, ordinary_unrun=0, complete_native_cells=16, failed_native_cells=0, unrun_native_cells=0, complete_native_pairs=2816, complete_native_children=5632, live_rust_comparisons=8448)
    assert receipt['retention'] == dict(planned_cells=16, passed=16, failed=0, unrun=0, native_credit_added=False)
    assert receipt['source_tools_products_unchanged'] is True and receipt['configuration_observations_unchanged'] is True
    assert receipt['external_e9_sha256'] == c.p.PRODUCTS
    for name in ('source', 'tools', 'config'):
        assert saved(name + '-before.json') == saved(name + '-after.json')
    old_source = saved('source-before.json')
    assert old_source['revision'] == B.REVISION and old_source['files'] == c.before['files']
    assert receipt['source_files_sha256'] == B.sha(json.dumps(c.before['files'], sort_keys=True).encode())
    assert receipt['tool_sha256'] == {c.normalized(p): row['sha256'] for p, row in c.owners.items() if p not in (str(args.reproducer), str(c.tools_input))}
    content = lambda table: {p: {k: v for k, v in row.items() if k not in ('stat', 'lstat')} for p, row in table.items()}
    assert content(saved('config-before.json')) == content(c.configs)
    assert B.sha(held(prior / 'results.json')) == args.prior_results_sha256
    results = saved('results.json'); assert [r['stage'] for r in results] == prior_plan and all(r['status'] == 'PASS' for r in results)
    result = {r['stage']: r for r in results}
    def stage(name):
        d = prior / 'commands' / name
        for n in ('request.json', 'receipt.json', 'closed.json', 'helper.log', 'stdout.txt', 'stderr.txt'): held(d / n)
        request = B.js(d / 'request.json'); terminal = c.p.receipt(d, request); closed(B.js(d / 'closed.json'))
        assert terminal['exit'] == 0 and B.sha(held(d / 'request.json')) == result[name]['request_sha256'] and B.sha(held(d / 'receipt.json')) == result[name]['receipt_sha256']
        assert held(d / 'helper.log') == (json.dumps(dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)) + '\n').encode()
        assert B.sha(held(d / 'helper.log')) == B.js(d / 'closed.json')['private_log_sha256']
        return d, request
    assert set(receipt['product_sha256']) == {'elf-exec-oracle', 'liteinst-rewrite', 'common_sites', 'verify_common_core'}
    c.products = {n: prior / 'products' / n for n in receipt['product_sha256']}
    for n, path in c.products.items(): assert B.sha(held(path)) == receipt['product_sha256'][n] and B.read(path)[1]['stat'][2] & 0o111
    build, request = stage('build-native')
    messages = [json.loads(line) for line in held(build / 'stdout.txt').splitlines()]
    assert messages[-1] == dict(reason='build-finished', success=True)
    selected = B.selected_product(messages, 'elf-exec-oracle', 'bin', c.repo / 'tests/support/elf_exec_driver.rs', c.repo / 'Cargo.toml', c.b.DEBUG0_PROFILE)
    assert selected == c.repo / 'target/debug/elf-exec-oracle'  # Metadata comparison only; never open target.
    c.originals = {v: prior / 'originals' / v for v in B.ORIGINALS}; c.images = {v: held(p) for v, p in c.originals.items()}
    assert {v: B.sha(data) for v, data in c.images.items()} == B.ORIGINALS
    _, symbols, _ = c.p.original_pair(c.images['unstripped'], c.images['stripped'])
    c.target = prior / 'target.tsv'; assert held(c.target) == B.full_target(held(prior / 'target.txt'))
    for cell in CELLS:
        style, variant = cell[len('null-'):].rsplit('-', 1)
        directory = prior / 'inventories' / cell
        inv = c.p.inventory(directory, c.images[variant], symbols, style, 'null', lambda p: held(Path(p)))
        assert inv['data']['instructions.tsv'] == held(c.repo / 'tests/support/e9_common_seed.instructions.tsv') and len(c.p.tsv(inv['data']['instructions.tsv'])) == 87
        assert inv['data']['target.txt'] == held(prior / 'target.txt')
        inv['directory'] = directory; c.inventories[cell] = inv
        policy_path = prior / 'production' / cell / 'comparison-policy.json'
        policy = dict(schema=1, original_sha256=B.ORIGINALS[variant], selection_sha256=B.sha(inv['data']['selection.txt']), e9_revision=c.p.REFERENCE['reference_commit'], instrumentation='null', selection_style=style)
        assert json.loads(held(policy_path)) == policy
        for lane in LANES:
            prefix = cell + '-' + lane; lane_dir = prior / 'production' / cell / lane
            envelope_path = lane_dir / 'envelope.json'; envelope = json.loads(held(envelope_path)); candidate = lane_dir / 'candidate.elf'
            stock = lane == 'stock-algorithm'; e9 = c.tools['e9']
            roles = dict(original=c.originals[variant], selection=directory / 'selection.txt', policy=policy_path, candidate=candidate, frontend=Path(e9['stock_frontend' if stock else 'transport_frontend']), backend=Path(e9['stock_backend' if stock else 'abi_backend']), loader=Path(e9['stock_loader' if stock else 'abi_loader']), transport_frontend=Path(e9['transport_frontend']), helper=c.helper)
            for phase in ('transport', 'producer'):
                d, _ = stage(prefix + '-' + phase)
                for role, name in [('request', 'request.json'), ('receipt', 'receipt.json'), ('stdout', 'stdout.txt'), ('stderr', 'stderr.txt')]: roles[phase + '_' + role] = d / name
            assert len(roles) == 17 and envelope['files'] == {n: B.descriptor(p) for n, p in roles.items()}
            for path in roles.values(): held(path)
            assert envelope['schema'] == 1 and envelope['lane'] == lane and envelope['hook'] is None and all(envelope[k] == v for k, v in c.p.REFERENCE.items())
            d, request = stage(prefix + '-adapter')
            assert request['argv'] == [c.tools['python'], '-B', str(c.repo / 'tools/elf-rewrite/e9-sites.py'), str(envelope_path), str(lane_dir / 'inventory'), '--envelope-sha256', B.sha(held(envelope_path))]
            binding = json.loads(held(lane_dir / 'inventory/producer-binding.json'))
            assert binding['selected_sites'] == len(inv['sites']) and binding['candidate_sha256'] == B.sha(held(candidate)) and binding['site_inventory_sha256'] == B.sha(held(lane_dir / 'inventory/sites.tsv'))
            assert binding['qualification_complete'] is False and binding['architectural_equivalence_proved'] is False
            comparison = json.loads(held(lane_dir / 'comparison.json')); stage(prefix + '-compare')
            assert comparison['selected_sites'] == len(inv['sites']) and comparison['comparison_policy'] == policy and not comparison['lost_e9_trampoline_sites']
            assert comparison['qualification_complete'] is False and comparison['scope'] == 'STRUCTURAL_CANDIDATE_SITE_INVENTORY_ONLY'
            c.candidates[(cell, lane)] = candidate; c.envelopes[(cell, lane)] = envelope_path
    c.stable(source=True)
    B.write(c.raw / 'reused-inputs-before.json', c.product_owners)


def native(c):
    witness_reader = B.load(c.repo, 'tools/elf-rewrite/e9-null-witness.py')
    f = c.re.witness_result
    check_witness = types.FunctionType(f.__code__, dict(f.__globals__, WITNESS_SHA=B.SOURCE_PINS['tools/elf-rewrite/e9-null-witness.py']), f.__name__)
    assert f.__globals__['RECORDING'] is False  # Only replace the old activation's source pin, no predicate or body.
    for lane, cell in c.native_order:
        row = next(r for r in c.native_results if (r['cell'], r['lane']) == (cell, lane)); row['status'] = 'FAILED'
        variant = cell.rsplit('-', 1)[1]; directory = c.raw / 'native' / (cell + '-' + lane); directory.mkdir()
        instructions = c.inventories[cell]['directory'] / 'instructions.tsv'; envelope = c.envelopes[(cell, lane)]
        witness = directory / 'witness'; wi = directory / 'witness-inputs.json'; captures = directory / 'captures'
        B.write(wi, dict(schema=1, structural_envelope=B.descriptor(envelope), instructions=B.descriptor(instructions), target=B.descriptor(c.target))); c.keep(wi)
        prefix = 'native-' + lane + '-' + cell
        d = c.run(prefix + '-witness', [c.tools['python'], '-B', c.repo / 'tools/elf-rewrite/e9-null-witness.py', wi, witness, '--inputs-sha256', B.sha(B.read(wi)[0]), '--structural-reader', c.repo / 'tools/elf-rewrite/e9-sites.py'])
        expected_inputs = dict(inputs=str(wi), structural_reader=str(c.repo / 'tools/elf-rewrite/e9-sites.py'), witness_reader=str(c.repo / 'tools/elf-rewrite/e9-null-witness.py'), structural_envelope=str(envelope), instructions=str(instructions), target=str(c.target))
        expected_inputs.update({'producer/' + k: v['path'] for k, v in B.js(envelope)['files'].items()})
        report, expanded, g = check_witness(c.p, witness, expected_inputs, lane, c.images[variant], B.read(c.candidates[(cell, lane)])[0], c.inventories[cell]['data']['selection.txt'], witness_reader.native_projection, lambda p: B.read(Path(p))[0])
        assert expanded is not None and report['witness_complete'] is True
        assert B.read(d / 'stdout.txt')[0] == b'E9 null witnesses: 87 required heads; 176 required cases; COMPLETE_BYTE_WITNESSES\n' and not B.read(d / 'stderr.txt')[0]
        assert B.read(witness / 'sites.tsv')[0] == B.read(envelope.parent / 'inventory/sites.tsv')[0]
        for name in ('witness.json', 'native.tsv', 'sites.tsv', 'files.json'): c.keep(witness / name)
        expected = c.re.capture_names(expanded); w = sum(len(B.read(witness / n)[0]) for n in ('witness.json', 'native.tsv', 'sites.tsv', 'files.json'))
        payload = sum(len(B.read(p)[0]) for p in (c.originals[variant], instructions, c.target, c.candidates[(cell, lane)]))
        metadata = 16 * B.MIB + 9000 * (len(str(directory)) + 256) + 12 * (65536 + sum(len(B.read(p)[0]) for p in (wi, envelope)))
        disk = (880 + len(expanded)) * (254288 + 2287 + 65536 + B.MIB) + (529 + len(expanded)) * g + 2 * w + 64 * B.MIB + metadata + 512 * B.MIB
        B.write(directory / 'resource.json', c.capacity(disk, 2 * (payload + w + 4 * g + 32 * B.MIB + 237568)))
        d = c.run(prefix + '-replay', [c.products['elf-exec-oracle'], 'replay-common-e9', c.originals[variant], instructions, c.target, witness / 'witness.json', witness / 'native.tsv', captures], 'native')
        assert B.read(d / 'stdout.txt')[0] == f'E9 null pairs complete: heads=87 normal=174 faults=2 comparisons=528 call_intermediates={len(expanded)} files={len(expected)} qualification_complete=false\n'.encode() and not B.read(d / 'stderr.txt')[0]
        counts = complete(captures, expanded); actual = {}
        for root, dirs, files in os.walk(captures, followlinks=False):
            assert all(not (Path(root) / n).is_symlink() for n in dirs + files)
            for name in files:
                p = Path(root) / name; actual[str(p.relative_to(captures))] = B.read(p)[1]
        assert set(actual) == set(expected) and B.read(captures / 'capture-inventory.tsv')[0] == ('\n'.join(expected) + '\n').encode()
        sizes = dict(regs=216, xstate=2287, data=4096, stack=32888, **{'stack-owned': 65536, 'loads': 151552, 'generated': g})
        for name, info in actual.items():
            suffix = name.rsplit('.', 1)[-1]
            if suffix in sizes: assert info['bytes'] == sizes[suffix]
            elif suffix == 'maps': assert 0 < info['bytes'] <= B.MIB
            elif suffix == 'xstate-raw': assert 576 <= info['bytes'] <= 65536
        assert actual['original-pages.bin']['bytes'] == 151552 and actual['candidate-pages.bin']['bytes'] == 151552 + g
        for name, source in [('original.elf', c.originals[variant]), ('instructions.tsv', instructions), ('runtime-target.tsv', c.target), ('e9-witness.json', witness / 'witness.json'), ('e9-native.tsv', witness / 'native.tsv')]: assert B.read(captures / name)[0] == B.read(source)[0]
        row.update(status='PASS', capture_files=len(actual), **counts); c.active = None
        c.retain_captures(lane, cell, captures, actual)


def finish(c, args, failure):
    stable = False
    try:
        final_configs = c.stable(source=True)
        assert all(B.archive_owner(Path(p), r['limit']) == r['owner'] for p, r in c.archive_owners.items())
        for name, value in [('source-after.json', c.p.source(c.repo)), ('tools-after.json', {p: B.read(Path(p))[1] for p in c.owners}), ('config-after.json', final_configs), ('reused-inputs-after.json', c.product_owners)]: B.write(c.raw / name, value)
        stable = True
    except BaseException as error: failure = (failure or '') + '; final continuity: ' + type(error).__name__ + ': ' + str(error)
    if failure:
        if c.active: c.results[c.active].update(status='FAILED', reason='see private failure.json')
        B.write(c.raw / 'failure.json', dict(error=failure, stage=c.active))
    passed = not failure and stable and all(r['status'] == 'PASS' for r in list(c.results.values()) + c.native_results + c.retention_results)
    assert len(c.results) == 16 and len(c.native_results) == len(c.retention_results) == 8
    if passed: assert sum(r['pairs'] for r in c.native_results) == 1408
    B.write(c.raw / 'results.json', list(c.results.values())); B.write(c.raw / 'command-contexts.json', c.contexts)
    B.write(c.raw / 'public/invocation.json', c.normalized(dict(argv=[c.tools['python'], '-B', str(Path(__file__).resolve()), *sys.argv[1:]], tools=c.tools, cpu_count=4,
        subject_limits=dict(witness=[20, 30, 16 * B.MIB], replay=[60, 90, 64 * B.MIB], native_child_seconds=15, native_child_stops=20000),
        command_contexts_sha256=B.sha(B.read(c.raw / 'command-contexts.json')[0]))))
    counts = lambda rows: {status.lower(): sum(r['status'] == status for r in rows) for status in ('PASS', 'FAILED', 'UNRUN')}
    receipt = dict(schema=1, status='PASS' if passed else 'FAILED', revision=B.REVISION, script_sha256=B.sha(B.read(Path(__file__).resolve())[0]), base_script_sha256=BASE_SHA,
        prior_receipt_sha256=args.prior_receipt_sha256, prior_results_sha256=args.prior_results_sha256, prior_parent_sha256=args.prior_parent_sha256,
        source_files_sha256=B.sha(json.dumps(c.before['files'], sort_keys=True).encode()), hardware=c.hardware, build_profile='dev-debug0-v1',
        product_sha256={n: c.product_owners[str(p)]['sha256'] for n, p in getattr(c, 'products', {}).items() if str(p) in c.product_owners},
        tool_sha256={c.normalized(p): v['sha256'] for p, v in c.owners.items() if p not in (str(args.reproducer), str(c.tools_input))},
        planned=dict(cells=8, stages=16, pairs=1408, children=2816, live_comparisons=4224), stages=counts(c.results.values()), native=counts(c.native_results), retention=counts(c.retention_results),
        observed={k: sum(r[k] for r in c.native_results if r['status'] == 'PASS') for k in ('pairs', 'children', 'comparisons')}, fresh_source_tools_inputs_and_configuration_observations_unchanged=stable,
        selected_inputs_sha256=B.sha(json.dumps(c.product_owners, sort_keys=True).encode()),
        configuration_denied_lookups=sum(v.get('observation') == 'READ_DENIED' for v in c.configs.values()), configuration_scope='Classified lookup observations under three-consecutive-negative-v1, not identical raw syscall outcomes; READ_DENIED is unknown content, not absent',
        historical_owner_continuity=False, historical_custody_reconstruction=False, independent_saved_content_audit=False, qualification_complete=False, performance_claim=False,
        comparison_scope='Existing live Rust full state comparisons; capture schema and hashes corroborated, not independently replayed')
    B.write(c.raw / 'public/receipt.json', receipt)
    for name, rows, columns in [('cells.csv', c.native_results, ['cell', 'lane', 'status', 'pairs', 'children', 'comparisons', 'capture_files']), ('retention.csv', c.retention_results, ['cell', 'lane', 'status', 'original_bytes', 'archive_bytes', 'archive_sha256', 'files']), ('stages.csv', list(c.results.values()), ['stage', 'status', 'reason', 'child_exit', 'seconds'])]:
        with (c.raw / 'public' / name).open('x', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore', lineterminator='\n'); writer.writeheader(); writer.writerows(rows)
    return 0 if passed else 1


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'raw', 'tools', 'reproducer', 'prior-raw', 'prior-parent'): ap.add_argument('--' + name, type=Path, required=True)
    for name in ('prior-receipt-sha256', 'prior-results-sha256', 'prior-parent-sha256'): ap.add_argument('--' + name, required=True)
    args = ap.parse_args(); assert not sys.flags.optimize
    assert all(len(getattr(args, n)) == 64 and set(getattr(args, n)) <= set('0123456789abcdef') for n in ('prior_receipt_sha256', 'prior_results_sha256', 'prior_parent_sha256'))
    assert args.reproducer.resolve(strict=True) == args.reproducer and not args.reproducer.is_symlink()
    assert hashlib.sha256(args.reproducer.read_bytes()).hexdigest() == BASE_SHA
    spec = importlib.util.spec_from_file_location('pinned_native_v3', args.reproducer); B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
    assert B.sha(B.read(args.reproducer)[0]) == BASE_SHA
    prior_plan, _ = B.stage_plan()
    B.stage_plan = plan  # Explicit continuation schedule only; all imported method bodies remain unchanged.
    args.tools = args.tools.resolve(strict=True); os.chdir(args.repo)
    campaign = None; failure = None
    try:
        campaign = B.Campaign(args); campaign.capacity(2 * 1024 * B.MIB)
        prepare(campaign, args, prior_plan); native(campaign)
    except BaseException as error: failure = type(error).__name__ + ': ' + str(error)
    if campaign is None:
        if args.raw.is_dir(): B.write(args.raw / 'setup-failure.json', dict(status='FAILED', error=failure, native_cells='UNRUN'))
        raise SystemExit(failure)
    raise SystemExit(finish(campaign, args, failure))
