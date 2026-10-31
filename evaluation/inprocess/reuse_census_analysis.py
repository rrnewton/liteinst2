#!/usr/bin/env python3
"""Interpret an explicitly pinned closed failed-prefix census; no guest execution or authority."""
import argparse
import ast
import collections
import hashlib
import json
from pathlib import Path
import resource
import signal
import struct
import subprocess
import types

SOURCES = (
    'evaluation/inprocess/reuse_census.py',
    'evaluation/inprocess/reuse_census_process.py',
    'tools/page-entry/selected/reuse_census.h',
    'tools/page-entry/selected/reuse_census_owner.inc',
    'tools/page-entry/selected/persistent_group_plan.h',
    'tools/page-entry/selected/persistent_group_plan.c',
    'tools/page-entry/selected/persistent_group_counters.h',
    'tools/page-entry/selected/linked_controller.inc',
)
REASONS = dict(enumerate(('ROOT_UNSUPPORTED', 'SOURCE_INVALID', 'SOURCE_TRUNCATED',
                         'SOURCE_OVERLAP', 'OUTSIDE_PAIR', 'HEAD_LIMIT', 'EXIT_LIMIT',
                         'QUEUE_LIMIT', 'NO_EXIT', 'RIP_REACH', 'BRANCH_REACH',
                         'FALLTHROUGH_REACH', 'GUARD_RIP_REACH', 'GUARD_FOLLOW_REACH',
                         'ROOT_SELECTED', 'SINGLE_MEMBER', 'LINK_LIMIT'), 1))


def need(ok, message):
    if not ok:
        raise ValueError(message)


def fact(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def analyze(root, receipt_path, expected_revision, expected_receipt_sha256):
    need(len(expected_revision) == 40 and len(expected_receipt_sha256) == 64 and
         all(c in '0123456789abcdef' for c in expected_revision + expected_receipt_sha256),
         'explicit full source revision and receipt digest')
    receipt_bytes = receipt_path.read_bytes()
    receipt_fact = fact(receipt_bytes)
    need(receipt_fact['sha256'] == expected_receipt_sha256, 'exact closed receipt')
    receipt = json.loads(receipt_bytes)
    target = receipt['target']
    need(receipt['revision'] == expected_revision and receipt['status'] == 'failed' and
         receipt['target_outcome'] == 'failed_prefix' and target['exit'] == -9 and
         target['reaped'] and not target['timed_out'] and target['bounds'] == [30, 512 << 20, 16 << 20, 60] and
         receipt['source_unchanged'] and receipt['cleanup_complete'] and receipt['namespace_complete'] and
         receipt['final_errors'] == [] and receipt['terminal'] is None and receipt['subentry_counts'] is None,
         'closed failed target with unchanged bounds and no invented terminal')
    sources, source_facts = {}, {}
    for relative in SOURCES:
        matches = [v for k, v in receipt['inputs'].items() if k.endswith('/' + relative)]
        need(len(matches) == 1, 'unique historical source input')
        data = subprocess.run(['git', 'show', expected_revision + ':' + relative], cwd=root,
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout
        need(fact(data) == matches[0], 'whole historical Git source equals closed receipt')
        sources[relative] = data
        source_facts[relative] = fact(data)
    parser = types.ModuleType('pinned_reuse_census')
    exec(compile(sources[SOURCES[0]], SOURCES[0], 'exec'), parser.__dict__)
    captures = {}
    for name in ('census', 'counters'):
        observed = target['captures'][name]
        need(Path(observed['file']).name == observed['file'], 'capture basename only')
        data = (receipt_path.parent / observed['file']).read_bytes()
        need(fact(data) == {k: observed[k] for k in ('bytes', 'sha256')}, 'exact closed raw capture')
        captures[name] = data
    ci = target['census_input']
    initial = (parser.MAGIC, 1, parser.BYTES, 4096, ci['nonce'], ci['parent'], ci['device'], ci['inode'])
    census = parser.read(captures['census'], initial, target['pid'], target['census_observation']['final_seals'])
    need(census == receipt['reuse_census'] == target['census_observation']['summary'], 'whole strict census replay')
    need(census['recorder_error'] == 0,
         'no recorder overflow/error; strict parser retains actual complete, partial and busy state')

    # Execute the unchanged existing ABI2 parser and its literal name tables,
    # without importing the process launcher or running any process helper.
    tree = ast.parse(sources[SOURCES[1]])
    wanted = {'NATIVE_NAMES', 'GROUP_NAMES', 'MAP_NAMES', 'VIEW_NAMES'}
    nodes = [n for n in tree.body if isinstance(n, ast.Assign) and
             len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id in wanted]
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'final_counter_prefix']
    need(len(nodes) == 4 and len(functions) == 1, 'exact existing counter parser extraction')
    counter_scope = dict(need=need, struct=struct)
    exec(compile(ast.Module(body=nodes + functions, type_ignores=[]), SOURCES[1], 'exec'), counter_scope)
    ci = target['counter_input']
    initial = (0x31434f554e544750, 2, 752, 4096, ci['nonce'], ci['parent'], ci['device'], ci['inode'])
    counters = counter_scope['final_counter_prefix'](captures['counters'], initial, target['pid'],
                                                     target['counter_observation']['final_seals'])
    need(all(value == target['counter_observation'][key] == receipt['counts'][key]
             for key, value in counters.items()), 'whole existing independent counter-cell replay')

    raw = captures['census']
    h = struct.unpack_from('<512Q', raw)
    pages = [(struct.unpack_from('<32Q', raw, parser.OFFSETS[0] + parser.SIZES[0] * i),
              memoryview(raw)[parser.OFFSETS[0] + parser.SIZES[0] * i + 256:
                              parser.OFFSETS[0] + parser.SIZES[0] * (i + 1)]) for i in range(h[17])]
    keys = [struct.unpack_from('<8Q', raw, parser.OFFSETS[1] + 64 * i) for i in range(h[18])]
    graphs = [struct.unpack_from('<8Q', raw, parser.OFFSETS[2] + 320 * i) for i in range(h[19])]
    attempts = [struct.unpack_from('<32Q', raw, parser.OFFSETS[4] + 256 * i) for i in range(h[21])]
    branches, branch_sites = collections.Counter(), collections.defaultdict(set)
    refusals, repeated_refusals, failure_keys = collections.Counter(), collections.Counter(), set()
    recent, distances, first_success = [], collections.defaultdict(collections.Counter), collections.Counter()
    publication_history, evicted = {}, set()
    repeated_publications = recompiled_after_eviction = 0
    for v in attempts:
        if not v[31] & 4:
            continue
        if v[17] == 3:
            reason = v[18] & 0xffffffff
            need(reason in REASONS, 'exact protocol refusal vocabulary')
            failure = (v[9], v[10], v[2], v[3], tuple(v[18:21]))
            refusals[reason] += 1
            repeated_refusals[reason] += failure in failure_keys
            failure_keys.add(failure)
            if reason == 5:
                key = keys[v[9] - 1]
                windows = [(meta, data, v[19] - meta[0]) for meta, data in
                           (pages[q - 1] for q in key[1:3]) if 0 <= v[19] - meta[0] < 4096]
                need(len(windows) == 1, 'miss origin uniquely belongs to its full saved source pair')
                meta, data, offset = windows[0]
                code = data[offset:offset + 15]
                if code[0] == 0xe9:
                    kind, length, displacement = 'JMP_rel32', 5, 1
                else:
                    need(len(code) >= 6 and code[0] == 0x0f and 0x80 <= code[1] <= 0x8f,
                         'every remaining actual outside-pair source is canonical near Jcc')
                    kind, length, displacement = 'Jcc_rel32', 6, 2
                need(len(code) >= length, 'whole original branch bytes available')
                target_pc = v[19] + length + int.from_bytes(code[displacement:displacement + 4], 'little', signed=True)
                need(v[18] >> 32 == 1 and 0 <= target_pc < 1 << 47 and target_pc == v[20] and
                     all(not pages[q - 1][0][0] <= target_pc < pages[q - 1][0][0] + 4096 for q in key[1:3]),
                     'computed canonical branch target equals actual miss detail outside both saved pages')
                branches[kind] += 1
                branch_sites[kind].add(v[19])
        if not v[31] & 8:
            continue
        identity = graphs[v[23] - 1][:2]
        kind = {1: 'root_hit', 2: 'internal_hit', 4: 'cold_publication'}[v[17]]
        if kind == 'cold_publication':
            previous = publication_history.get(identity)
            if previous is not None:
                repeated_publications += 1
                recompiled_after_eviction += previous in evicted
            if v[24]:
                evicted.add(v[24])
            publication_history[identity] = v[23]
        if identity in recent:
            distance = recent.index(identity)
            bucket = '0-1' if distance < 2 else '2-7' if distance < 8 else '8+'
            distances['all'][bucket] += 1
            distances[kind][bucket] += 1
            recent.remove(identity)
        else:
            first_success[kind] += 1
        recent.insert(0, identity)
    need(sum(branches.values()) == census['miss_reasons'].get('5', 0),
         'every actual outside-pair incident independently classified')
    need({str(k): v for k, v in refusals.items()} == census['miss_reasons'] and
         sum(repeated_refusals.values()) == census['events'].get('repeat_exact_refusals', 0) and
         dict(distances['all']) == census['distinct_successful_key_distance'] and
         sum(distances['cold_publication'].values()) == repeated_publications == census['events'].get('repeat_exact_publications', 0) and
         recompiled_after_eviction == census['events'].get('recompiled_after_recorded_eviction', 0),
         'independent derived populations match strict replay')
    unknown = census['eight']['first_unknown']
    eight_scope = (f"Eight-slot placement and all later LRU state are unknown from attempt {unknown['attempt']}."
                   if unknown is not None else 'Eight-slot replay is only an identical observed prefix; admission remains unpredicted.')
    return dict(schema=1, revision=expected_revision, receipt=receipt_fact, inputs={name: fact(data) for name, data in captures.items()},
                source_inputs=source_facts, target=dict(status='failed_prefix', exit=target['exit'], bounds=target['bounds'],
                process_ns=target['process_ns'], wrapper_ns=target['duration_ns'], terminal_available=False),
                census=census, counters=counters, outside_pair=dict(incidents=sum(branches.values()), forms=dict(branches),
                distinct_sites={name: len(sites) for name, sites in branch_sites.items()},
                all_targets_equal_miss_detail=True, all_targets_outside_both_saved_pages=True,
                unclassified=0, admission_prediction=False),
                refusal_repetition={REASONS[k]: dict(total=refusals[k], repeated=repeated_refusals[k]) for k in sorted(refusals)},
                successful_primary_distances={name: {bucket: row[bucket] for bucket in ('0-1', '2-7', '8+')}
                                              for name, row in distances.items()},
                first_successful_identities=dict(first_success), final_attempt_phase=attempts[-1][31] if attempts else None,
                limitations=['Killed prefix, not completed workload or performance evidence.',
                             'Branch counts are planner refusal incidents, not executed branches; alternate edges may be inspected.',
                             'Counter cells and census transactions are independent; no cross-cell normalization.',
                             'Distance counts successful primary identities; peer touches are not distance events.',
                             eight_scope,
                             'Canonical branch classification does not prove later plan or execution admission.'],
                qualification_credit=False, performance_credit=False)


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument('--root', type=Path, required=True)
    args.add_argument('--receipt', type=Path, required=True)
    args.add_argument('--expect-revision', required=True)
    args.add_argument('--expect-receipt-sha256', required=True)
    a = args.parse_args()
    for limit, value in ((resource.RLIMIT_CPU, 5), (resource.RLIMIT_AS, 512 << 20),
                         (resource.RLIMIT_FSIZE, 16 << 20), (resource.RLIMIT_CORE, 0)):
        resource.setrlimit(limit, (value, value))
    signal.alarm(15)
    print(json.dumps(analyze(a.root, a.receipt, a.expect_revision, a.expect_receipt_sha256),
                     sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    main()
