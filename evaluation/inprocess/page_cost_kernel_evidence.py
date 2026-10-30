#!/usr/bin/env python3
"""Reproduce one closed kernel-cost analysis; never execute/import a workload or evaluator.

--root is a repository or exported artifact tree preserving the pinned relative
paths. All required bytes and recorded source manifests are checked before any
output is opened. This is arithmetic projection, not new qualification.
"""
import argparse
import bisect
import collections
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re
import statistics
import struct
import tempfile

PINS = {'baseline_receipt': {'path': 'target/evaluation/inprocess/20261030T030044.789458Z-page-cost-compare-f7dd159db74f/receipt.json', 'bytes': 3045022, 'sha256': '3f9b144cf6a3998065960c37002c14f00b702d4d5a4d7b05ecaa713c9983f0ff'}, 'baseline_public': {'path': 'evaluation/inprocess/results/20261030T030044.789458Z-page-cost-compare-f7dd159db74f.json', 'bytes': 46040, 'sha256': 'b91f673efc6cfb83ee83eaf2afe1955b6b78828fc78b698d7eeccdb6cf523333'}, 'baseline_csv': {'path': 'evaluation/inprocess/results/20261030T030044.789458Z-page-cost-compare-f7dd159db74f.csv', 'bytes': 4608, 'sha256': 'd18b574556702bf380fecb05d69ae9f282e8b913169ebc913ee1bebfab017e15'}, 'bridge': {'path': 'target/evaluation/inprocess/20261030T030044.789458Z-page-cost-compare-f7dd159db74f/release/bridge-native-pair.so', 'bytes': 3170976, 'sha256': '037df7ed600258014b8f3d84b24257d88b6c7dbe288c3a98e1bbf9d91afee786'}, 'checks_public': {'path': 'evaluation/inprocess/results/20261030T031648.378097Z-checks-0847974d17b9.json', 'bytes': 11145, 'sha256': 'e32a1d53b741e6814d0bb60a5b8ffc8e6d4f3a58254e4189e367052a302a57c0'}, 'checks_receipt': {'path': 'target/evaluation/inprocess/20261030T031648.378097Z-checks-0847974d17b9/receipt.json', 'bytes': 11145, 'sha256': 'e32a1d53b741e6814d0bb60a5b8ffc8e6d4f3a58254e4189e367052a302a57c0'}, 'probe_failed': {'path': 'target/page-cost-kernel-next/probe/20261030T030625.092667Z/receipt.json', 'bytes': 7235, 'sha256': '39cabf7aef262c4539f2ffbba90214965421fde187f3b5cb5e36770452485e99'}, 'probe_observation': {'path': 'target/page-cost-kernel-next/probe/observation-r1/OBSERVED.json', 'bytes': 96727, 'sha256': 'a50ee89abbd0e9fc8671e2f23f7481f29d8f17403f26e9f34f62f89a147c8fce'}, 'access': {'path': 'target/page-cost-kernel-next/probe/ACCESS.json', 'bytes': 3466, 'sha256': '9e0bebdb6abc511ecec6bb31ca0a997a1594457482829024ffa1a740216e03b4'}, 'ls_receipt': {'path': 'target/evaluation/inprocess/20261030T031508.195312Z-page-cost-kernel-callchains-ls-0847974d17b9/receipt.json', 'bytes': 1425380, 'sha256': 'cb5b975de775a2da1f8f7800f7728c4c1bba503d2e6588f2cb365e6c613c56b9'}, 'ls_chains': {'path': 'target/evaluation/inprocess/20261030T031508.195312Z-page-cost-kernel-callchains-ls-0847974d17b9/callchains.json', 'bytes': 127383, 'sha256': '7a58572a1ce9f7f75f1d1de95edb9e8939e4295e6c135c751c56d8a2153edd46'}, 'ls_samples': {'path': 'target/evaluation/inprocess/20261030T031508.195312Z-page-cost-kernel-callchains-ls-0847974d17b9/capture/samples.json', 'bytes': 1158302, 'sha256': 'eb35443fa249549eff6c6df6f9437a571185ec2be8cf9587ced5d40d49bd3f04'}, 'ls_kallsyms': {'path': 'target/evaluation/inprocess/20261030T031508.195312Z-page-cost-kernel-callchains-ls-0847974d17b9/kernel/kallsyms', 'bytes': 10157007, 'sha256': 'db20ada07cac4846185c78d9147a684fb93a77c5dc97fbbefbaadd89d7493f4c'}, 'ls_kernel_snapshot': {'path': 'target/evaluation/inprocess/20261030T031508.195312Z-page-cost-kernel-callchains-ls-0847974d17b9/kernel/snapshot.json', 'bytes': 788, 'sha256': 'c756618c2f58934447bf4dae84da321ec2f2b9b36e740bcf96d63d646f878ba3'}, 'ls_public': {'path': 'evaluation/inprocess/results/20261030T031508.195312Z-page-cost-kernel-callchains-ls-0847974d17b9.json', 'bytes': 9601, 'sha256': '39ac81d0831adc45036e1908762c7622572934d660fa271fc078a69935adf98f'}, 'ls_csv': {'path': 'evaluation/inprocess/results/20261030T031508.195312Z-page-cost-kernel-callchains-ls-0847974d17b9.csv', 'bytes': 5891, 'sha256': '2026a88e83146aff563e1c0fe353ce164e8b76dc3be56a7738cc672dbb371b62'}, 'ls_kernel_csv': {'path': 'evaluation/inprocess/results/20261030T031508.195312Z-page-cost-kernel-callchains-ls-0847974d17b9-kernel.csv', 'bytes': 17519, 'sha256': '58e12b8133f2882443e92cfdabcf5c8067e486fe25b21cd0a450e999d03fc2bd'}, 'true_receipt': {'path': 'target/evaluation/inprocess/20261030T031602.015156Z-page-cost-kernel-callchains-true-0847974d17b9/receipt.json', 'bytes': 1420574, 'sha256': '54e5a6980d6a823f485b24ff07f8150410d1bc902572cad58e650ba12cbba1e4'}, 'true_chains': {'path': 'target/evaluation/inprocess/20261030T031602.015156Z-page-cost-kernel-callchains-true-0847974d17b9/callchains.json', 'bytes': 72745, 'sha256': '1293944cf69362b42b4ebf2f639fed1c565b61d447f0e4645ded03b19f529d89'}, 'true_samples': {'path': 'target/evaluation/inprocess/20261030T031602.015156Z-page-cost-kernel-callchains-true-0847974d17b9/capture/samples.json', 'bytes': 429984, 'sha256': '252816ec49155b7f1f1f8156e773b7b10066043b369c47a6c1413ce9efd673e4'}, 'true_kallsyms': {'path': 'target/evaluation/inprocess/20261030T031602.015156Z-page-cost-kernel-callchains-true-0847974d17b9/kernel/kallsyms', 'bytes': 10157007, 'sha256': 'db20ada07cac4846185c78d9147a684fb93a77c5dc97fbbefbaadd89d7493f4c'}, 'true_kernel_snapshot': {'path': 'target/evaluation/inprocess/20261030T031602.015156Z-page-cost-kernel-callchains-true-0847974d17b9/kernel/snapshot.json', 'bytes': 788, 'sha256': 'c756618c2f58934447bf4dae84da321ec2f2b9b36e740bcf96d63d646f878ba3'}, 'true_public': {'path': 'evaluation/inprocess/results/20261030T031602.015156Z-page-cost-kernel-callchains-true-0847974d17b9.json', 'bytes': 9463, 'sha256': 'ab18fa727cbc154f12ea284429cebe7e12789e418c56c9a327878d795272c531'}, 'true_csv': {'path': 'evaluation/inprocess/results/20261030T031602.015156Z-page-cost-kernel-callchains-true-0847974d17b9.csv', 'bytes': 3539, 'sha256': '8142ea07503c246a3e8e33d9194560d782482c0a752e11829b8ce5e9a15ce9d3'}, 'true_kernel_csv': {'path': 'evaluation/inprocess/results/20261030T031602.015156Z-page-cost-kernel-callchains-true-0847974d17b9-kernel.csv', 'bytes': 14763, 'sha256': 'c0d009e8116867c3041f66f8322f6e53dc0cd4522b39b4d2a23e4aeceb4ccfdb'}}
ANCHORS = [('perf_observer_named_path', ('perf_event_mmap', 'perf_event_mmap_output', 'perf_iterate_ctx', 'perf_iterate_sb', 'perf_output_begin', 'perf_output_begin_forward', 'perf_output_sample', 'perf_event_output_forward', 'perf_trace_run_bpf_submit', 'perf_trace_sys_enter', 'perf_trace_sys_exit')), ('proc_maps_named_path', ('show_map_vma', 'show_map', 'proc_get_vma')), ('memory_permission_named_path', ('__x64_sys_mprotect', 'do_mprotect_pkey', 'mprotect_fixup')), ('membarrier_named_path', ('__x64_sys_membarrier', '__se_sys_membarrier', 'membarrier_private_expedited', 'membarrier_global_expedited')), ('signal_exception_named_path', ('get_signal', 'handle_signal', 'force_sig_fault', 'force_sig_info', '__x64_sys_rt_sigreturn', 'do_user_addr_fault', 'exc_debug', 'exc_debug_user', 'exc_page_fault')), ('bpf_helper_named_path', ('__htab_map_lookup_elem', 'htab_map_lookup_elem', 'bpf_trace_run1', 'bpf_trace_run2', 'bpf_trace_run3', 'bpf_trace_run4', 'bpf_trace_run5', 'bpf_trace_run6', 'bpf_trace_run7', 'bpf_trace_run8', 'bpf_trace_run9', 'bpf_trace_run10', 'bpf_trace_run11', 'bpf_trace_run12', 'bpf_trampoline_enter', 'bpf_trampoline_exit'))]
BASE_REV = 'f7dd159db74f7ca1181a89bd48c11a329d7a49a5'
PROFILE_REV = '0847974d17b9f2b0e9c681c3c326e8e818af92ff'
SOURCES = {
    BASE_REV: ('2f8f8e436eaa514dca0d191e4e4b112df83e0c44', '96c4b98b44138f001ab39e46de690b3f4b5853c081ddb2c158a05153bb5888af'),
    PROFILE_REV: ('8ca646b2a8e199ad0c7b973e2b22dadf1dcbed3f', '9230790c1dac2d3d45f98908b021e140389f482b78029d4eccfb107620c8a2df'),
}
TARGET = [30, 536870912, 16777216, 60]
PROFILER = [30, 1073741824, 134217728, 80]


def need(ok, why):
    if not ok:
        raise ValueError(why)


def fact(b):
    return dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest())


def expected(key):
    return {k: PINS[key][k] for k in ('bytes', 'sha256')}


def read_all(root):
    blobs = {}
    for key, pin in PINS.items():
        path = root / pin['path']
        with path.open('rb') as f:
            before = os.fstat(f.fileno())
            data = f.read(pin['bytes'] + 1)
            after = os.fstat(f.fileno())
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'stable input ' + key)
        need(fact(data) == expected(key), 'exact retained input ' + key)
        blobs[key] = data
    return blobs


def source(r, revision):
    s = r['source']; tree, manifest = SOURCES[revision]
    need(s == dict(revision=revision, tree=tree, source_manifest_sha256=manifest,
                   tracked_clean=True, head_sources_match=True), 'exact source revision/tree/manifest')
    need(r['source_unchanged'], 'closed source unchanged')
    if 'source_after' in r:
        need(r['source_after'] == s, 'same source after')
    return s


def closure(r):
    need(r['status'] == 'passed' and r['cleanup_complete'] and not r['error'] and not r['final_errors'],
         'actual passed closed receipt')
    for k in ('inputs', 'aliases', 'artifacts'):
        need(r[k + '_before'] == r[k + '_after'], 'exact retained ' + k + ' closure')


def normalize(name):
    return re.sub(r'\.(?:llvm|isra|constprop)\.[0-9]+$', '', name)


def resolver(raw):
    rows = []
    for line in raw.decode('ascii').splitlines():
        p = line.split()
        need(len(p) in (3, 4) and re.fullmatch('[0-9a-fA-F]{16}', p[0]), 'captured kallsyms row')
        if len(p) == 3:
            rows.append((int(p[0], 16), p[1], p[2]))
    lo = [a for a, t, n in rows if n == '_stext' and t in ('t', 'T')]
    hi = [a for a, t, n in rows if n == '_etext' and t in ('t', 'T')]
    need(len(lo) == len(hi) == 1 and 0 < lo[0] < hi[0], 'closed core text bounds')
    groups = collections.defaultdict(set)
    for a, t, n in rows:
        if lo[0] <= a <= hi[0]:
            groups[a].add((t, n))
    starts = sorted(groups)
    def lookup(ip):
        if not lo[0] <= ip < hi[0]:
            return 'unknown:outside_core_text', set()
        i = bisect.bisect_right(starts, ip) - 1
        need(starts[i] <= ip < starts[i + 1], 'bounded core interval')
        vals = groups[starts[i]]
        if not all(t in ('t', 'T') for t, _ in vals):
            return 'unknown:nontext_or_mixed_symbol_group', set()
        names = sorted({n for _, n in vals})
        return 'core_interval:' + '|'.join(names), set(map(normalize, names))
    return lookup


def counter():
    return collections.defaultdict(lambda: [0, 0])


def add(c, key, row):
    c[key][0] += 1
    c[key][1] += row['period']


def table(c, total):
    return [dict(key=k, samples=n, sampled_period_ns=w, percent_sampled_cpu=100*w/total)
            for k, (n, w) in sorted(c.items(), key=lambda x: (-x[1][1], str(x[0])))]


def stats(values):
    q1, _, q3 = statistics.quantiles(values, n=4, method='inclusive')
    return dict(n=len(values), median=statistics.median(values), q1=q1, q3=q3, iqr=q3-q1)


def analyze(rows, chains, raw_symbols):
    lookup = resolver(raw_symbols)
    categories, disjoint, inclusive, roots, other, unknown, users, intersections = [counter() for _ in range(8)]
    selected = [r for r in rows if r['in_target_exec_window']]
    total = sum(r['period'] for r in selected)
    for row in selected:
        need(row['period'] > 0 and row['cpumode'] in (1, 2), 'positive host-mode sample')
        if row['cpumode'] == 2:
            add(users, (row['reason'], row['symbol']), row)
            continue
        chain = row['callchain']; pcs = chain['pcs']
        need(chain['depth'] == len(pcs) <= 64 and not chain['unwind_complete'], 'retained bounded incomplete unwind')
        labels = tuple(lookup(pc)[0] for pc in pcs)
        names = set().union(*(lookup(pc)[1] for pc in pcs)) if pcs else set()
        matches = [name for name, wanted in ANCHORS if names.intersection(wanted)]
        head = bool(pcs) and pcs[0] == row['ip']
        caller = (next((x for x in labels[1:] if x.startswith('core_interval:')), 'unknown:no_resolved_caller')
                  if head else 'unknown:empty_or_different_chain_head')
        category = ('empty_or_marker_only' if not pcs else 'unwind_head_mismatch' if not head else
                    matches[0] if matches else 'other_known_kernel_path' if names else 'unknown_kernel_path')
        leaf = lookup(row['ip'])[0]
        add(categories, category, row)
        add(disjoint, (category, leaf, caller, chain['state'], 'depth_limit' if chain['depth_limit_hit'] else 'below_limit'), row)
        for path in set(labels[i:] for i in range(len(labels))):
            add(inclusive, path, row)
        candidates = sorted(n for n in names if n.startswith('__x64_sys_') or n == '__se_sys_membarrier')
        root = candidates[0] if len(candidates) == 1 else 'no_recorded_syscall_root' if not candidates else ' | '.join(candidates)
        add(roots, root, row); add(intersections, (root, category), row)
        if category == 'other_known_kernel_path':
            add(other, root, row)
        if leaf.startswith('unknown:'):
            add(unknown, (root, caller), row)
    need({k: tuple(v) for k, v in disjoint.items()} ==
         {tuple(x['path']): (x['samples'], x['sampled_period_total']) for x in chains['disjoint']}, 'all original disjoint rows unchanged')
    need({k: tuple(v) for k, v in inclusive.items()} ==
         {tuple(x['path']): (x['samples'], x['sampled_period_total']) for x in chains['inclusive']}, 'all original overlapping inclusive rows unchanged')
    need({k: tuple(v) for k, v in categories.items()} ==
         {x['name']: (x['samples'], x['sampled_period_total']) for x in chains['categories']}, 'all original categories unchanged')
    need(sum(v[0] for v in roots.values()) == chains['kernel_samples'] and
         sum(v[1] for v in roots.values()) == chains['kernel_sampled_period_total'], 'kernel partition conserves all counts/periods')
    need(sum(v[0] for v in other.values()) == categories['other_known_kernel_path'][0], 'complete subdivision of original other category')
    def sumfor(c, predicate):
        return [sum(v[i] for k, v in c.items() if predicate(k)) for i in (0, 1)]
    models = {
        'open_close_candidate_envelope': sumfor(roots, lambda k: k in ('__x64_sys_openat', '__x64_sys_close')),
        'joined_repeat_closed_quiet_symbols': sumfor(users, lambda k: k[0] == 'authenticated_bridge_symbol' and
                                                      k[1] in ('li2_repeat_lease_closed', 'li2_repeat_custody_quiet')),
        'strict_maps_parser_symbols': sumfor(users, lambda k: k[0] == 'authenticated_bridge_symbol' and
                                            k[1] in ('read_maps_checked.part.0', 'number_checked.constprop.0')),
    }
    conditional = {}
    for name, (n, w) in models.items():
        f = w / total
        conditional[name] = dict(samples=n, sampled_period_ns=w, percent_sampled_cpu=100*f,
                                 conditional_half_component_cost_speedup=1/(1-f/2), elimination_ceiling=1/(1-f))
    frame = sumfor(users, lambda k: k[0] == 'authenticated_bridge_symbol' and k[1] in
                   ('frame', 'lease_frame_copy', 'chain_frame_equal', 'np_life_copy', 'np_capture'))
    f = sum(v[1] for v in models.values()) / total
    return dict(samples=len(selected), sampled_period_ns=total, kernel_samples=chains['kernel_samples'],
                original_categories=table(categories, total), syscall_root_partition=table(roots, total),
                original_other_known_subdivision=table(other, total), unknown_leaf_ancestry=table(unknown, total),
                mprotect_category_split=table({k[1]: v for k, v in intersections.items() if k[0] == '__x64_sys_mprotect'}, total),
                conditional_models=conditional, conditional_all_three_half_cost_speedup=1/(1-f/2),
                state_source_copy_compare=dict(samples=frame[0], sampled_period_ns=frame[1], percent_sampled_cpu=100*frame[1]/total),
                unknown_frame_samples=chains['unknown_frame_samples'], unknown_frame_occurrences=chains['unknown_frame_occurrences'],
                depth_limit_samples=chains['depth_limit_samples'], head_mismatch_samples=chains['nonempty_head_mismatch_samples'],
                original_full_disjoint_inclusive_preserved=True, unwind_complete=False)


def project(blobs):
    data = {k: json.loads(v) for k, v in blobs.items() if PINS[k]['path'].endswith('.json')}
    b, bp = data['baseline_receipt'], data['baseline_public']
    closure(b); base_source = source(b, BASE_REV); need(source(bp, BASE_REV) == base_source, 'baseline public source')
    need(bp['status'] == 'passed' and bp['cleanup_complete'] and bp['final_error_count'] == 0, 'actual baseline public closure')
    need(bp['private_receipt'] == expected('baseline_receipt') and bp['csv'] == dict(file=Path(PINS['baseline_csv']['path']).name, **expected('baseline_csv')), 'baseline public byte joins')
    need(len(b['cases']) == 60 and len(b['commands']) == 96 and
         all(c['reaped'] and not c['timed_out'] and not c['error'] and not c['cleanup_errors'] for c in b['commands']), 'all baseline command ownership retained')
    need(b['bounds']['program'] == TARGET and b['bounds']['program_dr'] == [30, 17179869184, 16777216, 60], 'unchanged baseline target/DR limits')
    csv_rows = list(csv.DictReader(io.StringIO(blobs['baseline_csv'].decode())))
    need(len(csv_rows) == 60, 'exact 60 baseline CSV launches')
    for observed, row in zip(b['cases'], csv_rows):
        need(set(row).issubset(observed), 'CSV fields backed by actual cases')
        need(all(str(observed[k]) == v for k, v in row.items()), 'all actual CSV values equal private cases')
        need(observed['status'] == 'passed' and observed['exit'] == 0, 'no failed attempt omitted or relabelled')
    baseline = {}
    for w in ('ls', 'true'):
        baseline[w] = {}
        for lane in ('native', 'gated', 'dynamorio'):
            rows = [x for x in b['cases'] if x['workload'] == w and x['lane'] == lane]
            need(len(rows) == 10 and {x['repeat'] for x in rows} == set(range(10)), 'exact ten attempts per lane/workload')
            measured = {k: stats([x[k] for x in rows]) for k in ('process_ns', 'user_cpu_ns', 'system_cpu_ns')}
            s = measured['process_ns']; published = bp['statistics'][w][lane]
            need(published == dict(planned=10, passed=10, median_ns=s['median'], q1_ns=s['q1'], q3_ns=s['q3'], iqr_ns=s['iqr']), 'exact original public medians/IQR')
            baseline[w][lane] = measured
    profiles = {}
    suffix = 'tools/page-entry/selected/runtime_loader.c'
    candidates = [p[:-len(suffix)] for p in b['inputs_before'] if p.endswith(suffix)]
    need(len(candidates) == 1, 'one recorded source root')
    prefix = candidates[0]
    native = {p: v for p, v in b['inputs_before'].items() if p.startswith(prefix) and
              (p[len(prefix):].startswith(('src/', 'crates/', 'tools/page-entry/')) or p[len(prefix):] in ('Cargo.toml', 'Cargo.lock'))}
    need(len(native) == 932, 'exact recorded native-source agreement population')
    for w in ('ls', 'true'):
        r, public = data[w+'_receipt'], data[w+'_public']; closure(r); current = source(r, PROFILE_REV)
        need(source(public, PROFILE_REV) == current and public['private_receipt'] == expected(w+'_receipt'), 'profile public/source/receipt joins')
        need(r['baseline'] == dict(**expected('baseline_receipt'), revision=BASE_REV, status='passed') and
             r['native_source_pins'] == len(native) and all(r['inputs_before'].get(p) == v for p, v in native.items()), 'same actual baseline native sources')
        need(r['bridge'] == expected('bridge') == b['release_build']['bridge'], 'same actual release bridge')
        need(r['command']['exit'] == 0 and r['command']['reaped'] and not r['command']['timed_out'] and
             not r['command']['cleanup_errors'] and r['command']['bounds'] == TARGET and
             public['bounds'] == dict(target=TARGET, profiler=PROFILER), 'unchanged successful target owner/bounds')
        need(public['status'] == 'passed' and public['cleanup_complete'] and public['final_error_count'] == 0, 'actual profile public closure')
        need(public['target_exit'] == public['profiler_exit'] == 0 and not public['benchmark_credit'] and not public['qualification'], 'diagnostic-only successful profiles')
        sampling = public['sampling']; chains = data[w+'_chains']; samples = data[w+'_samples']
        need(sampling == r['diagnostic']['sampling'] and sampling['loss_free'] and
             sampling['lost_samples'] == sampling['throttle_records'] == 0, 'actual loss-free retained sample stream')
        need({k: public['csv'][k] for k in ('bytes', 'sha256')} == expected(w+'_csv') and
             {k: public['kernel_csv'][k] for k in ('bytes', 'sha256')} == expected(w+'_kernel_csv') and
             public['callchains']['private_table'] == expected(w+'_chains'), 'all public CSV and private full-chain bytes')
        snap = data[w+'_kernel_snapshot']; need(snap['files']['kallsyms'] == expected(w+'_kallsyms'), 'exact retained boot-bound symbols')
        got = analyze(samples, chains, blobs[w+'_kallsyms'])
        need(got['samples'] == sampling['samples'] and got['sampled_period_ns'] == sampling['sampled_period_total'], 'all target samples and periods')
        got.update(process_ns=r['command']['process_ns'], controls=public['controls'], target_exit=0, profiler_exit=0,
                   loss_free=True, cpu=public['hardware']['probe_cpu'], kernel_build_ids=public['kernel_build_ids'])
        profiles[w] = got
    checks = data['checks_public']; need(blobs['checks_public'] == blobs['checks_receipt'], 'exact checks public/private pair')
    source(checks, PROFILE_REV)
    need(checks['status'] == 'passed' and len(checks['commands']) == 6 and
         all(c['status'] == 'passed' and c['exit_code'] == 0 and c['cleanup_complete'] for c in checks['commands']), 'all six actual closed checks')
    keys = ('id', 'status', 'seconds', 'timeout_seconds', 'tests_passed', 'recorder_observations', 'harness_totals',
            'backing_cleanup_harnesses_count', 'precontext_native_harnesses_count', 'native_cases_count',
            'native_validation_fixtures_count', 'dynamic_matrix_cases_count', 'dynamic_admission_fixtures_count')
    check_rows = [{k: c[k] for k in keys if k in c} for c in checks['commands']]
    failed, observation, access = data['probe_failed'], data['probe_observation'], data['access']
    need(failed['status'] == 'failed' and failed['error'].startswith('AssertionError') and
         observation['status'] == 'closed_data_observation' and observation['original_probe']['status'] == 'failed' and
         {k: observation['original_probe']['receipt'][k] for k in ('bytes', 'sha256')} == expected('probe_failed'), 'original capability failure remains failed')
    need(all(not x['readable'] and x['errno'] == 13 for x in access['access']) and len(access['access']) == 7, 'actual tracefs/audit access refusal')
    hardware_keys = ('architecture', 'vendor_id', 'cpu family', 'model', 'model name', 'stepping', 'microcode',
                     'kernel_version', 'kernel_release_sha256', 'runner_cap_eff', 'runner_is_root', 'runner_seccomp_mode')
    hardware = {k: bp['hardware'][k] for k in hardware_keys}
    isa_digest = bp['hardware']['isa_flags_sha256']
    need(all(hashlib.sha256(json.dumps(data[w+'_public']['hardware']['isa_flags'], sort_keys=True, separators=(',', ':')).encode()).hexdigest() == isa_digest for w in ('ls', 'true')), 'same full recorded ISA flags')
    need(all({k: data[w+'_public']['hardware'][k] for k in hardware_keys} == hardware for w in ('ls', 'true')), 'same recorded hardware/kernel identity')
    hardware['isa_flags_sha256'] = isa_digest
    refs = {k: dict(**expected(k), **({'file': Path(PINS[k]['path']).name} if '_public' in k or k.endswith('_csv') else {}))
            for k in PINS if k != 'bridge'}
    return dict(schema=1, scope='Closed-data arithmetic; no new execution, qualification or causal wall-speedup claim.',
                sources={BASE_REV: base_source, PROFILE_REV: current}, native_source_pins_equal=932,
                hardware=hardware, baseline_cpu=bp['cpu'], tools=data['ls_public']['tools'],
                baseline=dict(launches=60, commands=96, statistics=baseline, bounds=b['bounds'], quantiles=bp['quantiles'],
                              timing_scope=bp['whole_process_scope'], tool_versions=bp['tool_versions']),
                profiles=profiles, checks=dict(reference=refs['checks_public'], commands=check_rows, reproduce=checks['reproduce']), evidence=refs,
                predecessor=dict(original_probe_status='failed', original_error_class='AssertionError',
                                 data_only_observation_status='closed_data_observation',
                                 samples=observation['sampling']['samples'], kernel_samples=observation['sampling']['kernel_samples']),
                unresolved=dict(ptrace_requests=None, ptrace_stops=None, tracefs_audit_eacces_reads=7,
                                unknown_bpf_program_identity=True, observer_ownership_not_established=True,
                                open_close_filename_not_recorded=True),
                interpretation=['perf_event_mmap notification paths are observed; other host observers may contribute.',
                                'Open/close is a candidate envelope, not a maps-only attribution. Any maps-FD lease remains a conditional design investigation.',
                                'Disjoint categories conserve samples. Inclusive paths overlap and are not added as time.',
                                'Amdahl factors assume half the named component cost and unchanged remainder; they are not baseline wall predictions.'],
                reproduce=dict(artifact_root_layout='The pinned repository-relative paths may be exported under any retained artifact root.',
                    arithmetic='python3 evaluation/inprocess/page_cost_kernel_evidence.py --root "$ARTIFACT_ROOT" --output "$OUTPUT_JSON"',
                    reserve='CPU must already be reserved and SDK must identify the measured DynamoRIO SDK; no implicit CPU reservation.',
                    baseline='taskset -c "$CPU" python3 evaluation/inprocess/page_cost_compare.py --expect-revision '+BASE_REV+' --sdk "$SDK"',
                    profiles=['taskset -c "$CPU" python3 evaluation/inprocess/page_cost_profile_run.py --baseline "$CLOSED_BASELINE_RECEIPT" --expect-revision '+PROFILE_REV+' --workload '+w+' --kernel-callchains' for w in ('ls', 'true')],
                    revision_order='Baseline runs at f7dd; profile commands run at 0847 and require exact native-source agreement.'))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, default=Path('.'))
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    need(not args.output.exists() and args.output.parent.is_dir(), 'fresh output in existing directory')
    blobs = read_all(args.root)
    result = project(blobs)
    encoded = (json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    need(len(encoded) <= 32*1024, 'compact 32 KiB public projection')
    need(not any(x in encoded for x in (b'/home/', b'/tmp/', b'devbig', b'unknown:0x')), 'no private host paths or raw unknown addresses')
    # Publish only a fully checked buffer, without overwriting an existing result.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=args.output.parent, prefix='.kernel-cost-', delete=False) as stream:
            temporary = Path(stream.name); stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
        os.link(temporary, args.output)
    finally:
        if temporary is not None:
            temporary.unlink()


if __name__ == '__main__':
    main()
