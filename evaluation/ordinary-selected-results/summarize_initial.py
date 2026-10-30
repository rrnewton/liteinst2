#!/usr/bin/env python3
"""Extract the fixed initial 50e9 history from closed private records; never run code.

Usage: python3 -B summarize_initial.py --archive ROOT --output NEW_DIRECTORY
The archive contains the original ignored/a3 paths. Only JSON, text and hashes
are consumed. This is evidence extraction, not native execution or approval.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re

REV = '50e9fcba42c5dfb5e2c20e66d56b452a365644b5'
PINS = {
    'selected-session-build-v1/result.json': '32f2d9669b093177b4d196195fcba20b270e60b643c26616a4d6335199c24e2c',
    'selected-session-test-build-v1/result.json': '3e5d708316649fd2e131f91f99992ca002d90437457cdd336fbe24f82ed06ac2',
    'selected-controls-50e9-v1/result.json': '17eb617163f3d43943c802d6ebf83faf39885812f27798211d69eed5d376dc7b',
    'selected-campaign-50e9-v1/result.json': '6b25085f3ec88ce741d9d15fcde369d3e487a1d29fe5aeb0b0d0cdc2cce4e893',
    'selected-full-50e9-v2/closed.json': '177d7bc3a2879162d4352e2ee6bc7c5faf895f29340e08559c683aaaa4bb6419',
    'offline-router-owner-v1/selected-build-v1.json': '8d4e23c3d3bebcb1025ed7ccb9087175ed4bdef97b643ad14596cfd7fd170ea1',
    'offline-router-owner-v1/selected-test-build-v1.json': '8ef2493b86ebc41ee816cb4fa01749d7b2518bdb7a2afb1a139e617dc1359544',
    'offline-router-owner-v1/selected-controls-50e9-v1.json': '315f60220d56b4d32a89c1551689dc945b7a2c25822ee4421376c56710797570',
    'offline-router-owner-v1/selected-campaign-50e9-v1.json': 'a63b4168bc26ccb88b145cf21329682d137b920e976f95d7440b55a98b07cfd5',
    'offline-router-owner-v1/selected-full-50e9-v1.json': '10cf5ec0778835dad211e98d6a8f05b59b732e0b73403a339ac3946c45dee938',
    'offline-router-owner-v1/selected-full-50e9-v2.json': '6aeb3ddc50e3a71622a996218246b497c7007f8e2f5688762a36ae4a46da4405',
}
SUMMARY = re.compile(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s(?:;.*)?$', re.M)
README = '''The initial campaign FAILED. Four references passed 4052 calls; all four installed cells exited before READY/input with `EntryExit`. All eight cells had one attempt and normal reap; every owner completed cleanup. No installed success is claimed.

Full validation passed 3848 workspace tests, zero failures, 37 ignored (107 unfiltered summaries). The raw 3851 includes three nested child passes, each with 35 filtered tests, excluded from that total. Serial launch passed 1039; release controls passed 92 Rust and 94 Python. The wrong-revision preflight remains FAILED with zero tests.

receipt.json pins revisions, products, commands, tools, CPUs, loads and raw closures; cells.csv preserves all eight outcomes. Static review found ADC r8,0 at offset24 in uppercase_count: the existing CFG whitelist rejected it before loading. Generic stderr alone does not identify that guard. Later fixes cannot relabel this attempt. Full-state, arbitrary-ABI, performance and strict 2 ms claims remain unqualified; geometry and ABI/CET/signal/quiescence/lifetime premises were separate inputs.

The [extractor](../summarize_initial.py) reads the pinned private archive: `--archive ROOT --output NEW_DIRECTORY`. Logs/inventories/binaries stay ignored. The [public build recipe](../../ordinary-selected-session/BUILD.md) describes fresh experiments, not these historical private builders. Commands use `$ROOT`, `$TOOLCHAIN`, `$USER_HOME`, `$CARGO_HOME`. Earlier focused MSRV/checker refusals remain separate, outside these totals.
'''


def require(ok):
    if not ok:
        raise ValueError('closed initial-history join failed')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    base = args.archive.resolve(strict=True) / 'ignored/a3'
    def read(path, expected=None):
        raw = path.read_bytes()
        require(len(raw) <= 32 * 1048576 and (expected is None or digest(raw) == expected))
        return raw
    records = {name: json.loads(read(base / name, pin)) for name, pin in PINS.items()}
    build, test, controls, campaign, full = [records[name] for name in list(PINS)[:5]]
    oldroot = str(Path(campaign['environment']['CARGO_TARGET_DIR']).parent)
    prefixes = [(oldroot, '$ROOT'), (str(Path(build['tools']['rustc']['path']).parent.parent), '$TOOLCHAIN'),
                (build['environment']['CARGO_HOME'], '$CARGO_HOME'), (build['environment']['HOME'], '$USER_HOME')]
    def public(value):
        if isinstance(value, dict): return {k: public(v) for k, v in value.items()}
        if isinstance(value, list): return [public(v) for v in value]
        if isinstance(value, str):
            for source, replacement in prefixes: value = value.replace(source, replacement)
        return value
    def local(name):
        p = Path(name)
        require(p.is_relative_to(Path(oldroot)))
        return args.archive.resolve() / p.relative_to(oldroot)
    owners = []
    for name in list(PINS)[5:]:
        item = records[name]; closed = item['closed']; raw = read((base / name).with_suffix('.log'), closed['private_log_sha256'])
        require(item['source_unchanged'] is True and item['working_source_sha256'] == {} and closed['cleanup_complete'] is True and closed['termination'] is None and closed['reaped_descendants'] == 0 and item['attempts'] == 1)
        owners.append(dict(name=Path(name).stem, revision=item['base'], command=public(item['command']),
            cpus=item['reserved_cpus'], load_before=item['load_before'], load_after=item['load_after'],
            seconds=closed['seconds'], exit=closed['exit_code'], log_sha256=digest(raw)))
    validation = []
    for row in full['results']:
        closed = row['result']; raw = read(base / 'selected-full-50e9-v2' / (row['name'] + '.log'), closed['private_log_sha256'])
        require(closed['exit_code'] == 0 and closed['cleanup_complete'] is True and closed['termination'] is None and closed['reaped_descendants'] == 0)
        matches = list(SUMMARY.finditer(raw.decode())); kept = [m for m in matches if int(m[6]) == 0]
        require(not any(line.startswith('test result:') and not SUMMARY.fullmatch(line) for line in raw.decode().splitlines()))
        validation.append(dict(name=row['name'], command=row['command'], seconds=closed['seconds'], raw_sha256=digest(raw),
            included_summaries=len(kept), excluded_filtered_summaries=[list(map(int, m.group(2, 3, 4, 6))) for m in matches if int(m[6])],
            counts=[sum(int(m[i]) for m in kept) for i in (2, 3, 4)]))
    require(validation[3]['counts'] == [3848, 0, 37] and validation[4]['counts'] == [1039, 0, 0])
    require(campaign['status'] == 'FAILED' and controls['status'] == 'SELECTED_CONTROLS_PASS')
    require(controls['controls']['rust_count'] == 92 and controls['controls']['python_count'] == 94)
    rows = []
    for cell in campaign['cells']:
        child = local(cell['child']); data = read(child / 'result.json', campaign['retained'][cell['child'] + '/result.json']['sha256']); item = json.loads(data)
        stdout = read(child / 'stdout.txt', item['stdout_sha256']); stderr = read(child / 'stderr.txt', item['stderr_sha256'])
        require(cell['attempts'] == cell['attempt_limit'] == 1 and cell['retries'] == 0 and item['normal_reaps'] == 1 and item['rescue'] is False and item['cleanup_error'] is None)
        if cell['leg'] == 'installed': require(cell['status'] == item['status'] == 'FAILED' and item['child_exit'] == 1 and item['sent_bytes'] == 0 and stdout == b'' and stderr == b'normal-selected-session FAILED: EntryExit\n')
        else: require(cell['status'] == item['status'] == 'PASS' and item['child_exit'] == 0 and stderr == b'' and item['calls'] == cell['calls'])
        rows.append(dict(cell=cell['name'], status=cell['status'], attempts=1, expected_records=cell['records'], expected_calls=cell['calls'],
            observed_calls=item['calls'] if cell['leg'] == 'reference' else 0, sent_bytes=item['sent_bytes'], exit=item['child_exit'],
            normal_reaps=1, stdout_bytes=len(stdout), stdout_sha256=digest(stdout), stderr_sha256=digest(stderr), child_receipt_sha256=digest(data)))
    require(len(rows) == 8 and sum(r['observed_calls'] for r in rows) == 4052)
    stream = io.StringIO(newline=''); writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator='\n'); writer.writeheader(); writer.writerows(rows)
    csv_bytes = stream.getvalue().encode()
    receipt = dict(schema='selected-initial-history-v1', revision=REV, hardware='AMD EPYC Zen 5 dev host', campaign='FAILED',
        population=dict(functions=['first_equal', 'uppercase_count'], variants=['unstripped', 'stripped'], k=[10, 1000], n=2, epochs=520, references_pass=4, reference_calls=4052, installed_fail=4, installed_success=0),
        qualification=dict(architectural_state=False, performance=False, strict_2ms=False, arbitrary_abi=False),
        input_receipts=PINS, owners=owners, all_owner_cleanup_complete=True, all_owner_sources_unchanged=True,
        build=dict(revision=build['revision'], test_revision=test['revision'], products=build['products'], test_binary={k: test['binary'][k] for k in ('bytes', 'sha256')},
            tool_versions={k: v.splitlines()[0] for k, v in build['versions'].items()},
            commands=[public(json.loads(read(base / 'selected-session-build-v1' / row['name'] / 'request.json', row['request_sha256']))['argv']) for row in build['stages']],
            test_command=public(json.loads(read(base / 'selected-session-test-build-v1/request.json', test['members']['request.json']['sha256']))['argv'])),
        validation=validation, validation_threads=316, validation_wall_caps=[180, 180, 180, 900, 180],
        release_controls=dict(rust_pass=92, python_pass=94, stages=12, rust_filtered=365, python_suites=[[x['name'], x['count']] for x in controls['controls']['python']]),
        bounds=dict(outer_wall_seconds=1200, outer_log_bytes=8388608, cell_cpu_seconds=20, cell_wall_seconds=30, producer_wall_seconds=15, cell_stream_bytes=4194304, retries=0,
            build_cpu_seconds=120, build_wall_seconds=180, build_stream_bytes=134217728, capture_cpu_seconds=20, capture_wall_seconds=30, capture_stream_bytes=4194304),
        prior_wrong_revision_preflight=dict(status='FAILED', tests=0, reason='supplied revision mismatched actual HEAD before all phases'),
        cells=dict(bytes=len(csv_bytes), sha256=digest(csv_bytes)))
    receipt_bytes = (json.dumps(receipt, sort_keys=True, separators=(',', ':')) + '\n').encode()
    payload = receipt_bytes + csv_bytes + README.encode()
    require(b'/home/' not in payload and build['environment']['HOME'].split('/')[-1].encode() not in payload)
    if len(payload) > 16 * 1024:
        raise ValueError('public size cap: receipt=%d cells=%d readme=%d total=%d' % (len(receipt_bytes), len(csv_bytes), len(README.encode()), len(payload)))
    args.output.mkdir(parents=True, exist_ok=False)
    for name, data in (('receipt.json', receipt_bytes), ('cells.csv', csv_bytes), ('README.md', README.encode())):
        with (args.output / name).open('xb') as output: output.write(data)


if __name__ == '__main__':
    main()
