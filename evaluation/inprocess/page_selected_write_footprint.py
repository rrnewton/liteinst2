#!/usr/bin/env python3
"""Native write-footprint oracle; descriptive decoder results grant no execution."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_components import plain_executable
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT/'tools/page-entry/selected/tests/write_footprint'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def verify(data):
    need(len(data) == 1270344, 'complete fixed native record')
    header = struct.unpack_from('<11Q', data)
    need(header == (0x315057465032494c, 1, 184, 33400, 38, 38, 30, 8, 6, 0, 0), 'complete literal success header')
    need(data[88:136] == data[136:184], 'complete sealed allocator stats unchanged')
    rows = []
    for i in range(38):
        at = 184+i*33400
        row = struct.unpack_from('<8Q', data, at)
        need(row[:5] == (i, 1, 1, int(i < 26 or i >= 34), 1), 'every actual case/query/execution completed')
        pc, next_pc, first, end, version, policy, code, length = struct.unpack_from('<4Q4I', data, at+352)
        need(version == 1 and 0 < length <= 15 and next_pc == pc+length and
             (first, end) == row[6:8], 'actual footprint identity and expected bounds')
        need(policy in (0, 1, 2) and (policy != 0) == (i < 26 or i >= 34), 'explicit issued/refused split')
        if policy != 2:
            need(first == end == 0 and row[5] == 0, 'no range/no changed bytes for NONE/refusal')
        else:
            need(first < end, 'nonwrapping potential write interval')
        if i < 26 or i >= 34:
            need(data[at+64:at+208] == data[at+208:at+352], 'all actual pre-GPR/FS/GS equal query inputs')
        before, after = data[at+632:at+17016], data[at+17016:at+33400]
        changed = sum(a != b for a, b in zip(before, after, strict=True))
        need(changed == row[5], 'complete actual memory comparison extent')
        # The authenticated native C fixture independently checks literal ranges
        # and each complete expected memory image, including unchanged bytes.
        rows.append(dict(id=i, policy=policy, code=code, length=length,
                         potential_bytes=end-first, changed_bytes=changed, executed=bool(row[3])))
    palette_at = 184+38*33400
    ph = struct.unpack_from('<8Q', data, palette_at)
    need(ph[:3] == (0x31544c504632494c, 1, 960) and ph[3] >= 7 and ph[7] == 1 and
         ph[4] & 0x1c000000 == 0x1c000000 and ph[5] & 0x40010008 == 0x40010008 and
         ph[6] & 0xe7 == 0xe7, 'actual AVX512/BMI1 and OS-state qualification')
    palette = []
    for j, expected in enumerate((0x8000000180000081, 0x7ffffffe7fffff7e)):
        at = palette_at+64+j*448
        q = struct.unpack_from('<8Q', data, at)
        need(q == (34+j, expected, 0x0123456789abcdef, 0x0123456789abcdef, expected, 1, 1720, 6),
             'actual unmasked K1 equality result and seeded mask')
        a = bytes((i*13+3) & 255 for i in range(64))
        b = bytes(x if expected & (1 << i) else x ^ 0x5a for i, x in enumerate(a))
        need(all(data[at+64+k*128:at+64+(k+1)*128] == a+b for k in range(3)),
             'literal seeded and actually captured before/after ZMM16/ZMM17')
        palette.append(dict(id=34+j, expected_mask=expected, actual_before_mask=q[3], actual_after_mask=q[4]))
    for i in range(34, 38):
        at = 184+i*33400
        need(rows[i]['policy'] == 1 and rows[i]['potential_bytes'] == rows[i]['changed_bytes'] == 0 and
             rows[i]['code'] == (1720 if i < 36 else 3676) and rows[i]['length'] == (6 if i < 36 else 5),
             'exact-Code register-only NONE with full unchanged memory')
        before = struct.unpack_from('<16Q', data, at+208)
        after = struct.unpack_from('<16Q', data, at+472)
        raw = bytes.fromhex('62b1754074c8' if i < 36 else 'c4e2c8f3d6')
        need(data[at+616:at+616+len(raw)] == raw, 'actual exact instruction bytes')
        if i >= 36:
            need(before[6] == (0 if i == 36 else 0x23456789abcde000) and
                 after[6] == (0xffffffffffffffff if i == 36 else 0x3fff), 'literal actual BLSMSK register effect')
        need(all(x == y for reg, (x, y) in enumerate(zip(before, after, strict=True)) if i < 36 or reg != 6),
             'all unrelated actual GPRs unchanged')
    return dict(cases=38, actual_instructions=30, supplied_refusals=8, api_controls=6,
                old_cases=34, added_register_only_cases=4, palette=palette,
                sealed_stats_unchanged=True, rows=rows)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    args = parser.parse_args()
    need(sys.flags.optimize == 0 and re.fullmatch('[0-9a-f]{40}', args.expect_revision), 'exact revision and enabled checks')
    need(len(os.sched_getaffinity(0)) == 1, 'one externally reserved CPU')
    cpu = next(iter(os.sched_getaffinity(0)));os.chdir(ROOT)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-page-selected-write-footprint-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/name;private.mkdir(parents=True, exist_ok=False)
    public = ROOT/'evaluation/inprocess/results'/(name+'.json')
    r = dict(profile='page-selected-write-footprint-v1', status='failed', expected_revision=args.expect_revision,
             started_utc=stamp, cpu=cpu, source=None, source_unchanged=False, commands=[], error=None, final_errors=[],
             scope='Descriptive write footprints only. No rseq registration, RX owner, kernel/REP write coverage or performance claim.',
             reproduce=['python3', 'evaluation/inprocess/page_selected_write_footprint.py', '--expect-revision', args.expect_revision])
    pins, binaries = {}, {};builder = None
    def bind(path, table):
        p = Path(path).resolve();v = fact(p)
        need(str(p) not in table or table[str(p)] == v, 'immutable input/artifact')
        table[str(p)] = v;return p
    def pin(p): return bind(p, pins)
    def binary(p): return bind(p, binaries)
    def run(label, argv, expected=0, profile='native', env=None):
        need(all(fact(p) == v for p, v in pins.items()) and all(fact(p) == v for p, v in binaries.items()), 'pre-command byte closure')
        row = dict(name=label, argv=list(map(str, argv)), expected_exit=expected, profile=profile,
                   bounds=PROFILES[profile], capture_limit=8192 if profile == 'native' else 1 << 20,
                   environment=dict(ENV, **(env or {})))
        r['commands'].append(row)
        out, err = invoke(row, private, cpu, record=profile == 'native', step=profile == 'native')
        need(row['exit'] == expected, 'actual process outcome: '+label)
        return row, out, err
    try:
        r['source'] = source();need(r['source']['revision'] == args.expect_revision, 'revision differs')
        r['hardware'] = hardware(cpu)
        paths = subprocess.check_output(['git', 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'], timeout=5).split(b'\0')
        for p in paths:
            if p and not os.fsdecode(p).startswith('evaluation/inprocess/results/'): pin(ROOT/os.fsdecode(p))
        builder = Build(r, private, pin, binary, run);products = builder.prepare()
        run('fixture-build', [builder.tools['sh'], FIXTURE/'oracle-build.sh', products['archive'], private/'footprint-oracle',
                             ROOT/'tools/page-entry/selected'], profile='fixture_link', env=builder.environment)
        executable = binary(private/'footprint-oracle');r['elf'] = plain_executable(executable)
        _, out, err = run('fixture-undefined', [builder.tools['nm'], '-u', executable], profile='inspect', env=builder.environment)
        need(not out and not err, 'no unresolved fixture imports')
        row, out, err = run('native', [executable])
        expected = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())['commands'][0]
        need(out.decode() == expected['stdout'] and err == b'', 'exact native output')
        data = (private/'native.record').read_bytes();r['record'] = fact(private/'native.record')
        r['result'] = verify(data);r['status'] = 'passed'
    except BaseException as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        if builder is not None:
            try:
                r['final_errors'].extend(builder.finish())
                if r['status'] == 'passed': need(r['build']['status'] == 'passed', 'build closure')
            except BaseException as exc: r['final_errors'].append('build closure: '+repr(exc))
        try:
            fixture = private/'footprint-oracle'
            if fixture.is_file():
                r['fixture_after'] = fact(fixture)
                binary(fixture)
        except BaseException as exc:
            r['final_errors'].append('partial fixture retention: '+repr(exc))
        r['inputs_before'], r['binaries_before'] = pins, binaries
        for name, table in (('inputs_after', pins), ('binaries_after', binaries)):
            r[name] = {}
            for p, value in table.items():
                try:
                    r[name][p] = fact(p);need(r[name][p] == value, 'final byte closure')
                except BaseException as exc: r['final_errors'].append(p+': '+repr(exc))
        try:
            r['source_unchanged'] = source() == r['source'];need(r['source_unchanged'], 'source changed')
        except BaseException as exc: r['final_errors'].append('source: '+repr(exc))
        if r['final_errors']:
            r['status'] = 'failed'
            if r['error'] is None: r['error'] = 'FinalObservationError: closure failed'
        receipt = private/'receipt.json';save(receipt, r)
        b = r.get('build', {})
        output = {k: r.get(k) for k in ('profile', 'status', 'scope', 'expected_revision', 'started_utc', 'cpu', 'source',
                                       'source_unchanged', 'hardware', 'reproduce', 'result', 'record')}
        output.update(private_receipt=fact(receipt), command_count=len(r['commands']), command_rows_sha256=digest(r['commands']),
                      inputs_sha256=digest(pins), artifacts_sha256=digest(binaries), bounds=PROFILES, environment=ENV,
                      tool_versions=b.get('numeric_versions', {}), tool_hashes={k: {x: v[x] for x in ('bytes', 'sha256')}
                          for k, v in b.get('tools', {}).items()}, build_status=b.get('status', 'not_started'),
                      failure_type=(r.get('error') or '').split(':')[0] or None, final_error_count=len(r['final_errors']))
        text = json.dumps(output, sort_keys=True, indent=2, allow_nan=False)+'\n'
        need(not re.search(r'/home/|devbig[0-9]+|internalfb\.com', text), 'public location guard')
        with public.open('x') as f: f.write(text)
    print(json.dumps(dict(status=r['status'], result=r.get('result'), failure_type=(r.get('error') or '').split(':')[0] or None)))
    return int(r['status'] != 'passed')

if __name__ == '__main__':
    raise SystemExit(main())
