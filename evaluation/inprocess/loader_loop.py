#!/usr/bin/env python3
"""Bounded ADD primitive and whole-loader-graph validation; no startup timing."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_register_time_build import recipe, expand, headers

ROOT = Path(__file__).resolve().parents[2]
SELECTED = ROOT/'tools/page-entry/selected'
PROFILES = dict(BUILD_PROFILES, component=[5, 512 << 20, 16 << 20, 15])
ELF_SHA = '34c232018a619b0091e97add6805072d00db3250937fc049a1ef968cecfa99c9'
PAIR_SHA = 'd581910c998f52887ed76623d2280e52d178a4d25d46001d64586bd2c8ddf7ab'
RESULTS = {
    'add-model': dict(schema=1, add_codes=1, descriptors=349, byte_models=5096,
        refusals=20, corruptions=21, interval_edges=465, max_tree_height=8,
        postseal_equal=1, emitted_instruction_execution=0),
    'add-native': dict(schema=1, original_generated_pairs=402, success_pairs=386,
        fault_pairs=16, postseal_equal=1, emitted_instruction_execution=1,
        production_qualification=0),
}


def extract(path, output):
    data = path.read_bytes()
    need(len(data) == 939216 and hashlib.sha256(data).hexdigest() == ELF_SHA,
         'exact reference interpreter; a different ELF needs separate qualification')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:3] == (3, 62), 'reference ELF64 ET_DYN')
    ph = [struct.unpack_from('<IIQQQQQQ', data, h[5]+i*h[9]) for i in range(h[10])]
    need(sum(p[0] == 1 and p[1] == 5 and p[2] == p[3] and
             p[3] <= 0x10000 and p[3]+p[5] >= 0x12000 for p in ph) == 1,
         'whole file-backed executable source pair')
    rows = 0
    for i in range(h[12]):
        s = struct.unpack_from('<IIQQQQIIQQ', data, h[6]+i*h[11])
        if s[1] in (4, 9):
            need(s[9] in (16, 24) and s[5] % s[9] == 0, 'complete relocation rows')
            for at in range(s[4], s[4]+s[5], s[9]):
                need(not 0x10000 <= struct.unpack_from('<Q', data, at)[0] < 0x12000,
                     'no ELF relocation target in the source pair')
                rows += 1
    pair = data[0x10000:0x12000]
    need(rows == 143 and hashlib.sha256(pair).hexdigest() == PAIR_SHA, 'exact complete pair')
    output.write_bytes(pair)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--interpreter', type=Path, default=Path('/usr/lib64/ld-linux-x86-64.so.2'))
    args = ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1, 'assertions and one reserved CPU')
    os.chdir(ROOT)
    cpu = next(iter(os.sched_getaffinity(0)))
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-loader-loop-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = ROOT/'evaluation/inprocess/results'/(name+'.json')
    receipt = private/'receipt.json'
    r = dict(schema=1, status='failed', revision=args.expect_revision, source=None,
             source_unchanged=False, cleanup_complete=False, commands=[], cases={},
             error=None, final_errors=[], hardware=hardware(cpu), bounds=PROFILES,
             scope='ADD primitive and descriptive whole loader graphs; no page-owner or performance credit')
    pins, artifacts, aliases = {}, {}, {}

    def pin(path):
        p = Path(path).resolve(strict=True)
        value = fact(p)
        need(str(p) not in pins or pins[str(p)] == value, 'stable input')
        pins[str(p)] = value
        return p

    def binary(path):
        p = Path(path).resolve(strict=True)
        value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable artifact')
        artifacts[str(p)] = value
        return p

    def closure():
        need(all(fact(p) == v for p, v in pins.items()), 'input bytes unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v
                 for p, v in artifacts.items()), 'artifact bytes and modes unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'input aliases unchanged')

    def run(label, argv, profile='metadata', env=None):
        closure()
        row = dict(name=label, argv=list(map(str, argv)), bounds=PROFILES[profile],
                   expected_exit=0, capture_limit=16 << 20, environment=dict(ENV if env is None else env))
        need(not any(c['name'] == label for c in r['commands']), 'unique command label')
        r['commands'].append(row)
        save(receipt, r)
        out, err = invoke(row, private, cpu)
        save(receipt, r)
        need(row['exit'] == 0, 'exact command exit '+label)
        return row, out, err

    builder = Build(r, private, pin, binary, run, ('region.rs',),
                    scalar_span=True, linked_epoch=True, mov_guard=True, add_guard=True)

    def link(label, script, archive, extra=()):
        script = pin(script)
        output = private/label
        rows = recipe(script, '"$cc_bin"')
        need(len(rows) == 1, 'one literal component link recipe')
        argv = expand(rows[0], {'$cc_bin': builder.tools['cc'], '$selected': SELECTED,
            '$fixture': script.parent, '$archive': archive, '$output': output}, extra)
        units = [x for x in argv if x.endswith(('.c', '.S'))]
        for unit in units:
            pin(unit)
        state = r.setdefault('links', {})[label] = dict(recipe=fact(script), argv=argv)
        headers(label+'-headers', argv, units, archive, builder, pin, aliases, run, state)
        _, _, err = run(label+'-build', argv, profile='metadata', env=builder.environment)
        need(not err, 'component build stderr')
        return binary(output)

    try:
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision, 'exact clean revision')
        archive = builder.prepare()['archive']
        pair = private/'source-pair.bin'
        interpreter = pin(args.interpreter)
        extract(interpreter, pair)
        binary(pair)
        r['interpreter'] = fact(interpreter)
        r['pair'] = fact(pair)
        for label, script in (('add-model', 'build.sh'), ('add-native', 'build-native.sh')):
            exe = link(label, SELECTED/'tests/linked_add_guard'/script, archive)
            _, out, err = run(label, [exe], profile='component', env=builder.environment)
            need(not err, 'component stderr')
            value = json.loads(out)
            need(type(value) is dict and value == RESULTS[label], 'complete exact component result')
            r['cases'][label] = value
        for mode in ('baseline', 'add'):
            extra = ['-DLI2_ADD_GUARD=1', str(SELECTED/'linked_add_guard.c')] if mode == 'add' else []
            exe = link('planner-'+mode, SELECTED/'tests/loader_loop/build.sh', archive, extra)
            _, out, err = run('planner-'+mode, [exe, pair, '400000'], profile='component', env=builder.environment)
            need(not err, 'planner stderr')
            values = [json.loads(line) for line in out.splitlines()]
            need([v['root_offset'] for v in values] == [0x1002e, 0x102c8] and
                 all(v['result'] == 0 and v['ready'] == 1 and v['plan_validate'] == 0 and
                     v['compact_build'] == 0 and v['compact_validate'] == 0 for v in values),
                 'both complete graphs and reconstructions')
            r['cases']['planner-'+mode] = [{k: v[k] for k in
                ('root_offset', 'result', 'ready', 'heads', 'exits', 'stores', 'links', 'source_bytes',
                 'source_mask', 'plan_validate', 'compact_build', 'compact_validate')} for v in values]
        r['status'] = 'passed'
    except BaseException as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        r['final_errors'].extend(builder.finish())
        try:
            closure()
            need(source() == r['source'], 'exact source unchanged')
            r['source_unchanged'] = True
        except BaseException as exc:
            r['final_errors'].append(type(exc).__name__+': '+str(exc))
        r['cleanup_complete'] = all(c.get('reaped') and not c.get('cleanup_errors') and
            all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r['inputs'] = pins
        r['artifacts'] = artifacts
        save(receipt, r)
        summary = {k: r[k] for k in ('schema', 'status', 'revision', 'source', 'source_unchanged',
            'cleanup_complete', 'hardware', 'bounds', 'scope', 'cases')}
        summary.update(receipt=fact(receipt), interpreter=r.get('interpreter'), pair=r.get('pair'),
            reproduce=['python3', 'evaluation/inprocess/loader_loop.py', '--expect-revision', args.expect_revision,
                       '--interpreter', 'REFERENCE_INTERPRETER'],
            tool_versions=builder.record.get('numeric_versions'), error_type=r['error'].split(':', 1)[0] if r['error'] else None,
            commands=[{k: c.get(k) for k in ('name', 'exit', 'duration_ns', 'timed_out', 'reaped', 'captures')}
                      for c in r['commands']])
        payload = (json.dumps(summary, sort_keys=True)+'\n').encode()
        need(len(payload) <= 32768 and b'/home/' not in payload, 'compact public receipt without host paths')
        public.write_bytes(payload)
        with public.with_suffix('.csv').open('w', newline='') as f:
            w = csv.writer(f)
            w.writerow(('revision', 'command', 'exit', 'duration_ns', 'status'))
            for c in r['commands']:
                w.writerow((args.expect_revision, c['name'], c.get('exit'), c.get('duration_ns'), r['status']))
    print(json.dumps(dict(status=r['status'], receipt=str(public.relative_to(ROOT)))))
    return int(r['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
