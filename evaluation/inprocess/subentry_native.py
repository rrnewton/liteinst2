#!/usr/bin/env python3
"""Bounded native execution from every head in a complete two-member graph."""
import argparse
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
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
EXPECTED = dict(schema=1, heads=68, source_pages=2, members=2,
    original_generated_pairs=4356, success_pairs=4352, fault_pairs=4,
    poisoned_spill_recoveries=4352, emitted_execution=1, owner_qualification=0)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    args = ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1, 'assertions and one reserved CPU')
    os.chdir(ROOT)
    cpu = next(iter(os.sched_getaffinity(0)))
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-subentry-native-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = ROOT/'evaluation/inprocess/results'/(name+'.json')
    receipt = private/'receipt.json'
    r = dict(schema=1, status='failed', revision=args.expect_revision, source=None,
             source_unchanged=False, cleanup_complete=False, commands=[], cases={},
             error=None, final_errors=[], hardware=hardware(cpu), bounds=PROFILES,
             scope='Every certified head: GPR/flags/full source,data,stack and raw faults; no full FP, page-owner or performance credit')
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
                    scalar_span=True, linked_epoch=True, mov_guard=True)

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
        exe = link('subentry-native', SELECTED/'tests/persistent_subentry_native/build.sh', archive)
        _, out, err = run('subentry-native', [exe], profile='component', env=builder.environment)
        need(not err, 'native component stderr')
        value = json.loads(out)
        need(type(value) is dict and value == EXPECTED, 'complete exact native component counts')
        r['cases']['subentry-native'] = value
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
        summary.update(receipt=fact(receipt),
            reproduce=['cpuset-alloc', 'run', '--cores', '1', '--', 'python3', '-B',
                       'evaluation/inprocess/subentry_native.py', '--expect-revision', args.expect_revision],
            tool_versions=builder.record.get('numeric_versions'), error_type=r['error'].split(':', 1)[0] if r['error'] else None,
            commands=[{k: c.get(k) for k in ('name', 'exit', 'duration_ns', 'timed_out', 'reaped', 'captures')}
                      for c in r['commands']])
        payload = (json.dumps(summary, sort_keys=True)+'\n').encode()
        need(len(payload) <= 32768 and b'/home/' not in payload, 'compact public receipt without host paths')
        public.write_bytes(payload)
        with public.with_suffix('.csv').open('w', newline='') as f:
            w = csv.writer(f, lineterminator='\n')
            w.writerow(('revision', 'command', 'exit', 'duration_ns', 'status'))
            for c in r['commands']:
                w.writerow((args.expect_revision, c['name'], c.get('exit'), c.get('duration_ns'), r['status']))
    print(json.dumps(dict(status=r['status'], receipt=str(public.relative_to(ROOT)))))
    return int(r['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
