#!/usr/bin/env python3
"""Pure rollout regression: run with invoke's 5CPU/15wall/512MiB/16MiB limits.

No compiler, Cargo, guest, shell recipe or historical reconstructed source runs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

sys.dont_write_bytecode = True
from page_selected import need, fact
from page_selected_register_time_build import recipe, expand
from page_selected_oneshot_build import commands
import page_selected_maps_recipe as selection
import page_selected_maps_sources as transport
import page_selected_maps_reset_sources as reset_transport

ROOT = Path(__file__).resolve().parents[2]
SELECTED = ROOT/'tools/page-entry/selected'
FLAGS = {None: ('-DLI2_MAPS_MAINTAINED=1',),
         'fresh-baseline': (), 'maintained': ('-DLI2_MAPS_MAINTAINED=1',),
         'differential': ('-DLI2_MAPS_MAINTAINED=1', '-DLI2_MAPS_DIFFERENTIAL=1')}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1,
         'assertions and separately reserved singleton')
    output = args.output.resolve()
    need(output.is_relative_to(ROOT/'target') and not output.exists(), 'fresh private pure-test output')
    output.mkdir()
    pins = {}; positives = []; refusals = []

    def pin(path):
        path = Path(path).resolve(strict=True); value = fact(path)
        need(str(path) not in pins or pins[str(path)] == value, 'same whole pure-test input')
        pins[str(path)] = value
        return path

    def reject(name, fn):
        try:
            fn()
        except ValueError:
            refusals.append(name)
        else:
            raise ValueError('accepted recipe control: '+name)

    for module in tuple(sys.modules.values()):
        name = getattr(module, '__file__', None)
        if name and Path(name).is_file() and Path(name).resolve().is_relative_to(ROOT):
            pin(name)
    transport.bind(pin)
    cc = Path('/compiler-not-executed')
    builder = SimpleNamespace(tools={'cc': cc}, environment={})
    archive, build = output/'decoder-not-built.a', output/'not-built'
    tails = []
    for script in selection.SCRIPTS:
        original = pin(SELECTED/script); text = original.read_text()
        tails.append(text.split(selection.BLOCK)[1])
        rows = recipe(original, '"$cc_bin"')
        values = {'$cc_bin': cc, '$source_dir': SELECTED, '$parent_dir': SELECTED.parent,
                  '$output_dir/decoder.a': archive, '$output_dir': build}
        baseline = [expand(row, values, ()) for row in rows[1:]]
        for profile, extra in FLAGS.items():
            builder.environment = {}
            result = selection.configure(builder.environment, profile)
            need(result == dict(requested=profile, effective='maintained' if profile is None else profile,
                                implicit_default=profile is None), 'exact explicit/default selection record')
            need(('LI2_MAPS_PROFILE' not in builder.environment) == (profile is None),
                 'implicit default is genuinely absent, never an explicit alias')
            expected = [list(x) for x in baseline]
            at = expected[0].index('-DLI2_MAPS_PHASE_REUSE=1')+1
            expected[0][at:at] = extra
            actual = commands(original, builder, build, archive, pin)
            need(actual == expected and all('$' not in x for row in actual for x in row),
                 'whole two actual C argv equal independent literal profile insertion')
            positives.append(script+':'+str(profile))
        for value in ('', 'unknown', True, 1):
            builder.environment = {'LI2_MAPS_PROFILE': value}
            reject(script+':environment:'+repr(value),
                   lambda: commands(original, builder, build, archive, pin))
        builder.environment = {}
        mutations = {
            'block_missing': text.replace(selection.BLOCK, ''),
            'block_duplicate': text.replace(selection.BLOCK, selection.BLOCK*2),
            'default_syntax': text.replace('${LI2_MAPS_PROFILE-maintained}', '${LI2_MAPS_PROFILE:-maintained}'),
            'wrong_mode_flag': text.replace('maintained) set -- -DLI2_MAPS_MAINTAINED=1', 'maintained) set --'),
            'tail_byte': text+'# changed tail\n',
            'missing_extra': text.replace('=1 "$@" -I', '=1 -I'),
            'duplicate_extra': text.replace('=1 "$@" -I', '=1 "$@" "$@" -I'),
            'extra_second': text.replace('"$cc_bin" -std=gnu11 -O2 -g -Wall', '"$cc_bin" "$@" -std=gnu11 -O2 -g -Wall'),
            'late_assignment': text.replace(selection.BLOCK, selection.BLOCK+'set --\n'),
            'prefix_override': text.replace(selection.BLOCK, 'LI2_MAPS_PROFILE=fresh-baseline\n'+selection.BLOCK),
            'extra_cc_row': text+'"$cc_bin" --version\n',
            'truncated_tail': text[:-1],
        }
        with tempfile.TemporaryDirectory(prefix='recipes-', dir=output) as directory:
            for name, changed in mutations.items():
                need(changed != text, 'actual distinct recipe mutation')
                path = Path(directory)/script; path.write_text(changed)
                reject(script+':'+name, lambda: commands(path, builder, build, archive, lambda p: Path(p)))
            path = Path(directory)/'unknown.sh'; path.write_text(text)
            reject(script+':unknown_positional_recipe',
                   lambda: commands(path, builder, build, archive, lambda p: Path(p)))
    need(tails[0] == tails[1] == tails[2], 'whole 8/11/13 source C tails remain identical')
    for value in ('', 'unknown', 1, True, (), {}):
        reject('configure:'+repr(value), lambda: selection.configure({}, value))
    for value in ('fresh-baseline', 'maintained', 'differential'):
        reject('inherited:'+value, lambda: selection.configure({'LI2_MAPS_PROFILE': value}, None))
    need(len(positives) == 12 and len(refusals) == len(set(refusals)) == 60,
         'all twelve exact profiles and sixty causal recipe refusals')

    # Every listed original source endpoint must reconstruct as a whole. Actual
    # current facts stay current; these are static-source comparisons only.
    table = json.loads(pin(transport.DATA).read_bytes())
    endpoints = []; inverse_refusals = []
    for relative, row in table['sources'].items():
        path = pin(ROOT/relative); raw = path.read_bytes()
        for target in row['targets'].values():
            want = target['fact']
            need(transport.historical(path, want, fact(path)) == want,
                 'whole current source reconstructs the unchanged requested endpoint')
            endpoints.append((relative, want['sha256']))
        for label, spans, expected in (
                ('missing', [], row['donor']),
                ('order', [[1, 0, 'x']], row['donor']),
                ('range', [[0, len(raw)+1, 'x']], row['donor']),
                ('target', row['inverse'], dict(bytes=row['donor']['bytes'], sha256='0'*64))):
            try:
                transport.inverse(raw, spans, expected)
            except ValueError:
                inverse_refusals.append(relative+':'+label)
            else:
                raise ValueError('accepted source inverse control: '+relative+':'+label)
    need(len(endpoints) == len(set(endpoints)) == 32 and len(inverse_refusals) == 112,
         'all thirty-two source endpoints and four controls for each28 changed sources')
    # Additional exact reset/RX/TLS endpoints. Original table cases above remain.
    reset_endpoints = []; reset_refusals = []
    def reject_reset(name, call):
        try:
            call()
        except ValueError:
            reset_refusals.append(name)
        else:
            raise ValueError('accepted reset source control: '+name)
    need(len(reset_transport.SOURCES) == 9, 'all nine exact reset/RX/TLS/transit source rows')
    for relative, row in reset_transport.SOURCES.items():
        path = pin(ROOT/relative); raw = path.read_bytes(); observed = fact(path)
        need(observed == row['current'], 'actual current reset/RX/TLS source fact')
        wants = [row['prior']] + [target['fact'] for target in row['targets'].values()]
        for want in wants:
            need(reset_transport.historical(relative, want, observed, raw) == want,
                 'whole exact reset/RX/TLS historical endpoint')
            reset_endpoints.append((relative, want['sha256']))
        for label, edits, expected in (
                ('missing', [], row['prior']),
                ('order', [[1, 0, 'x']], row['prior']),
                ('range', [[0, len(raw)+1, 'x']], row['prior']),
                ('target', row['inverse'], dict(bytes=row['prior']['bytes'], sha256='0'*64))):
            reject_reset(relative+':'+label,
                         lambda: transport.inverse(raw, edits, expected))
        reject_reset(relative+':current_byte', lambda: reset_transport.historical(
            relative, row['prior'], observed, raw+b'# changed current source\n'))
        reject_reset(relative+':unknown_endpoint', lambda: reset_transport.historical(
            relative, dict(bytes=row['prior']['bytes'], sha256='0'*64), observed, raw))
    need(len(reset_endpoints) == len(set(reset_endpoints)) == 10 and
         len(reset_refusals) == len(set(reset_refusals)) == 54,
         'all ten exact additional endpoints and fifty-four causal refusals')
    need(all(fact(path) == before for path, before in pins.items()), 'whole input closure')
    result = dict(schema=1, scope='pure recipe/source transport only',
                  profile_argv=12, recipe_refusals=60, source_endpoints=32, inverse_refusals=112,
                  reset_source_endpoints=10, reset_source_refusals=54,
                  source_inputs=pins, subjects=0, builds=0, qualification_credit=False)
    (output/'result.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'source_inputs'}, separators=(',', ':')))


if __name__ == '__main__':
    main()
