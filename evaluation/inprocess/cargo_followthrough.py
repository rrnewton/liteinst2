#!/usr/bin/env python3
"""Reproduce the five Cargo/serial checks only; never qualify the required gate.

Run from a clean checkout on four reserved CPUs, with Python 3.12 and the
toolchain on an absolute PATH. The output directory must be fresh under target/.
This standalone entrypoint may live outside the checkout being measured.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--expect-revision', required=True)
ap.add_argument('--output', type=Path, required=True)
a = ap.parse_args()
ROOT = Path.cwd().resolve()
assert sys.version_info[:2] == (3, 12) and not sys.flags.optimize
assert len(a.expect_revision) == 40 and all(c in '0123456789abcdef' for c in a.expect_revision)
assert len(os.sched_getaffinity(0)) == 4
out = a.output.resolve()
assert out.is_relative_to(ROOT/'target') and out != ROOT/'target'
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
import checks

source = checks.source()
assert source['revision'] == a.expect_revision
commands = [row for row in checks.COMMANDS if row[0] != 'recorder_tests']
assert commands == [
    ('fmt', ['cargo', 'fmt', '--check'], 180),
    ('clippy', ['cargo', 'clippy', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'], 180),
    ('workspace_tests', ['cargo', 'test', '--workspace'], 900),
    ('workspace_check', ['cargo', 'check', '--workspace', '--all-features', '--all-targets'], 180),
    ('serial_launch', ['cargo', 'test', '-p', 'liteinst-launch', '--tests', '--', '--test-threads=1', '--nocapture'], 180),
]
out.mkdir()
scratch = out/'tmp'
scratch.mkdir()
env = checks.admission.controlled_environment(os.environ, scratch)
corpus = json.loads((ROOT/'evaluation/admission/corpus.json').read_bytes())
checks.admission.core_cc846_inventory.require_current(corpus)
r = dict(schema=1, scope='Four required Cargo checks plus serial only. '
    'The recorder is not run; this does not qualify or replace the whole required-check gate.',
    source=source, hardware=checks.hardware(min(os.sched_getaffinity(0))),
    configuration=checks.admission.cargo_configuration(env), commands=[], status='running',
    whole_profile_qualified=False, source_unchanged=False, configuration_unchanged=False)


def save():
    (out/'receipt.json').write_text(json.dumps(r, sort_keys=True, indent=2)+'\n')


save()
try:
    for name, argv, seconds in commands:
        assert int(subprocess.check_output(['du', '-sx', '-B1', '.']).split()[0]) < 20_000_000_000
        delta = {'LITEINST_EVALUATION': '1'} if name == 'serial_launch' else {}
        row = dict(id=name, argv=argv, timeout_seconds=seconds, environment_delta=delta)
        row.update(checks.admission.run_command(argv, env|delta, out/(name+'.log'), seconds))
        row['status'] = 'passed' if row['exit_code'] == 0 and row['termination'] is None and row['cleanup_complete'] else 'failed'
        checks.admission.command_evidence(row, (out/(name+'.log')).read_text(errors='replace'), corpus)
        r['commands'].append(row)
        save()
        print(json.dumps({k: row[k] for k in ('id', 'status', 'exit_code', 'seconds')}), flush=True)
    r['source_unchanged'] = checks.source() == source
    r['configuration_unchanged'] = checks.admission.cargo_configuration(env) == r['configuration']
    r['status'] = 'passed_cargo_and_serial_only' if len(r['commands']) == 5 and all(x['status'] == 'passed' for x in r['commands']) and r['source_unchanged'] and r['configuration_unchanged'] else 'failed'
except BaseException as e:
    r['error'] = type(e).__name__+': '+str(e)
    r['status'] = 'failed'
finally:
    save()
print(json.dumps(dict(output=str(out), status=r['status'], source_unchanged=r['source_unchanged'])), flush=True)
raise SystemExit(r['status'] != 'passed_cargo_and_serial_only')
