#!/usr/bin/env python3
"""Measure the unchanged serial launch command on one reserved CPU."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / 'evaluation/admission'))
import run as admission

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--expect-revision', required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
assert not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1
before = admission.source_state()
assert before['tracked_clean'] and before['head_sources_match']
assert before['revision'] == args.expect_revision
assert args.output.resolve().is_relative_to(ROOT / 'target/evaluation')
args.output.mkdir()
temporary = args.output / 'tmp'
temporary.mkdir()
env = admission.controlled_environment(os.environ, temporary)
config = admission.cargo_configuration(env)
corpus = json.loads((ROOT / 'evaluation/admission/corpus.json').read_bytes())
admission.core_cc846_inventory.require_current(corpus)
name, argv, seconds = admission.COMMANDS[-1]
assert name == 'serial_launch' and seconds == 180
record = dict(schema=1, profile='serial-affinity-diagnostic-v1',
              status='failed', revision=args.expect_revision,
              affinity=sorted(os.sched_getaffinity(0)), hardware=admission.hardware(),
              source={k: before[k] for k in ('revision', 'tree', 'source_manifest_sha256')},
              configuration=config, environment=admission.ENV,
              reproduce=[sys.executable, '-B', *sys.argv],
              qualification_credit=False, performance_credit=False,
              source_unchanged=False, configuration_unchanged=False, error=None)
command = dict(id=name, argv=argv, timeout_seconds=seconds,
               environment_delta={'LITEINST_EVALUATION': '1'})
record['command'] = command
try:
    log = args.output / 'serial_launch.log'
    command.update(admission.run_command(argv, env | command['environment_delta'], log, seconds))
    command['status'] = 'passed' if (command['exit_code'] == 0 and
        command['termination'] is None and command['cleanup_complete']) else 'failed'
    admission.command_evidence(command, log.read_text(errors='replace'), corpus)
    record['source_unchanged'] = admission.source_state() == before
    record['configuration_unchanged'] = admission.cargo_configuration(env) == config
    assert record['source_unchanged'] and record['configuration_unchanged']
    assert command['status'] == 'passed' and command['evidence_status'] == 'complete'
    assert len(command['harnesses']) == 27
    assert sum(r['outer']['passed'] for r in command['harnesses']) == 1039
    assert len(command['backing_cleanup_harnesses']) == 1
    assert admission.backing_cleanup_query.is_complete(command['backing_cleanup_harnesses'][0])
    record['status'] = 'passed'
except BaseException as error:
    record['error'] = repr(error)
finally:
    (args.output / 'receipt.json').write_text(json.dumps(record, sort_keys=True, indent=2)+'\n')
print(json.dumps(dict(status=record['status'], seconds=command.get('seconds'),
    receipt=str(args.output / 'receipt.json'))), flush=True)
raise SystemExit(record['status'] != 'passed')
