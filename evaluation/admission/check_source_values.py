#!/usr/bin/env python3
"""Run the fixed source-value controls; this is not the required recorder gate."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'evaluation/admission'
sys.path.insert(0, str(HERE))
import run as admission
from processes import run_command

PINS = {
    'inventory_regex.py': '031f5c9332cff56a06de905181b7e262962591f67be4a7554523a3f54f4e6fc6',
    'inventory_regex_controls.py': '03c551d6be8a382b80264e96a93693ec9844ba4200c42a339262d9af44b7932c',
    'inventory_digest.py': '1453fa84f3603c03ff9ce3861e797b68d7f879b7c172dbc8fce3d55a64d2f59c',
    'inventory_digest_controls.py': '78487b64b234d5e6cce6971d51af4b2e8f64e0f235031be5bce65154c2c29367',
    'core_97ab_inventory.py': '1e3d7f40c6ba1bbf44c52aa25badd79821d1c14aa3db93ef7adff0bc7517941b',
    'compare_catalog_walk.py': '6c77563cd7273feef1c83e33163c72ece80e51008efb4824cfb5cb360eae4309',
}
SCHEDULE = (('inventory_regex_controls', 'RegexValueControls', 10),
            ('inventory_digest_controls', 'DigestControls', 6),
            ('compare_catalog_walk', None, 82))
BOUNDS = dict(cpu_seconds=30, wall_seconds=60, address_space_bytes=512 << 20,
              file_size_bytes=16 << 20, log_bytes=8 << 20)
WALK_RESULT = dict(status='passed_differential_only', comparisons=82,
                   original_comparisons=74, metadata_comparisons=8,
                   fresh_graph_per_call=True, qualification_credit=False)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def fact(path):
    path = Path(path)
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                mode=stat.S_IMODE(path.stat().st_mode))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    parser.add_argument('--cpu', type=int, required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and
         re.fullmatch(r'[0-9a-f]{40}', args.expect_revision) and
         Path.cwd().resolve() == ROOT and os.sched_getaffinity(0) == {args.cpu},
         'exact Python, revision, natural root and reserved singleton')
    output = Path(args.output).resolve()
    need(output.is_relative_to(ROOT / 'target/evaluation') and
         output != ROOT / 'target/evaluation' and not output.exists(), 'fresh private output')
    before = admission.source_state()
    need(before['revision'] == args.expect_revision and before['tracked_clean'] and
         before['head_sources_match'], 'exact clean installed source')
    inputs, aliases = {}, {}
    for path in [Path(__file__), Path(sys.executable), Path('/usr/bin/prlimit'),
                 Path('/usr/bin/git'), Path(re.__file__), HERE/'run.py',
                 HERE/'processes.py', *(HERE / name for name in PINS)]:
        lexical = path.absolute()
        actual = lexical.resolve(strict=True)
        aliases[str(lexical)] = str(actual)
        inputs[str(actual)] = fact(actual)
    for name, expected in PINS.items():
        need(inputs[str((HERE/name).resolve())]['sha256'] == expected and
             before['source_sha256'].get('evaluation/admission/' + name) == expected,
             'exact installed control/helper source')
    need(before['source_sha256'].get('evaluation/admission/check_source_values.py') ==
         fact(__file__)['sha256'], 'installed reproducer is a tracked source')
    output.mkdir(); (output/'tmp').mkdir()
    env = admission.controlled_environment(os.environ, output/'tmp') | {'PYTHONPATH': str(HERE)}
    configuration = admission.cargo_configuration(env)
    receipt = dict(schema=1, profile='source-value-controls-v1', status='failed',
                   revision=args.expect_revision, cpu=args.cpu, source=before,
                   hardware=admission.hardware(), driver=fact(__file__), environment=env,
                   configuration=configuration, inputs=inputs, aliases=aliases, bounds=BOUNDS,
                   commands=[], error=None, final_errors=[], source_unchanged=False,
                   inputs_unchanged=False, artifacts_unchanged=False,
                   configuration_unchanged=False, cleanup_complete=False,
                   recorder_gate_credit=False, qualification_credit=False, performance_credit=False)
    try:
        for module, class_name, count in SCHEDULE:
            path = HERE/(module + '.py')
            expected = None
            if class_name:
                classes = [n for n in ast.parse(path.read_bytes()).body
                           if isinstance(n, ast.ClassDef) and n.name == class_name]
                need(len(classes) == 1, 'exact control class')
                methods = sorted(n.name for n in classes[0].body
                                 if isinstance(n, ast.FunctionDef) and n.name.startswith('test_'))
                need(len(methods) == count, 'fixed control method population')
                expected = [f'{name} ({module}.{class_name}.{name}) ... ok' for name in methods]
            command = (['-m', 'unittest', '-v', module] if class_name else [str(path)])
            argv = ['/usr/bin/prlimit', '--cpu=30:30', '--as=536870912:536870912',
                    '--fsize=16777216:16777216', sys.executable, '-B', *command]
            row = dict(id=module, expected_count=count, argv=argv, status='failed')
            receipt['commands'].append(row)
            log = output/(module + '.log')
            row['result'] = run_command(argv, env, log, 60, max_log_bytes=8 << 20)
            row['log'] = fact(log)
            result = row['result']
            need(result['exit_code'] == 0 and result['termination'] is None and
                 result['cleanup_complete'] is True and result['reaped_descendants'] == 0 and
                 result['private_log_sha256'] == row['log']['sha256'], 'whole successful child closure')
            text = log.read_text()
            if class_name:
                lines = text.splitlines()
                need([line for line in lines if line.startswith('test_')] == expected and
                     re.findall(r'^Ran (\d+) tests in [0-9.]+s$', text, re.M) == [str(count)] and
                     lines[-1:] == ['OK'] and lines.count('OK') == 1,
                     'all exact controls passed without skip or relabel')
            else:
                need(json.loads(text) == WALK_RESULT, 'all original 82 comparisons')
            row['status'] = 'passed'
            admission.write_result(output/'receipt.json', receipt)
        receipt['status'] = 'passed_controls_only'
    except BaseException as error:
        receipt['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        for field, check in (
            ('source_unchanged', lambda: admission.source_state() == before and
             os.sched_getaffinity(0) == {args.cpu}),
            ('configuration_unchanged', lambda: admission.cargo_configuration(env) == configuration),
            ('artifacts_unchanged', lambda: all(
             fact(output/(row['id'] + '.log')) == row['log']
             for row in receipt['commands'] if 'log' in row)),
            ('inputs_unchanged', lambda: all(fact(p) == value for p, value in inputs.items()) and
             all(str(Path(p).resolve(strict=True)) == value for p, value in aliases.items()))):
            try:
                receipt[field] = bool(check())
                need(receipt[field], field)
            except BaseException as error:
                receipt['final_errors'].append(type(error).__name__ + ': ' + str(error))
        receipt['cleanup_complete'] = bool(receipt['commands']) and all(
            row.get('result', {}).get('cleanup_complete') is True for row in receipt['commands'])
        if receipt['error'] or receipt['final_errors'] or not receipt['cleanup_complete']:
            receipt['status'] = 'failed'
        admission.write_result(output/'receipt.json', receipt)
    print(json.dumps(dict(status=receipt['status'], commands=len(receipt['commands']),
                          error=receipt['error'], final_errors=receipt['final_errors'],
                          receipt=fact(output/'receipt.json'))), flush=True)
    return int(receipt['status'] != 'passed_controls_only')


if __name__ == '__main__':
    raise SystemExit(main())
