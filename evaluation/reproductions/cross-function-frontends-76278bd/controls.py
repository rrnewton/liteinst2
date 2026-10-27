#!/usr/bin/env python3
"""Real saved projection plus four synthetic refusals; never mutate actual raw files."""
import argparse
import contextlib
import io
import hashlib
import json
from pathlib import Path
import runpy
import sys
import traceback

COLLECTOR_SHA = 'a917b61f00df9c6aeaa32dc9b543ef9f500d48ef6e01b7e5472ca104f4a274e7'


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--collector', type=Path, required=True)
    ap.add_argument('--inputs', type=Path, required=True)
    ap.add_argument('--inputs-sha256', required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    INPUTS_SHA = a.inputs_sha256
    digest = lambda b: hashlib.sha256(b).hexdigest()
    source, supplied = a.collector.read_bytes(), a.inputs.read_bytes()
    assert digest(source) == COLLECTOR_SHA and digest(supplied) == INPUTS_SHA
    spec = json.loads(supplied)
    assert a.out.is_absolute() and a.out.parent.resolve(strict=True) == a.out.parent and not a.out.exists()
    assert a.out.is_relative_to(Path(spec['repo']) / 'ignored')
    a.out.mkdir(mode=0o700)
    selected_log = Path(spec['raw']) / 'targeted/command.log'
    original_log = selected_log.read_bytes()
    records = []
    for name, message in [('missing-pass-log', 'PASS phase requires complete command.log'),
                          ('missing-pass-inventory', 'successful tests require their complete reviewed inventory')]:
        caller = a.inputs
        if name == 'missing-pass-inventory':
            clone = json.loads(supplied)
            clone['phases']['targeted']['inventory'] = None
            caller = a.out / 'missing-inventory-inputs.json'
            caller.write_text(json.dumps(clone, sort_keys=True, indent=2) + '\n')
        caller_bytes = caller.read_bytes()
        output = a.out / (name + '-output')
        previous_argv = sys.argv
        previous_is_file = Path.is_file
        sys.argv = [str(a.collector), '--inputs', str(caller), '--inputs-sha256', digest(caller_bytes),
                    '--new-output', str(output)]
        if name == 'missing-pass-log':
            Path.is_file = lambda path: False if path == selected_log else previous_is_file(path)
        try:
            try:
                runpy.run_path(str(a.collector), run_name='__main__')
            except AssertionError as error:
                frames = traceback.extract_tb(error.__traceback__)
                assert str(error) == message
                assert Path(frames[-1].filename) == a.collector
                assert frames[-1].line.endswith(repr(message)) or frames[-1].line.endswith('"' + message + '"')
                assert frames[-1].line.lstrip().startswith('assert ')
                records.append(dict(name=name, status='EXPECTED_ASSERTION_REFUSAL', message=message,
                                    source_line=frames[-1].lineno, assertion=frames[-1].line,
                                    traceback=traceback.format_exc(), output_absent=not output.exists()))
            else:
                raise AssertionError('synthetic omission incorrectly accepted')
        finally:
            sys.argv = previous_argv
            Path.is_file = previous_is_file
        assert not output.exists()
        assert selected_log.read_bytes() == original_log and a.inputs.read_bytes() == supplied
        assert a.collector.read_bytes() == source
    # The original two omission controls above remain literal.
    previous_argv = sys.argv
    output = a.out / 'real-positive-output'
    sys.argv = [str(a.collector), '--inputs', str(a.inputs), '--inputs-sha256', INPUTS_SHA,
                '--new-output', str(output)]
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            runpy.run_path(str(a.collector), run_name='__main__')
    finally:
        sys.argv = previous_argv
    complete = json.loads((output / 'collection.json').read_bytes())
    assert complete['completed'] is True
    assert json.loads(captured.getvalue()) == complete
    observed = json.loads((output / 'public/groups.json').read_bytes())
    targeted = [row for row in observed if row['command'] == 'targeted']
    cases = json.loads((output / 'public/cases.json').read_bytes())
    assert len(targeted) == 8 and len([row for row in cases if row['command'] == 'targeted']) == 133
    for name in ('check_elf_tactic_refusals', 'verify_elf_exec', 'verify_elf_tactics'):
        match = [row for row in targeted if row['group'] == 'unit/' + name + '/' + name]
        assert len(match) == 1 and all(value == 0 for value in match[0]['counts'].values())
    parsed = json.loads((output / 'public/parser-results.json').read_bytes())
    assert next(row for row in parsed if row['command'] == 'targeted')['public_parser'] == 'invalid_harness_binary_path'
    records.append(dict(name='real-complete-projection', status='PASS_SAVED_REPORT_PROJECTION', targeted_groups=8,
                        targeted_cases=133, zero_examples=3, unchanged_parser_error_retained=True))
    # Synthetic copied metadata deliberately changes only the reviewed group field.
    # Actual caller, logs, inventories and source remain byte-identical.
    description = spec['phases']['targeted']['inventory']
    original_metadata = {key: Path(path).read_bytes() for key, path in description.items()}
    for name, message, origin in [
            ('malformed-example-source-binary', 'malformed or ambiguous targeted example identity', 'reviewed_harness_id'),
            ('ambiguous-duplicate-example', '', 'inventory')]:
        fixture = a.out / name
        fixture.mkdir()
        group_rows = json.loads(original_metadata['groups'])
        checks = json.loads(original_metadata['checks'])
        binding = json.loads(original_metadata['binding'])
        group = next(row for row in group_rows if 'examples/check_elf_tactic_refusals.rs ' in row['header'])
        if name == 'malformed-example-source-binary':
            group['header'] = group['header'].replace('examples/check_elf_tactic_refusals-', 'examples/verify_elf_exec-')
        else:
            group_rows.append(json.loads(json.dumps(group)))
            checks['outer_groups'] += 1
        clone = json.loads(supplied)
        paths = dict(groups=fixture / 'test-groups.json', checks=fixture / 'checks.json', binding=fixture / 'binding.json')
        for key, value in [('groups', group_rows), ('checks', checks)]:
            data = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
            paths[key].write_bytes(data)
            binding['files'][paths[key].name] = dict(sha256=digest(data), bytes=len(data))
        paths['binding'].write_text(json.dumps(binding, sort_keys=True, indent=2) + '\n')
        for key, path in paths.items():
            data = path.read_bytes()
            clone['files'][str(path)] = dict(sha256=digest(data), bytes=len(data))
        clone['phases']['targeted']['inventory'] = {key: str(path) for key, path in paths.items()}
        caller = fixture / 'inputs.json'
        caller.write_text(json.dumps(clone, sort_keys=True, indent=2) + '\n')
        output = fixture / 'output'
        previous_argv = sys.argv
        sys.argv = [str(a.collector), '--inputs', str(caller), '--inputs-sha256', digest(caller.read_bytes()),
                    '--new-output', str(output)]
        try:
            try:
                runpy.run_path(str(a.collector), run_name='__main__')
            except AssertionError as error:
                frames = traceback.extract_tb(error.__traceback__)
                assert str(error) == message and Path(frames[-1].filename) == a.collector
                assert frames[-1].name == origin
                if name == 'ambiguous-duplicate-example':
                    assert frames[-1].line.endswith('assert gid is not None and gid not in expected')
                else:
                    assert frames[-1].line.endswith(repr(message))
                records.append(dict(name=name, status='EXPECTED_ASSERTION_REFUSAL', message=message,
                                    source_line=frames[-1].lineno, assertion=frames[-1].line,
                                    traceback=traceback.format_exc(), output_absent=not output.exists()))
            else:
                raise AssertionError('synthetic header incorrectly accepted')
        finally:
            sys.argv = previous_argv
        assert not output.exists()
    assert selected_log.read_bytes() == original_log and a.inputs.read_bytes() == supplied
    assert a.collector.read_bytes() == source
    assert all(Path(description[key]).read_bytes() == data for key, data in original_metadata.items())
    result = dict(completed=True, controls=records, actual_raw_mutations=0,
                  source_sha256=COLLECTOR_SHA, inputs_sha256=INPUTS_SHA,
                  scope='saved reporting positive and synthetic refusal controls only; no validation execution')
    (a.out / 'results.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(dict(completed=True, controls=len(records), statuses=[r['status'] for r in records]), sort_keys=True))


if __name__ == '__main__':
    main()
