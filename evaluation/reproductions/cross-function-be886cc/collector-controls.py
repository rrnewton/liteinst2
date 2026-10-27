#!/usr/bin/env python3
"""Two synthetic refusal injections; never remove or rename actual raw files."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import sys
import traceback

COLLECTOR_SHA = 'e55a8ae53eace0d9b5b2850c90ed9f369bdfb0e739bdc9dbdf3c9dc3c09ab380'
INPUTS_SHA = '734c2e46f6145eebab8487d4ea413ae080d3c3d7f4096c15ce5e126b4e1bbb67'


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions required')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--collector', type=Path, required=True)
    ap.add_argument('--inputs', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
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
    result = dict(completed=True, controls=records, actual_raw_mutations=0,
                  source_sha256=COLLECTOR_SHA, inputs_sha256=INPUTS_SHA,
                  scope='synthetic reporting refusal controls only; no validation execution')
    (a.out / 'results.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps(dict(completed=True, controls=2, statuses=[r['status'] for r in records]), sort_keys=True))


if __name__ == '__main__':
    main()
