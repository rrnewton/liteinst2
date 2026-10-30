#!/usr/bin/env python3
"""Read-only guard controls against one actual closed command-metadata capture."""
import argparse
import copy
import json
from unittest import mock

import command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw', type=command.Path, required=True)
    args = parser.parse_args()
    raw = args.raw.resolve(strict=True)
    result = command.inspect(raw)
    assert result['argv_equal'] and result['expected_words'] == result['observed_words'] == 40
    original_loads = json.loads
    manifests = {name: (raw/name).read_text() for name in ('inputs.json', 'request.json')}
    inputs = original_loads(manifests['inputs.json'])
    request = original_loads(manifests['request.json'])
    mutants = [('inputs.json', {})]
    for name in inputs:
        changed = copy.deepcopy(inputs)
        del changed[name]
        mutants.append(('inputs.json', changed))
    changed = copy.deepcopy(inputs)
    changed[str(raw/'stdout')] = command.pin(raw/'stdout')
    mutants.append(('inputs.json', changed))
    for name in inputs:
        changed = copy.deepcopy(inputs)
        changed[name]['sha256'] = '0'*64
        mutants.append(('inputs.json', changed))
    for name in ('cwd', 'stdout', 'stderr'):
        changed = copy.deepcopy(request)
        changed[name] += '-changed'
        mutants.append(('request.json', changed))
    for name in request['env']:
        changed = copy.deepcopy(request)
        changed['env'][name] += '-changed'
        mutants.append(('request.json', changed))
    for name in ('cpu_seconds', 'wall_seconds', 'file_bytes'):
        changed = copy.deepcopy(request)
        changed[name] += 1
        mutants.append(('request.json', changed))
    changed = copy.deepcopy(request)
    changed['argv'][-1] = 'changed-authority'
    mutants.append(('request.json', changed))
    for name, changed in mutants:
        # Substitute only one decoded authority object. Actual capture, pins,
        # owner/receipt and every file stay untouched throughout the controls.
        def loads(text, *a, **kw):
            return changed if text == manifests[name] else original_loads(text, *a, **kw)
        with mock.patch.object(command.json, 'loads', side_effect=loads):
            try:
                command.inspect(raw)
            except AssertionError:
                pass
            else:
                raise AssertionError('authority mutant accepted: '+name)
    assert command.inspect(raw) == result
    print(json.dumps(dict(real_capture_checks=2, refused_authority_mutants=len(mutants),
                          capture_unchanged=True, scope='reader guards; no new capture')))


if __name__ == '__main__':
    main()
