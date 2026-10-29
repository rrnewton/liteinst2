#!/usr/bin/env python3
"""Materialize only the two previously UNRUN allocation checks; never execute."""
import ast
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATOR_SHA = 'ff93f100983ef5fbce1155592a4c34fa865c4b110fb4b24dd845ab88d1682363'
PAYLOAD_SHA = '6e7bb45250ea92ce6cb5a48b5839cfd43caf27c3d80a57d2b71963002862dde6'


def main():
    generator = ROOT / 'evaluation/ordinary-call-pair-native-cfc8d76/reproduce_tail.py'
    data = generator.read_bytes()
    assert hashlib.sha256(data).hexdigest() == GENERATOR_SHA
    literals = {}
    for node in ast.parse(data).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ('SOURCE_SHA', 'PAYLOAD_SHA', 'CHANGES'):
                literals[name] = ast.literal_eval(node.value)
    data = (ROOT / 'evaluation/admission/check_exec_identity.py').read_bytes()
    assert hashlib.sha256(data).hexdigest() == literals['SOURCE_SHA']
    text = data.decode()
    for span in literals['CHANGES']:
        assert text.count(span['before']) == 1
        text = text.replace(span['before'], span['after'])
    assert hashlib.sha256(text.encode()).hexdigest() == literals['PAYLOAD_SHA']
    changes = {'Run only the three previously UNRUN serial launch, staged allocation and prefixed-pun checks.': 'Run only the two previously UNRUN staged allocation and prefixed-pun checks.', "required = {'serial-launch', 'staged-allocation', 'prefixed-pun'}": "required = {'staged-allocation', 'prefixed-pun'}", 'Only the three previously UNRUN tail checks. Original workspace timeout remains FAILED; this is not whole-seven-check acceptance.': 'Only the two previously UNRUN allocation checks. Prior failed checks remain FAILED; this is not whole-seven-check acceptance.', 'ignored/a5/cfc8d76-tail-checks-source-v1/successor-v2/tail_checks.py': 'ignored/a5/cfc8d76-tail-checks-source-v1/successor-v3/tail_checks.py'}
    for before, after in changes.items():
        assert text.count(before) == 1
        text = text.replace(before, after)
    data = text.encode()
    assert hashlib.sha256(data).hexdigest() == PAYLOAD_SHA
    dest = ROOT / 'ignored/a5/cfc8d76-tail-checks-source-v1/successor-v3/tail_checks.py'
    dest.parent.mkdir(parents=True, exist_ok=True)
    assert dest.parent.resolve() == dest.parent
    if dest.exists():
        assert dest.is_file() and not dest.is_symlink() and dest.read_bytes() == data
    else:
        with dest.open('xb') as stream:
            stream.write(data)
    assert dest.read_bytes() == data
    print(dest.relative_to(ROOT))


if __name__ == '__main__':
    main()
