#!/usr/bin/env python3
"""Pure whole-source transport controls; no retained subjects or qualification."""
import ast
import hashlib
import json
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[2]
    driver = Path(__file__).with_name('loop_ro_native_controls.py')
    tree = ast.parse(driver.read_bytes())
    # Execute the real pure predicate/constants and the actual need() helper,
    # without importing the collector or executing its retained-input preflight.
    nodes = []
    for name in ('H', 'HOOKS'):
        found = [n for n in tree.body if isinstance(n, ast.Assign)
                 and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                 and n.targets[0].id == name]
        assert len(found) == 1
        nodes.extend(found)
    for path, name in ((root/'evaluation/inprocess/page_selected.py', 'need'),
                       (driver, 'source_input')):
        found = [n for n in ast.parse(path.read_bytes()).body
                 if isinstance(n, ast.FunctionDef) and n.name == name]
        assert len(found) == 1
        nodes.extend(found)
    env = {'hashlib': hashlib}
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
                 str(driver), 'exec'), env)
    check, hooks = env['source_input'], env['HOOKS']
    assert len(hooks) == 5 and sum(map(len, hooks.values())) == 6
    positives = negatives = 0

    def whole(data):
        return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

    def accept(path, data, expected, branch):
        nonlocal positives
        assert check(path, data, expected) == branch
        positives += 1

    def reject(path, data, expected):
        nonlocal negatives
        try:
            check(path, data, expected)
        except ValueError:
            negatives += 1
        else:
            raise AssertionError('changed whole input or malformed hook accepted')

    for path, spans in hooks.items():
        data = (root/path).read_bytes()
        old = data
        for span in reversed(spans):
            assert old.count(span['new'].encode()) == 1
            old = old.replace(span['new'].encode(), span['old'].encode())
        assert old != data
        accept(path, data, whole(data), 'current')
        accept(path, data, whole(old), 'hook_inverse')
        # Whole equality remains mandatory outside every allowed insertion.
        drift = data + b'/* unexpected source drift */\n'
        reject(path, drift, whole(data))
        reject(path, drift, whole(old))
        reject(path, data, dict(whole(data), sha256='0'*64))
        reject(path, data, dict(whole(data), bytes=len(data)+1))
        reject(path, data, dict(whole(data), extra=0))
        for span in spans:
            before, after = span['old'].encode(), span['new'].encode()
            # Even an exact recorded current fact cannot excuse missing,
            # duplicated, or partly edited current insertion syntax.
            missing = data.replace(after, before)
            duplicate = data.replace(after, after+after)
            partial = data.replace(after, after.replace(b'LI2_LOOP_RO_TEST',
                                                        b'LI2_LOOP_RO_TEST_EDIT', 1))
            for changed in (missing, duplicate, partial):
                assert changed != data
                reject(path, changed, whole(changed))
    plain = b'ordinary exact compiler input\n'
    accept('ordinary.h', plain, whole(plain), 'current')
    reject('ordinary.h', plain+b'drift', whole(plain))
    reject('ordinary.h', plain, dict(whole(plain), sha256='0'*64))
    reject('ordinary.h', plain, dict(whole(plain), bytes=len(plain)+1))
    reject('ordinary.h', plain, dict(whole(plain), extra=0))
    # An inverse is unavailable under any path outside the fixed donor roster.
    reject('other.h', data, whole(old))
    assert (positives, negatives) == (11, 48)
    print(json.dumps(dict(schema=1, status='observed_pure_source_controls',
        hook_files=5, hook_spans=6, positives=positives, negatives=negatives,
        native_subjects=0, qualification_credit=False), sort_keys=True,
        separators=(',', ':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
