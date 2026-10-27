#!/usr/bin/env python3
"""Materialize the historical bounded validation caller at a new checkout."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess

p = argparse.ArgumentParser(description=__doc__)
for name in ('repo', 'toolchain', 'user-home', 'cargo-home'):
    p.add_argument('--' + name, type=Path, required=True)
p.add_argument('--phase', choices=('targeted-profiler', 'required', 'serial',
               'parallel-library', 'parallel-prefixed', 'parallel-neighbor'), required=True)
a = p.parse_args()
recipe = Path(__file__).resolve().parent
repo = a.repo.resolve(strict=True)
assert subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], timeout=10, text=True).strip() == 'c66ea0607e38db67dd5b7cfbc7ab7f0ac7f7afdd'
source = (recipe / 'validate.py').read_bytes()
assert hashlib.sha256(source).hexdigest() == '24e1b3b39e98bf9e3b5bd35cb0926d573448f8177396118cc44d8f0025e40dec'
parent = (recipe / 'launch.py.template').read_text()
for token, value in (('@TOOLCHAIN@', a.toolchain), ('@USER_HOME@', a.user_home), ('@CARGO_HOME@', a.cargo_home)):
    assert parent.count(token) == 1
    parent = parent.replace(token, json.dumps(str(value.resolve(strict=True))))
ast.parse(parent)
destination = repo / 'ignored/a4/native-interval-bridge-validation-source-v1'
destination.mkdir(parents=True, exist_ok=True)
for name, data in (('validate.py', source), ('launch.py', parent.encode())):
    path = destination / name
    if path.exists():
        assert not path.is_symlink() and path.read_bytes() == data
    else:
        with path.open('xb') as stream:
            stream.write(data)
raise SystemExit(subprocess.run(['/usr/bin/python3.9', '-B', str(destination / 'launch.py'), a.phase], cwd=repo, check=False).returncode)
