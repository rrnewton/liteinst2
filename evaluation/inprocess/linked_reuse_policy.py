#!/usr/bin/env python3
"""Reproduce pure aging-policy checks; no guest or ownership qualification."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shlex
import shutil
import sys
from types import ModuleType

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'evaluation/inprocess'))
from page_selected import fact, need, save
from page_selected_process import invoke
from run import hardware

FINITE = [5, 512 << 20, 16 << 20, 15]
ENV = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1')
SOURCE = 'tools/page-entry/selected/linked_reuse.inc'
FIXTURE = 'tools/page-entry/selected/tests/linked_reuse_policy/metadata.c'
EXPECTED = dict(ratio_cases=495616, selection_cases=4736, aging_cases=4032, hand_cases=512, guest_executions=0)


def function(text, name, result):
    prefix = 'static ' + result + ' ' + name + '('
    start = text.index(prefix)
    end = text.index('\n}\n', start) + 3
    return text[start:end]


def module_files():
    # checks.admission is executed dynamically and retained in its parent
    # globals without a sys.modules entry. Follow those actual module objects.
    todo, seen, files = list(sys.modules.values()), set(), set()
    while todo:
        module = todo.pop()
        if not isinstance(module, ModuleType) or id(module) in seen:
            continue
        seen.add(id(module))
        path = getattr(module, '__file__', None)
        if path and Path(path).is_file():
            files.add(path)
        todo.extend(value for value in list(vars(module).values()) if isinstance(value, ModuleType))
    return sorted(files)


def public_result(private, output):
    # Keep arbitrary failure text and the complete original private result local.
    keys = ('schema', 'profile', 'status', 'source_revision', 'cpu', 'hardware', 'environment',
            'guest_executions', 'qualification_credit', 'production_bodies', 'sources', 'observed',
            'source_unchanged', 'cleanup_complete', 'input_closure', 'compiler', 'commands')
    public = {key: private[key] for key in keys if key in private}
    substitutions = [(str(output), '${OUTPUT}'), (str(ROOT), '${REPO}')]
    if 'compiler' in private:
        substitutions.extend((path, '${COMPILER}') for path in
                             (private['compiler']['path'], '/usr/bin/gcc'))
    substitutions = sorted(set(substitutions), key=lambda item: len(item[0]), reverse=True)

    def sanitized(value):
        if isinstance(value, str):
            for before, after in substitutions:
                value = value.replace(before, after)
            return value
        if isinstance(value, list):
            return [sanitized(item) for item in value]
        if isinstance(value, dict):
            return {sanitized(key): sanitized(item) for key, item in value.items()}
        return value

    public = sanitized(public)
    public.update(private_result=fact(output / 'result.json'),
                  failure_present='error' in private, final_error_count=len(private['final_errors']),
                  reproduction_argv=['python3', '-I', '-S', '-B', '${REPO}/evaluation/inprocess/linked_reuse_policy.py',
                                     '--expected-revision', private['source_revision'], '--output', '${OUTPUT}'])
    encoded = (json.dumps(public, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    forbidden = (str(ROOT), str(output), str(Path.home()), platform.node(), '/home/', '/data/users/')
    need(len(encoded) <= 32 << 10 and not any(value and len(value) > 1 and value.encode() in encoded
         for value in forbidden), 'bounded sanitized public policy result without host paths/names')
    name = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ') + '-linked-reuse-policy-' + private['source_revision'][:12] + '.json'
    destination = ROOT / 'evaluation/inprocess/results' / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('xb') as stream:
        stream.write(encoded)
    return str(destination.relative_to(ROOT))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--expected-revision', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    need(Path.cwd().resolve() == ROOT and not sys.flags.optimize and sys.flags.isolated and sys.flags.no_site,
         'root, assertions and isolated Python -I -S')
    need(re.fullmatch('[0-9a-f]{40}', a.expected_revision), 'exact expected revision')
    affinity = os.sched_getaffinity(0)
    need(len(affinity) == 1, 'one reserved CPU')
    cpu = next(iter(affinity))
    out = a.output.absolute()
    out.mkdir(parents=False, exist_ok=False, mode=0o700)
    inputs, aliases, artifacts = {}, {}, {}
    r = dict(schema=1, profile='linked-reuse-aging-policy-pure-v1', status='failed',
             source_revision=a.expected_revision, cpu=cpu, hardware=hardware(cpu), environment=ENV,
             guest_executions=0, qualification_credit=False, commands=[], final_errors=[])

    def pin(path):
        named = Path(path).absolute()
        resolved = named.resolve(strict=True)
        value = fact(resolved)
        need(str(resolved) not in inputs or inputs[str(resolved)] == value, 'stable input')
        inputs[str(resolved)] = value
        aliases[str(named)] = str(resolved)
        return resolved

    def artifact(path):
        path = Path(path).resolve(strict=True)
        artifacts[str(path)] = dict(fact(path), mode=path.stat().st_mode & 0o777)

    def command(name, argv):
        executable = shutil.which(str(argv[0]), path=ENV['PATH'])
        need(executable is not None, 'actual executable')
        pin(executable)
        row = dict(name=name, argv=list(map(str, argv)), bounds=FINITE, environment=ENV,
                   capture_limit=16 << 20, expected_exit=0)
        r['commands'].append(row)
        try:
            stdout, stderr = invoke(row, out, cpu)
            need(row['exit'] == 0, 'actual command exit ' + name)
            return stdout, stderr
        finally:
            for capture in row.get('captures', {}).values():
                artifact(out / capture['file'])

    try:
        repository_modules = []
        for filename in module_files():
            path = pin(filename)
            if path.is_relative_to(ROOT):
                repository_modules.append(str(path.relative_to(ROOT)))
        production, metadata = pin(ROOT / SOURCE), pin(ROOT / FIXTURE)
        stdout, stderr = command('head', ['/usr/bin/git', '-C', ROOT, 'rev-parse', 'HEAD'])
        need(stdout.decode().strip() == a.expected_revision and not stderr, 'exact current source revision')
        command('tracked-clean', ['/usr/bin/git', '-C', ROOT, 'diff', '--exit-code', 'HEAD'])
        required = sorted(set(repository_modules + [SOURCE, FIXTURE]))
        stdout, stderr = command('tracked-inputs', ['/usr/bin/git', '-C', ROOT, 'ls-files', '--error-unmatch', '--', *required])
        need(not stderr and sorted(stdout.decode().splitlines()) == required, 'all source modules are tracked')
        source_text, test_text = production.read_text(), metadata.read_text()
        r['production_bodies'] = []
        for name, kind in (('ler_age_greater', 'int'), ('ler_choose', 'size_t'), ('ler_published', 'void')):
            body = function(source_text, name, kind)
            need(function(test_text, name, kind) == body and test_text.count(body) == 1,
                 'exact production body in pure fixture: ' + name)
            r['production_bodies'].append(dict(name=name, bytes=len(body.encode()), sha256=hashlib.sha256(body.encode()).hexdigest()))
        r['sources'] = {name: fact(ROOT / name) for name in (SOURCE, FIXTURE, str(Path(__file__).resolve().relative_to(ROOT)))}
        flags = ['/usr/bin/gcc', '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                 '-fno-tree-vectorize', '-mgeneral-regs-only']
        compiler = pin(flags[0])
        r['compiler'] = dict(path=str(compiler), **fact(compiler))
        stdout, stderr = command('headers', [*flags, '-M', '-MT', 'policy_test', metadata])
        rules = stdout.decode().replace('\\\n', ' ').splitlines()
        need(not stderr and len(rules) == 1 and rules[0].startswith('policy_test: '), 'actual single include closure')
        for name in shlex.split(rules[0].split(':', 1)[1]):
            pin(name)
        executable = out / 'policy-test'
        command('compile', [*flags, metadata, '-o', executable])
        artifact(executable)
        stdout, stderr = command('policy', [executable])
        observed = json.loads(stdout)
        need(not stderr and json.dumps(observed, sort_keys=True) == json.dumps(EXPECTED, sort_keys=True),
             'exact typed pure-policy population')
        r['observed'] = observed
        r['status'] = 'passed'
    except BaseException as error:
        r['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        for filename in module_files():
            try:
                pin(filename)
            except BaseException as error:
                r['final_errors'].append('module: ' + repr(error))
        for path, wanted in inputs.items():
            try:
                need(fact(Path(path)) == wanted, 'changed input ' + path)
            except BaseException as error:
                r['final_errors'].append('input: ' + repr(error))
        for path, wanted in aliases.items():
            try:
                need(str(Path(path).resolve(strict=True)) == wanted, 'changed alias ' + path)
            except BaseException as error:
                r['final_errors'].append('alias: ' + repr(error))
        for path, wanted in artifacts.items():
            try:
                need(dict(fact(Path(path)), mode=Path(path).stat().st_mode & 0o777) == wanted, 'changed artifact ' + path)
            except BaseException as error:
                r['final_errors'].append('artifact: ' + repr(error))
        try:
            stdout, stderr = command('head-after', ['/usr/bin/git', '-C', ROOT, 'rev-parse', 'HEAD'])
            need(stdout.decode().strip() == a.expected_revision and not stderr, 'unchanged final revision')
            command('tracked-clean-after', ['/usr/bin/git', '-C', ROOT, 'diff', '--exit-code', 'HEAD'])
        except BaseException as error:
            r['final_errors'].append('source closure: ' + repr(error))
        r['source_unchanged'] = not r['final_errors']
        r['cleanup_complete'] = all(c.get('reaped') is True and not c.get('timed_out') and not c.get('error')
            and c.get('cleanup_errors') == [] and all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['final_errors'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        save(out / 'inputs.json', dict(inputs=inputs, aliases=aliases, artifacts=artifacts))
        r['input_closure'] = dict(fact(out / 'inputs.json'), inputs=len(inputs), artifacts=len(artifacts))
        # Full bounded process records remain private; public result retains exact
        # argv/bounds/exits/capture facts, not stdout, stderr or another audit log.
        r['commands'] = [{k: c.get(k) for k in ('name', 'argv', 'bounds', 'exit', 'captures', 'timed_out', 'reaped')}
                         for c in r['commands']]
        encoded = (json.dumps(r, sort_keys=True, separators=(',', ':')) + '\n').encode()
        need(len(encoded) <= 32 << 10, 'bounded pure-policy result')
        (out / 'result.json').write_bytes(encoded)
        public = public_result(r, out)
        print(json.dumps(dict(status=r['status'], result=str(out / 'result.json'), public=public)), flush=True)
    return 0 if r['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
