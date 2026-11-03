#!/usr/bin/env python3
"""Current-source, one-CPU decoder/descriptor/model campaign; no native qualification."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import sys
import tomllib
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from decoder_facts_support import BOUNDS, Context, ROOT, fact, load

SELECTED = ROOT / 'tools/page-entry/selected'
DECODER = SELECTED / 'decoder'
LEAF = ROOT / 'crates/liteinst-x86'
BASE = ('lib.rs', 'abi.rs', 'arena.rs', 'decode.rs', 'scan.rs', 'tf.rs',
        'write_footprint.rs', 'admission_oneshot.rs')
EXTRA = ('region.rs', 'mov_guard.rs', 'add_guard.rs')
FEATURES = {'default': '', 'extended': 'linked-epoch,mov-guard,add-guard', 'marked': 'scalar-region'}
RESOLVED = {'default': ['default'], 'extended': ['add-guard', 'default', 'linked-epoch',
    'mov-guard', 'scalar-region', 'scalar-span'], 'marked': ['default', 'scalar-region']}
OLD_CASES = ('forms', 'tiny-arena', 'personality', 'freestanding')
SUBJECTS = tuple(p + '-' + c for p in ('default', 'extended') for c in OLD_CASES) + (
    'region-matrix', 'region-guarded', 'region-busy', 'region-allocation', 'span', 'mov', 'add')


def dependencies(ctx, dep, root, profile):
    prefix = str(ROOT / 'target/release/libli2_page_selected_decoder.a') + ': '
    text = dep.read_text().strip()
    assert text.startswith(prefix) and '\n' not in text
    paths = shlex.split(text[len(prefix):])
    additions = EXTRA if profile == 'extended' else ('region.rs',) if profile == 'marked' else ()
    expected = {str(root / 'tools/page-entry/selected/decoder/src' / n) for n in BASE + additions}
    expected.add(str(root / 'crates/liteinst-x86/src/lib.rs'))
    assert len(paths) == len(expected) and set(paths) == expected, 'exact local dep-info closure'
    assert len(paths) == {'default': 9, 'extended': 12, 'marked': 10}[profile]
    return {p: fact(ctx.pin(p)) for p in paths}


def cargo_graph(ctx, profile, root, package_check):
    decoder = root / 'tools/page-entry/selected/decoder'
    leaf = root / 'crates/liteinst-x86'
    feature = ['--features', FEATURES[profile]] if FEATURES[profile] else []
    _, out, err = ctx.run(profile + '-cargo-metadata', [ctx.tools['cargo'], 'metadata',
        '--manifest-path', decoder / 'Cargo.toml', '--format-version', '1', '--locked', '--offline', *feature])
    assert not err
    metadata = json.loads(out)
    assert Path(metadata['target_directory']).resolve() == ROOT / 'target'
    locked = {(p['name'], p['version']): p for p in tomllib.loads((decoder / 'Cargo.lock').read_text())['package']}
    assert {(p['name'], p['version']) for p in metadata['packages']} == set(locked)
    local = {p['name']: p for p in metadata['packages'] if p['source'] is None}
    assert set(local) == {'li2-page-selected-decoder', 'liteinst-x86'}
    assert Path(local['li2-page-selected-decoder']['manifest_path']).resolve() == decoder / 'Cargo.toml'
    assert Path(local['liteinst-x86']['manifest_path']).resolve() == leaf / 'Cargo.toml'
    nodes = {n['id']: n for n in metadata['resolve']['nodes']}
    assert len(nodes) == len(metadata['packages']) and metadata['resolve']['root'] == local['li2-page-selected-decoder']['id']
    assert nodes[local['li2-page-selected-decoder']['id']]['features'] == RESOLVED[profile]
    assert nodes[local['liteinst-x86']['id']]['features'] == [], 'independent freestanding leaf selects no std feature'
    packages = []
    for p in metadata['packages']:
        ctx.pin(p['manifest_path'])
        lock = locked[(p['name'], p['version'])]
        if p['source'] is not None:
            assert p['source'] == lock['source']
            packages.append(dict(name=p['name'], version=p['version'],
                                 root=str(Path(p['manifest_path']).parent), checksum=lock['checksum']))
        else:
            assert 'checksum' not in lock
        if p['name'] == 'iced-x86':
            expected = {'decoder', 'lazy_static', 'no_std'}
            if profile != 'default':
                expected.add('instr_info')
            assert set(nodes[p['id']]['features']) == expected
    before = [package_check(p) for p in packages]
    ctx.receipt.setdefault('cargo_graphs', {})[profile] = dict(metadata=metadata, registry_before=before)
    return packages, before


def exports(ctx, label, archive, *, region, marked=False):
    _, out, err = ctx.run(label + '-exports', [ctx.tools['nm'], '-g', '--defined-only', archive], profile='inspect')
    assert not err
    rows = [line.split() for line in out.splitlines()]
    for symbol in ('rust_eh_personality', 'li2_decoder_tf_classify', 'li2_decoder_write_footprint'):
        assert sum(r[-2:] == [b'T', symbol.encode()] for r in rows) == 1
    assert sum(r[-2:] == [b'T', b'li2_decoder_region_describe'] for r in rows) == int(region)
    expected = ['li2_region_test_allocate', 'li2_region_test_busy'] if marked else []
    assert sorted(r[-1].decode() for r in rows if r and r[-1].startswith(b'li2_region_test_')) == expected
    if marked:
        assert all(sum(r[-2:] == [b'T', n.encode()] for r in rows) == 1 for n in expected)


def inspect(ctx, label, path, elf, plain_executable, *, static=False):
    path = Path(path)
    ctx.artifacts[str(path)] = fact(path)
    data, head, segments = elf(path)
    assert head[1] in (2, 3)
    assert all(s[2] + s[5] <= len(data) and s[5] <= s[6] and s[1] & 3 != 3 for s in segments if s[0] == 1)
    result = dict(artifact=fact(path))
    if static:
        result['elf'] = plain_executable(path)
        _, out, err = ctx.run(label + '-undefined', [ctx.tools['nm'], '-u', path], profile='inspect')
        assert out == err == b''
    else:
        entries = [s for s in segments if s[0] == 3]
        assert len(entries) == 1
        p = entries[0]
        name = data[p[2]:p[2] + p[5]]
        assert name.startswith(b'/') and name.endswith(b'\0') and b'\0' not in name[:-1]
        loader = ctx.pin(name[:-1].decode())
        _, out, err = ctx.run(label + '-libraries', [loader, '--list', path], profile='inspect')
        assert not err
        libraries = {}
        for line in out.decode().splitlines():
            if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)', line):
                continue
            match = re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)', line)
            assert match is not None
            dependency = ctx.pin(match[1])
            assert dependency.name not in libraries
            libraries[dependency.name] = dict(path=str(dependency), **fact(dependency))
        assert libraries and any(v['path'] == str(loader) for v in libraries.values())
        result['libraries'] = libraries
    _, _, err = ctx.run(label + '-elf', [ctx.tools['readelf'], '-h', '-l', '-d', '-r', '-W', path], profile='inspect')
    assert not err
    ctx.receipt.setdefault('executables', {})[label] = result


def campaign(ctx):
    sys.path.insert(0, str(ROOT / 'evaluation/inprocess'))
    from page_selected_generic_build import package_check
    from page_selected_register_time_build import recipe, expand, headers
    from page_selected import elf
    from page_selected_components import plain_executable
    from checks import admission
    decoder = load('facts_original_controls', ctx.pin(HERE / 'decoder.py'))
    reader = load('facts_region_reader', ctx.pin(SELECTED / 'tests/region_decoder/check.py'))
    span = load('facts_span_reader', ctx.pin(SELECTED / 'tests/scalar_span/check.py'))
    ctx.pin(SELECTED / 'tests/scalar_span/model.py')
    ctx.pin(admission.__file__)
    ctx.loaded_sources()
    for path in (DECODER / 'Cargo.toml', DECODER / 'Cargo.lock', LEAF / 'Cargo.toml', LEAF / 'src/lib.rs',
                 SELECTED / 'build.sh', SELECTED / 'tests/region_decoder/test_exports.rs'):
        ctx.pin(path)
    for name in BASE + EXTRA:
        ctx.pin(DECODER / 'src' / name)
    configuration = admission.cargo_configuration(ctx.environment)
    ctx.receipt['cargo_configuration'] = configuration
    versions = ctx.receipt['versions'] = {}
    for name in ('cc', 'cargo', 'rustc', 'python'):
        _, out, err = ctx.run('version-' + name, [ctx.tools[name], '-vV' if name == 'rustc' else '--version'])
        assert not err
        versions[name] = out.decode().strip()
    for name in ('cc1', 'collect2', 'as', 'ld'):
        _, out, err = ctx.run('resolve-' + name, [ctx.tools['cc'], '-print-prog-name=' + name])
        assert not err and out.strip()
        value = out.decode().strip()
        ctx.tools[name] = ctx.pin(value if Path(value).is_absolute() else shutil.which(value, path=ctx.environment['PATH']))
    ctx.receipt['tools'] = {k: dict(path=str(v), **fact(v)) for k, v in ctx.tools.items()}
    builder = SimpleNamespace(tools=ctx.tools, environment=ctx.environment)

    def include(label, argv, archive):
        argv = list(map(str, argv))
        argv[0] = str(ctx.tools['cc'])
        sources = [a for a in argv if a.endswith(('.c', '.S'))]
        state = ctx.receipt.setdefault('links', {}).setdefault(label, dict(argv=argv))
        headers(label + '-headers', argv, sources, archive, builder, ctx.pin, ctx.aliases, ctx.run, state)
        assert str(SELECTED / 'decoder.h') in state['headers']

    def binary(label, path, *, static=False):
        inspect(ctx, label, path, elf, plain_executable, static=static)

    for profile in ('default', 'extended'):
        packages, before = cargo_graph(ctx, profile, ROOT, package_check)
        env = dict(ctx.environment, LI2_DECODER_FEATURES=FEATURES[profile])
        production = ROOT / 'target/page-entry/selected'
        # Same C commands as the production shell script, observed before the build.
        lines = [words for words in recipe(SELECTED / 'build.sh', '"$cc_bin"') if '-o' in words]
        assert len(lines) == 2
        values = {'$cc_bin': ctx.tools['cc'], '$source_dir': SELECTED,
                  '$parent_dir': SELECTED.parent, '$output_dir': production}
        for i, words in enumerate(lines):
            include(profile + '-product-' + str(i), expand(words, values), production / 'decoder.a')
        ctx.run(profile + '-build', [ctx.tools['sh'], SELECTED / 'build.sh'], profile='build', env=env)
        ctx.capacity(profile + '-retention')
        dest = ctx.out / profile
        checked = False

        def original_run(name, command, wall, environment, expected=0):
            nonlocal checked
            if '-link-' in name:
                if not checked:
                    dep = dependencies(ctx, dest / 'decoder.d', ROOT, profile)
                    ctx.receipt['decoder_builds'][profile]['dep_info'] = dep
                    for member, key in (('decoder-rustc.txt', 'rustc'), ('decoder-cargo.txt', 'cargo'), ('cc-version.txt', 'cc')):
                        assert (dest / member).read_text().strip() == versions[key]
                    exports(ctx, profile, dest / 'decoder.a', region=profile == 'extended')
                    checked = True
                argv = command[command.index('--') + 1:]
                include(name, argv, dest / 'decoder.a')
                result = ctx.raw(name, command, wall, environment, expected)
                binary(name, argv[-1], static=name.endswith('-free'))
                return result
            ctx.receipt['subjects'][name]['status'] = 'DISPATCHED_UNKNOWN'
            result = ctx.raw(name, command, wall, environment, expected)
            ctx.capacity(name + '-closed')
            return result

        try:
            decoder.controls(ROOT, ctx.out, profile, ctx.cpus[0], env, original_run, ctx.durable, ctx.receipt)
        finally:
            for row in ctx.receipt.get('decoder_builds', {}).get(profile, {}).get('cases', []):
                ctx.receipt['subjects'][profile + '-' + row['name']].update(status='PASS', **row)
        for name, wanted in ctx.receipt['decoder_builds'][profile]['artifacts'].items():
            assert fact(dest / name) == wanted
            ctx.artifacts[str(dest / name)] = wanted
        after = [package_check(p) for p in packages]
        assert after == before
        ctx.receipt['cargo_graphs'][profile]['registry_after'] = after
        ctx.capacity(profile + '-closed')

    archive = ctx.out / 'extended/decoder.a'
    fixture = SELECTED / 'tests/region_decoder'
    old = SELECTED / 'tests/decoder'
    flags = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fno-builtin',
             '-fno-tree-loop-distribute-patterns', '-mgeneral-regs-only']

    def region_link(label, linked_archive, extra=()):
        path = ctx.out / label
        argv = [ctx.tools['cc'], *flags, *extra, fixture / 'oracle.c', old / 'support.c',
                linked_archive, '-Wl,--gc-sections', '-o', path]
        include(label, argv, linked_archive)
        assert str(SELECTED / 'region_decode.h') in ctx.receipt['links'][label]['headers']
        ctx.run(label + '-link', argv, profile='build')
        binary(label, path)
        return path

    matrix = region_link('region-production', archive)
    # Preserve the manifest's relative leaf dependency exactly in a fresh mirror.
    mirror = ctx.out / 'test-source'
    copies = ctx.receipt['test_source'] = {}
    extra = (fixture / 'test_exports.rs').read_bytes()
    paths = [DECODER / n for n in ('Cargo.toml', 'Cargo.lock')]
    paths += [DECODER / 'src' / n for n in BASE + EXTRA]
    paths += [LEAF / 'Cargo.toml', LEAF / 'src/lib.rs']
    for source in paths:
        dest = mirror / source.relative_to(ROOT)
        dest.parent.mkdir(parents=True, exist_ok=True)
        data = source.read_bytes()
        added = extra if source == DECODER / 'src/lib.rs' else b''
        with dest.open('xb') as stream:
            stream.write(data + added)
        assert dest.read_bytes() == data + added
        copies[str(source.relative_to(ROOT))] = dict(original=fact(source), copied=fact(ctx.pin(dest)))
    testcrate = mirror / DECODER.relative_to(ROOT)
    assert (testcrate / '../../../../crates/liteinst-x86').resolve() == mirror / LEAF.relative_to(ROOT)
    assert (testcrate / 'src/lib.rs').read_bytes()[:-len(extra)] == (DECODER / 'src/lib.rs').read_bytes()
    packages, before = cargo_graph(ctx, 'marked', mirror, package_check)
    identity = 'li2_region_facts_test_exports_v1_' + hashlib.sha256(json.dumps(copies, sort_keys=True).encode() + str(mirror).encode()).hexdigest()
    ctx.receipt['marked_metadata'] = identity
    ctx.run('marked-build', [ctx.tools['cargo'], 'rustc', '--manifest-path', testcrate / 'Cargo.toml',
        '--release', '--locked', '--offline', '-j', '1', '--features', 'scalar-region', '--', '-C', 'metadata=' + identity], profile='build')
    ctx.capacity('marked-retention')
    generated = ROOT / 'target/release/libli2_page_selected_decoder.a'
    test_archive = ctx.retain(generated, ctx.out / 'marked-decoder.a')
    test_dep = ctx.retain(generated.with_suffix('.d'), ctx.out / 'marked-decoder.d')
    ctx.receipt['marked_dep_info'] = dependencies(ctx, test_dep, mirror, 'marked')
    after = [package_check(p) for p in packages]
    assert after == before
    ctx.receipt['cargo_graphs']['marked']['registry_after'] = after
    exports(ctx, 'marked', test_archive, region=True, marked=True)
    marked = region_link('region-marked', test_archive, ['-DLI2_REGION_TEST_EXPORTS=1'])
    for name, executable, argument, row in (
        ('region-matrix', matrix, '0', 4), ('region-guarded', matrix, '1', 5),
        ('region-busy', marked, '2', 6), ('region-allocation', marked, '3', 7)):
        state = ctx.receipt['subjects'][name]
        state['status'] = 'DISPATCHED_UNKNOWN'
        expected = 125 if row == 7 else 0
        child, out, err = ctx.run(name, [executable, argument], profile='decoder', expected=expected)
        state.update(result=reader.check(out, err, child['exit'], row), expected_exit=expected, actual_exit=child['exit'])
        controls = reader.controls(out, err, child['exit'], row)
        assert len(controls) == {4: 22, 5: 22, 6: 22, 7: 4}[row]
        state.update(status='PASS', reader_controls=len(controls))
        ctx.capacity(name + '-closed')

    # Reuse the exact MOV output authority without importing its native campaign.
    persistent = ctx.pin(ROOT / 'evaluation/inprocess/persistent_epoch.py')
    assignments = [n for n in ast.parse(persistent.read_text()).body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'COMPONENT_STDOUT' for t in n.targets)]
    assert len(assignments) == 1
    mov_expected = ast.literal_eval(assignments[0].value)['mov_guard']
    add_expected = b'{"schema":1,"add_codes":1,"descriptors":349,"byte_models":5096,"refusals":20,"corruptions":21,"interval_edges":465,"max_tree_height":8,"postseal_equal":1,"emitted_instruction_execution":0}\n'
    add_source = ctx.pin(SELECTED / 'tests/linked_add_guard/metadata.c').read_text()
    assert 'printf(' + json.dumps(add_expected.decode()) + ')' in add_source
    for name, directory in (('span', 'scalar_span'), ('mov', 'linked_mov_guard'), ('add', 'linked_add_guard')):
        fixture = SELECTED / 'tests' / directory
        build = ctx.pin(fixture / 'build.sh')
        output = ctx.out / ('component-' + name)
        output.mkdir()
        path = output / ('span-metadata' if name == 'span' else name)
        values = {'$cc_bin': ctx.tools['cc'], '$root': ROOT, '$selected': SELECTED,
            '$fixture': fixture, '$kind': 'metadata', '$support': old / 'support.c',
            '$archive': archive, '$output': output if name == 'span' else path}
        lines = recipe(build, '"$cc_bin"')
        assert len(lines) == 1
        argv = expand(lines[0], values)
        assert argv[-1] == str(path)
        include(name, argv, archive)
        if name == 'span':
            ctx.run(name + '-link', argv, profile='build')
        else:
            ctx.run(name + '-link', [ctx.tools['sh'], build, SELECTED, archive, path], profile='finite')
        binary(name, path)
        state = ctx.receipt['subjects'][name]
        state['status'] = 'DISPATCHED_UNKNOWN'
        child, out, err = ctx.run(name, [path], profile='finite')
        if name == 'span':
            result = span.metadata(out, err, child['exit'])
        else:
            assert child['exit'] == 0 and err == b'' and out == (mov_expected if name == 'mov' else add_expected)
            result = json.loads(out)
        state.update(status='PASS', expected_exit=0, actual_exit=child['exit'], result=result)
        ctx.capacity(name + '-closed')
    assert admission.cargo_configuration(ctx.environment) == configuration
    ctx.receipt['registry_final'] = [package_check(p) for p in packages]
    assert ctx.receipt['registry_final'] == before
    assert set(ctx.receipt['subjects']) == set(SUBJECTS) and len(SUBJECTS) == 15
    assert all(v['status'] == 'PASS' for v in ctx.receipt['subjects'].values())
    assert sum(v.get('reader_controls', 0) for v in ctx.receipt['subjects'].values()) == 138
    ctx.receipt['subjects_passed'] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--toolchain', required=True, type=Path)
    args = parser.parse_args()
    ctx = Context(args, SUBJECTS)
    try:
        ctx.capacity('before')
        ctx.admitted = True
        campaign(ctx)
    except BaseException as error:
        ctx.receipt['error'] = type(error).__name__ + ': ' + str(error)
        if ctx.safe:
            for row in ctx.receipt['subjects'].values():
                if row['status'] == 'DISPATCHED_UNKNOWN':
                    row['status'] = 'FAILED'
    return ctx.finish()


if __name__ == '__main__':
    if not (__debug__ and sys.flags.isolated and sys.dont_write_bytecode):
        raise SystemExit('use Python -I -B with assertions enabled')
    raise SystemExit(main())
