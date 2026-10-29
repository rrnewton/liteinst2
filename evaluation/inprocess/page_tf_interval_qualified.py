"""Read-only replay of a complete, same-revision interval qualification.

No command, fixture generator, observer preparation, or target is executed here.
The finite producer's original readers decide every positive and failed outcome.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shlex
import struct
import sys
from types import SimpleNamespace

import page_selected_tf_interval as finite
from page_default_ls_release_performance import decode, qualified, HARDWARE_KEYS
from page_selected import ENV, fact, need, elf
from page_selected_fast_memset import body_check
from page_selected_oneshot_build import commands, UNITS, MACROS
from page_selected_register_time_build import headers, bridge_check, recipe, expand
from page_selected_rseq_time import hidden_memset
import page_selected_images as image_elf

ROOT = Path(__file__).resolve().parents[2]


def _load(name, path, pin):
    spec = importlib.util.spec_from_file_location(name, pin(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _observed(prepare, selected, output, pin, binary):
    """Reconstruct the declared adapters in memory; never call prepare()."""
    facts, generated = [], {}
    for name in prepare.FILES:
        original = pin(selected / name)
        before = original.read_bytes()
        data = before
        for path, old, new in prepare.ADAPTERS:
            if path == name:
                need(data.count(old.encode()) == 1, 'one exact observation seam')
                data = data.replace(old.encode(), new.encode())
        suffix = (prepare.FETCH_WRAPPER if name == 'native_controller.inc' else
                  prepare.PROTECTION if name == 'lifecycle_loader.c' else '')
        data += suffix.encode()
        inverse = data[:-len(suffix)] if suffix else data
        for path, old, new in reversed(prepare.ADAPTERS):
            if path == name:
                need(inverse.count(new.encode()) == 1, 'one exact observation inverse')
                inverse = inverse.replace(new.encode(), old.encode())
        need(inverse == before, 'whole product inverse')
        actual = pin(binary(output / name))
        need(actual.read_bytes() == data, 'complete actual generated product bytes')
        facts.append(dict(name=name, before=fact(original), after=fact(actual)))
        generated[name] = fact(actual)
    for name, dest in (('observe.inc', 'tf_interval_observe.inc'),
                       ('record.h', 'tf_interval_record.h')):
        original = pin(selected / 'tests/tf_interval' / name)
        data = original.read_bytes()
        if name == 'record.h':
            old, new = b'#include "../rseq_native/record.h"', b'#include "tf_interval_old_record.h"'
            need(data.count(old) == 1 and new not in data, 'one original frame-header include')
            data = data.replace(old, new)
            need(data.replace(new, old) == original.read_bytes(), 'complete frame-header inverse')
        actual = pin(binary(output / dest))
        need(actual.read_bytes() == data, 'complete actual observation header bytes')
        facts.append(dict(name=dest, before=fact(original), after=fact(actual)))
        generated[dest] = fact(actual)
    original = pin(selected / 'tests/rseq_native/record.h')
    actual = pin(binary(output / 'tf_interval_old_record.h'))
    need(actual.read_bytes() == original.read_bytes(), 'whole original native frame header')
    facts.append(dict(name=actual.name, before=fact(original), after=fact(actual)))
    generated[actual.name] = fact(actual)
    return facts, generated


def _interpreter(images, directory, pin, binary):
    """The source-defined emitter's literal bytes, reconstructed without writes."""
    dynamic, strings = 0x400, 0x480
    dyn = b''.join(struct.pack('<qQ', t, v) for t, v in
                   ((5, strings), (10, len(images.SONAME) + 1), (14, 1), (0, 0)))
    ph = [image_elf.segment(1, 4, 0, 0, 4096),
          image_elf.segment(1, 5, 4096, 4096, 4096),
          image_elf.segment(2, 4, dynamic, dynamic, len(dyn), 8),
          image_elf.segment(0x6474e551, 6, 0, 0, 0, 16)]
    code = bytes.fromhex('0fa2') + image_elf.mov64(0, images.MAIN) + bytes.fromhex('ffe0')
    data = bytearray(8192)
    data[:image_elf.EH.size] = image_elf.header(3, 4096, ph)
    for i, row in enumerate(ph):
        image_elf.PH.pack_into(data, image_elf.EH.size + i * image_elf.PH.size, *row)
    for offset, value in ((dynamic, dyn), (strings, b'\0' + images.SONAME), (4096, code)):
        data[offset:offset + len(value)] = value
    path = pin(binary(directory / images.SONAME[:-1].decode()))
    need(path.read_bytes() == data and path.stat().st_mode & 0o777 == 0o700,
         'complete literal native interpreter and actual executable mode')
    text = '.section .interp,"a",@progbits\n.asciz ' + json.dumps(str(path)) + '\n'
    text += '.section .dynstr.fixture,"a",@progbits\n.asciz ' + json.dumps(images.SONAME[:-1].decode()) + '\n'
    text += '.section .note.GNU-stack,"",@progbits\n'
    metadata = pin(binary(directory / 'metadata.S'))
    need(metadata.read_bytes() == text.encode(), 'exact generated custom interpreter metadata')
    return path, metadata


def authenticate(path, sha, current_source, pin, binary, record):
    """Return only authenticated timing assets after all forty saved rows replay."""
    path = pin(path)
    need(fact(path)['sha256'] == sha, 'explicit complete interval receipt SHA256')
    q = decode(path.read_bytes())
    private, output = path.parent, path.parent / 'interval'
    selected = ROOT / 'tools/page-entry/selected'
    fixture = selected / 'tests/tf_interval'
    cpu = record['cpu']
    need(type(cpu) is int and cpu >= 0 and q['schema'] == 1 and
         q['profile'] == 'page-selected-tf-interval-v1' and q['status'] == 'passed' and
         q['expected_revision'] == current_source['revision'] and
         q['source'] == q['source_after'] == current_source and
         q['source_unchanged'] is True and q['error'] is None and q['final_errors'] == [],
         'complete interval qualification at the exact current committed source')
    need(q['bounds'] == finite.BOUNDS and
         q['required_source_inputs'] == record['required_source_inputs'] and
         all(q['inputs'].get(p) == v for p, v in record['required_source_inputs'].items()),
         'all current committed runtime/evaluator inputs and original bounds')
    hardware_keys = (*HARDWARE_KEYS, 'isa_flags', 'runner_euid', 'runner_cap_eff',
                     'runner_seccomp_mode', 'probe_cpu', 'affinity_cpu_count')
    need(q['hardware']['probe_cpu'] == cpu and q['hardware']['affinity_cpu_count'] == 1 and
         all(q['hardware'][k] == record['hardware'][k] for k in hardware_keys),
         'same actual hardware/kernel/process envelope and single reserved CPU')

    def closure():
        need(q['inputs'] and q['aliases'] and q['artifacts'], 'complete retained final custody')
        for p, want in q['inputs'].items():
            need(fact(pin(p)) == want, 'exact actual interval input')
        for p, target in q['aliases'].items():
            need(str(pin(p)) == target, 'exact actual interval lexical alias')
        for p, want in q['artifacts'].items():
            actual = binary(p)
            need(dict(fact(pin(actual)), mode=actual.stat().st_mode & 0o777) == want,
                 'exact actual interval artifact bytes/mode')
        need(q['configuration_presence'] == {p: os.path.lexists(p) for p in
             ('/etc/ld.so.cache', '/etc/ld.so.preload')} and
             q['configuration_presence']['/etc/ld.so.preload'] is False,
             'same actual loader configuration and no preload')
        for p, target in q['namespace_links'].items():
            need(Path(p).is_symlink() and os.readlink(p) == target,
                 'retained actual interval sealed namespace links')

    closure()
    old = q['prerequisite_receipt']
    prerequisite = pin(old['path'])
    need(fact(prerequisite) == {k: old[k] for k in ('bytes', 'sha256')},
         'explicit same-revision original lease prerequisite')
    tools, unobserved = qualified(prerequisite, old['sha256'], current_source,
                                 pin, binary, record, lease_mode=True)
    need(record['qualification'] == q['qualification'] and
         record['prerequisite_configuration'] == q['prerequisite_configuration'] and
         record['qualified_namespace_aliases'] == q['qualified_namespace_aliases'],
         'unchanged original148 plus6/49/17 qualification, Build, and namespace joins')
    prior = decode(prerequisite.read_bytes())
    archive = pin(prior['build']['artifacts']['decoder.a']['path'])
    need(q['unobserved_bridge'] == dict(path=str(unobserved), **fact(unobserved)) and
         q['archive'] == dict(path=str(archive), **fact(archive)),
         'exact qualified production bridge/archive, without an observation overlay')
    gd = prior['tf_same_page_fixture']['tools']['gdb']
    tools['gdb'] = pin(gd['path'])
    need(fact(tools['gdb']) == {k: gd[k] for k in ('bytes', 'sha256')} and
         q['tools'] == {k: dict(path=str(p), **fact(p)) for k, p in tools.items()} and
         pin(sys.executable) == tools['python'], 'complete exact actual finite tool inventory')
    builder = SimpleNamespace(tools=tools, environment=record['prerequisite_configuration']['environment'])
    gdb_env = dict(builder.environment, XDG_CACHE_HOME=str(output / 'gdb-cache'))
    prepare = _load('interval_auth_prepare', fixture / 'prepare.py', pin)
    check = _load('interval_auth_check', fixture / 'check.py', pin)
    pipe = _load('interval_auth_pipe', fixture / 'pipe_run.py', pin)
    images = _load('interval_auth_images', selected / 'tests/provider_launch/interpreter.py', pin)
    namespace = _load('interval_auth_namespace', ROOT / 'tools/page-entry/namespace.py', pin)
    policy = _load('interval_auth_policy', selected / 'tests/oneshot_integrated/check.py', pin)
    reports = _load('interval_auth_reports', selected / 'tests/tf_same_page/reports.py', pin)
    need(pipe.BOUNDS == finite.BOUNDS['interval'] and pipe.CONTROLS ==
         {'normal': '0', 'bad-ready': '1', 'extra-done': '2', 'missing-done': '3',
          'wrong-go': '0', 'eof-go': '0'}, 'unchanged fixed protocol/control contract')

    rows = q['commands']
    need([(r['name'], r['profile']) for r in rows] == finite.inventory(),
         'all forty actual commands in their original order')
    captures = {}
    for row in rows:
        name = row['name']
        pipe_row = row['profile'] == 'interval' and not name.startswith('interval-fd-')
        fd_row = name.startswith('interval-fd-')
        streams = ('stdout', 'stderr', 'record', 'preparation') if pipe_row else \
                  ('stdout', 'stderr', 'record') if fd_row else ('stdout', 'stderr')
        need(type(row['pid']) is int and row['pid'] > 0 and type(row['exit']) is int and
             row['reaped'] is True and row['timed_out'] is False and row['cleanup_errors'] == [] and
             type(row['duration_ns']) is int and row['duration_ns'] > 0 and
             row['bounds'] == finite.BOUNDS[row['profile']] and
             all(type(v) is int for v in row['bounds']) and row['capture_limit'] == 16 << 20 and
             set(row['captures']) == set(streams) and
             all(d['closed'] is True for d in row['descriptors']),
             'actual reaped non-timeout commands, original limits and exact capture domains')
        if not pipe_row:
            need(row['error'] is None and row['descriptors'] ==
                 ([dict(name='record', fd=3, closed=True)] if fd_row else []),
                 'unchanged ordinary command/descriptor closure')
        need(decode(pin(binary(private / (name + '.json'))).read_bytes()) == row,
             'exact complete retained command row')
        captures[name] = {}
        for stream in streams:
            got = row['captures'][stream]
            actual = pin(binary(private / (name + '.' + stream)))
            need(got == dict(fact(actual), file=actual.name) and
                 type(got['bytes']) is int and 0 <= got['bytes'] <= 16 << 20,
                 'complete bounded actual capture bytes and exact filename')
            captures[name][stream] = actual.read_bytes()
        # The producer inserts these keys in this order; JSON save sorts them.
        # Restore only that deterministic order for its public manifest digest.
        row['captures'] = {stream: row['captures'][stream] for stream in streams}
    cursor = 0

    def replay(name, argv, profile='metadata', env=ENV, expected=0, record=False):
        """Consume one saved row. This function cannot launch a command."""
        nonlocal cursor
        need(cursor < len(rows), 'finite saved command inventory not exhausted')
        row = rows[cursor]
        wanted = [str(x) for x in argv]
        if record:
            wanted = ['3' if x == '{record_fd}' else x for x in wanted]
        need((row['name'], row['profile']) == (name, profile) and row['argv'] == wanted and
             row['environment'] == dict(env) and row['expected_exit'] == expected and
             (expected is None or row['exit'] == expected),
             'exact source-derived saved argv/environment/outcome: ' + name)
        cursor += 1
        return row, captures[name]['stdout'], captures[name]['stderr']

    _, names, err = replay('source-paths', [tools['git'], '-C', ROOT, 'ls-files', '-z', '--',
                                        'tools/page-entry', 'evaluation/inprocess'])
    need(not err, 'successful actual tracked source listing')
    listed = [os.fsdecode(n) for n in names.split(b'\0') if n and
              not n.startswith(b'evaluation/inprocess/results/')]
    need(len(listed) == len(set(listed)) and
         {str(pin(ROOT / n)): fact(ROOT / n) for n in listed} == q['required_source_inputs'],
         'literal complete actual tracked source membership')
    for tool in ('gdb', 'objdump'):
        _, out, err = replay('interval-' + tool + '-version', [tools[tool], '--version'],
                             env=gdb_env if tool == 'gdb' else builder.environment)
        need(out and not err, 'actual qualified inspection-tool version')

    def inspect(name, artifact, record_name, bridge=False):
        binary(artifact)
        if bridge:
            bridge_check(artifact)
        _, out, err = replay(name + '-undefined', [tools['nm'], '-u', artifact],
                             profile='inspect', env=builder.environment)
        need(out == err == b'', 'actual complete ELF has no unresolved imports')
        _, symbols, err = replay(name + '-symbols', [tools['nm'], '-S', '--defined-only', artifact],
                                 profile='inspect', env=builder.environment)
        need(not err, 'actual full defined-symbol observation')
        value = dict(path=str(artifact), **fact(artifact))
        if bridge:
            _, assembly, err = replay(name + '-memset', [tools['objdump'], '-d', '-w', '-M', 'att',
                '--disassemble=memset', artifact], profile='inspect', env=builder.environment)
            need(not err, 'actual complete reset assembly')
            value['reset'] = hidden_memset(artifact, body_check(artifact, symbols, assembly, 'fast', symbol_name='memset'))
        _, out, err = replay(name + '-layout', [tools['gdb'], '-q', '-nx', '-batch', '-iex',
            'set auto-load off', '-iex', 'set debuginfod enabled off', '-iex', 'set index-cache enabled off',
            '-iex', 'maintenance set worker-threads 1', '--readnow', '--se=' + str(artifact),
            '-x', fixture / 'layout.py'], env=gdb_env)
        need(not err, 'actual file-only DWARF capture')
        layout = value['layout'] = decode(out)
        symbols = [x.split() for x in symbols.splitlines() if x.split()[-1:] == [record_name.encode()]]
        _, _, ph = elf(artifact)
        need(layout['record'] == record_name and len(symbols) == 1 and len(symbols[0]) == 4 and
             symbols[0][2] == b'b' and
             0 < int(symbols[0][1], 16) == layout['types'][record_name]['bytes'] < 16 << 20 and
             sum(p[0] == 1 and p[1] == 6 and p[3] <= int(symbols[0][0], 16) <
                 int(symbols[0][0], 16) + int(symbols[0][1], 16) <= p[3] + p[6] for p in ph) == 1,
             'complete actual record extent in one writable NX load')
        return value

    observed = output / 'observed'
    adapters, generated = _observed(prepare, selected, observed, pin, binary)
    need(adapters == q['adapters'], 'all actual whole-product observation adapter joins')
    recipe_path = pin(selected / 'build-tf-same-page-lease.sh')
    argv = commands(recipe_path, builder, output, archive, pin)[0]
    units = [str(selected.parent / p) for p in UNITS[:-1]]
    macros = (MACROS - {'-DLI2_ONESHOT_PUBLICATION=1'}) | {
        '-DLI2_CPUID_NX_ONLY=1', '-DLI2_RSEQ_NATIVE=1', '-DLI2_RSEQ_NATIVE_BOUNDARY=1',
        '-DLI2_RSEQ_TCGETS_BTRFS=1', '-DLI2_RSEQ_TIOCGWINSZ_BTRFS=1', '-DLI2_TF_SAME_PAGE_LEASE=1'}
    need([x for x in argv if x.endswith(('.c', '.S'))] == units and len(units) == 15 and
         {x for x in argv if x.startswith('-DLI2_')} == macros and
         sum(x.startswith('-DLI2_') for x in argv) == len(macros) == 13 and
         argv[-2:] == ['-o', str(output / 'bridge-tf-same-page-lease.so')] and
         all(x in argv for x in ('-O2', '-g', '-nostdlib', '-shared', '-fPIC', '-fvisibility=hidden',
                                '-mgeneral-regs-only', '-fno-builtin', '-Werror')),
         'unchanged complete fifteen-TU thirteen-macro release recipe')
    actual, sources = argv.copy(), units.copy()
    actual[-1] = str(output / 'observed.so')
    for basename in ('runtime_loader.c', 'lifecycle_loader.c'):
        old, new = str(selected / basename), str(observed / basename)
        need(actual.count(old) == 1, 'one exact observed translation-unit replacement')
        actual = [new if x == old else x for x in actual]
        sources = [new if x == old else x for x in sources]
    build = dict(name='interval-observed', recipe=fact(recipe_path), argv=actual,
                 archive=fact(archive), translation_units=15, status='passed')
    header_aliases = {}
    headers('interval-observed-headers', actual, sources, archive, builder,
            pin, header_aliases, replay, build)
    need({str(observed / n) for n in (*prepare.FILES, 'tf_interval_observe.inc',
         'tf_interval_record.h', 'tf_interval_old_record.h')} <= set(build['headers']),
         'all generated observer files in actual compiler include closure')
    replay('interval-observed-link', actual, profile='interval_build', env=builder.environment)
    bridge = pin(binary(output / 'observed.so'))
    build['artifact'] = fact(bridge)
    build['inspection'] = inspect('interval-observed', bridge, 'tfi_record', True)
    need(q['builds'] == [build], 'entire actual observed build, headers, ELF and DWARF join')
    gated_layout = build['inspection']['layout']
    interpreter, metadata = _interpreter(images, output / 'interpreter', pin, binary)
    for p in (interpreter, metadata):
        generated[p.name] = dict(path=str(p), **fact(p))
    need(q['generated'] == generated, 'complete actual generated-file inventory')
    carrier_tool = pin(ROOT / 'tools/page-entry/carrier.py')
    fixture_recipe = pin(fixture / 'build.sh')
    templates = recipe(fixture_recipe, '"$cc_bin"')
    need(len(templates) == 1 and len(q['programs']) == len(q['pairs']) == 2 and len(q['cases']) == 17,
         'one fixture recipe, two programs/pairs, seventeen actual subjects')
    programs, assets, namespace_links = {}, {}, {}
    case_cursor = 0

    def namespace_check(case, original, carrier, ns, objects, prep, mode, control):
        need(prep['mode'] == mode and type(prep['control']) is int and prep['control'] == control and
             prep['mask'] == 0 and prep['affinity'] == [cpu] and
             [x['signal'] for x in prep['dispositions']] == [n for n in range(1, 65) if n not in (9, 19)] and
             all(x['after'] == 0 for x in prep['dispositions']), 'actual prepared CPU, signal dispositions and mask')
        env = {k: v for k, v in ENV.items() if k != 'PYTHONDONTWRITEBYTECODE'}
        need(prep['environment'] == env and prep['argv'] == [str(original), mode,
             str(prep['pipes'][0]['fd']), str(prep['pipes'][1]['fd']), str(control)],
             'actual fixed original argv and default environment')
        if mode != 'gated':
            need('namespace' not in case and 'backing' not in case, 'native lane has no gated identity')
            return
        manifest, launch = pin(binary(ns / 'namespace.json')), pin(binary(ns / 'launch.json'))
        sealed, started = decode(manifest.read_bytes()), decode(launch.read_bytes())
        need(sealed['original'] == str(original) and sealed['original_sha256'] == fact(original)['sha256'] and
             sealed['interpreter_sha256'] == fact(interpreter)['sha256'] and len(sealed['objects']) == len(objects),
             'actual complete sealed namespace for the qualified original')
        for got, item in zip(sealed['objects'], objects):
            need(got['names'] == item['names'] and got['sha256'] == finite.H(item['bytes']) and
                 got['size'] == len(item['bytes']) and got['seals'] == namespace.SEALS and
                 got['device'] > 0 and got['inode'] > 0, 'actual immutable namespace object')
            for alias in got['names']:
                p, target = ns / alias, '/proc/self/fd/' + str(got['fd'])
                need(p.is_symlink() and os.readlink(p) == target, 'actual sealed dependency alias')
                namespace_links[str(p)] = target
        env.update(LD_LIBRARY_PATH=str(ns), LD_BIND_NOW='1', LI2_DEPENDENCY_FDS=','.join(str(x['fd']) for x in sealed['objects']))
        need(started['argv'] == prep['argv'] and started['environment'] == env and
             {k: started[v] for k, v in (('bytes', 'carrier_size'), ('sha256', 'carrier_sha256'))} ==
             fact(carrier) == case['backing'] and
             case['namespace'] == dict(manifest=fact(manifest), launch=fact(launch)),
             'actual exact lane-specific sealed carrier and namespace launch')

    def pipe_case(count, profile, control='normal'):
        nonlocal case_cursor
        program = programs[count]
        original, image = Path(program['path']), program['image']
        mode = check.PROFILES[profile]
        name = 'interval-' + str(count) + '-' + profile if control == 'normal' else 'interval-control-' + control
        case = q['cases'][case_cursor]
        case_cursor += 1
        need((case['name'], case['operations'], case['profile'], case['control'], case['status']) ==
             (name, count, profile, control, 'passed'), 'exact original fixed child inventory')
        carrier = Path(program['carriers'][profile]['path']) if mode == 'gated' else None
        ns = output / (name + '-namespace') if mode == 'gated' else None
        if carrier is not None:
            need(case['backing'] == fact(pin(binary(carrier))), 'exact profile-specific backing authority')
            image = dict(image, backing=case['backing'])
        command = tuple(pipe.command(tools['python'], original, mode, interpreter.parent, carrier, ns))
        row = rows[cursor]
        data = captures[name]
        prep = decode(data['preparation'])
        go, notify = (x['fd'] for x in prep['pipes'])
        values = {'{record_fd}': '3', '{go_fd}': str(go), '{notify_fd}': str(notify),
                  '{preparation}': str(private / (name + '.preparation')), '{control}': pipe.CONTROLS[control]}
        replay(name, [values.get(x, x) for x in command], 'interval', ENV,
               0 if control == 'normal' else None)
        need(row['control'] == control and
             all(case[k] == row[k] for k in ('pid', 'exit', 'reaped', 'timed_out')) and
             case['preparation'] == prep and case['captures'] == row['captures'],
             'actual child identity/outcome/preparation/capture joins')
        namespace_check(case, original, carrier, ns, program['objects'], prep, mode, int(pipe.CONTROLS[control]))
        rs, outst = (private / (name + '.record')).stat(), (private / (name + '.stdout')).stat()
        need(prep['observer'] == dict(fd=3, device=rs.st_dev, inode=rs.st_ino) and
             prep['stdout']['identity'][:2] == [outst.st_dev, outst.st_ino],
             'actual retained regular record/stdout objects match prepared child descriptors')
        if control == 'normal':
            layout = program['inspection']['layout'] if profile == 'native-reference' else \
                     gated_layout if profile == 'gated-observed' else None
            result = check.terminal(row, data['stdout'], data['stderr'], data['record'], prep,
                                    image=image, layout=layout, cpu=cpu,
                                    expected_command=command, profile=profile)
            need(row['accepted'] is True and row['error'] is None and row['exit'] == 0 and
                 result == row['terminal_validation'] == case['comparison'] and
                 case['operation_status'] == 'completed', 'original strict complete positive terminal replay')
        else:
            result = finite.protocol_failure(control, row, data['stdout'], data['stderr'], data['record'],
                                            prep, image, go, notify, check, reports, cpu)
            need(result == case['comparison'] and case['operation_status'] == 'protocol_failed',
                 'original exact failed protocol replay without performance credit')
        return case, data

    for index, count in enumerate((1, 256)):
        name = 'interval-program-' + str(count)
        directory = output / name
        original = pin(binary(directory / 'original'))
        argv = expand(templates[0], {'$cc_bin': tools['cc'], '$fixture_dir': fixture,
                      '$metadata': metadata, '$output': original, '$operations': count})
        units = [str(fixture / 'fixture.S'), str(fixture / 'native_reference.c'), str(metadata)]
        need([x for x in argv if x.endswith(('.c', '.S'))] == units and argv[-2:] == ['-o', str(original)] and
             argv.count('-DTFI_N=' + str(count)) == 1 and all(x in argv for x in
             ('-O2', '-g', '-Werror', '-nostdlib', '-no-pie', '-ffreestanding', '-fno-builtin', '-mgeneral-regs-only', '-mcmodel=large')),
             'unchanged exact three-TU fixed-N fixture link')
        program = dict(operations=count, path=str(original), recipe=fact(fixture_recipe),
                       argv=argv, status='passed', carriers={})
        flags = [x for x in argv[1:-2] if x not in units and not x.startswith('-Wl,')]
        _, out, err = replay(name + '-headers', [tools['cc'], *flags, '-M', '-MT', 'tf_interval', *units],
                             env=builder.environment)
        rules = out.decode().replace('\\\n', ' ').splitlines()
        need(not err and len(rules) == 3 and all(x.startswith('tf_interval: ') for x in rules),
             'all three actual fixture compiler include rules')
        program['headers'] = {str(pin(t)): fact(pin(t)) for line in rules for t in shlex.split(line.split(':', 1)[1])}
        need(set(units) <= set(program['headers']), 'every actual linked fixture source is authenticated')
        replay(name + '-link', argv, profile='interval_build', env=builder.environment)
        program['artifact'] = fact(original)
        program['inspection'] = inspect(name, original, 'tfi_native_record')
        program['image'] = check.elf(original.read_bytes(), interpreter, count, policy.native_policy)
        objects, description = namespace.plan(original, [interpreter.parent],
            bytes.fromhex(fact(original)['sha256']), bytes.fromhex(fact(interpreter)['sha256']))
        program['namespace_plan'], program['dependencies'] = description, []
        for item in objects:
            need(fact(pin(item['path']))['sha256'] == finite.H(item['bytes']), 'entire actual dependency source')
            program['dependencies'].append(dict(names=item['names'], **fact(pin(item['path']))))
            for alias in item['names']:
                pin(interpreter.parent / alias)
        for lane, actual_bridge in (('gated-observed', bridge), ('gated-timing', unobserved)):
            carrier = pin(binary(directory / (lane + '-carrier')))
            _, out, err = replay('interval-' + str(count) + '-' + lane + '-make',
                                 [tools['python'], carrier_tool, 'make', original, actual_bridge, carrier])
            identities = decode(out)
            need(not err and identities['original_sha256'] == fact(original)['sha256'] and
                 identities['bridge_sha256'] == fact(actual_bridge)['sha256'] and
                 identities['interpreter_sha256'] == fact(interpreter)['sha256'] and
                 identities['carrier_sha256'] == fact(carrier)['sha256'],
                 'actual original/interpreter/carrier and exact profile-specific bridge')
            program['carriers'][lane] = dict(path=str(carrier), **fact(carrier), identities=identities)
        need(program == q['programs'][index], 'complete actual program/build/source/namespace/carrier inventory')
        programs[count] = dict(program, objects=objects)
        native, nd = pipe_case(count, 'native-reference')
        gated, gd = pipe_case(count, 'gated-observed')
        comparison = check.pair(nd['record'], gd['record'], nd['stdout'], gd['stdout'],
            {'native': program['inspection']['layout'], 'gated': gated_layout},
            dict(program['image'], backing=gated['backing']), native['pid'], gated['pid'], cpu,
            native_fds=tuple(x['fd'] for x in native['preparation']['pipes']),
            gated_fds=tuple(x['fd'] for x in gated['preparation']['pipes']))
        nt, _ = pipe_case(count, 'native-timing')
        gt, gtd = pipe_case(count, 'gated-timing')
        observed_reports, timing_reports = reports.reports(gd['stderr']), reports.reports(gtd['stderr'])
        reports.completed(observed_reports, gated['pid'])
        reports.completed(timing_reports, gt['pid'])
        need(comparison['accepted'] is True and comparison['operations'] == count and
             comparison['native']['accepted'] is True and comparison['gated']['accepted'] is True and
             observed_reports['lease'] == timing_reports['lease'] and
             all(observed_reports['loader'][k] == timing_reports['loader'][k] for k in finite.SEMANTIC) and
             all(c['comparison']['output']['count'] == count and c['comparison']['output']['cpu'] == cpu
                 for c in (native, gated, nt, gt)),
             'full pair state and fixed complete observed/unobserved semantic equality')
        need(q['pairs'][index] == dict(operations=count, comparison=comparison, semantic_join=True,
             semantic_fields=list(finite.SEMANTIC)), 'exact complete original pair result')
        carrier = Path(program['carriers']['gated-timing']['path'])
        assets[count] = dict(original=original, interpreter=interpreter, carrier=carrier,
            image=copy.deepcopy(program['image']), gated_image=dict(program['image'], backing=fact(carrier)),
            namespace_plan=description, objects=objects,
            semantic=dict(lease=copy.deepcopy(timing_reports['lease']),
                          loader={k: timing_reports['loader'][k] for k in finite.SEMANTIC}))
    for control in finite.CONTROLS:
        pipe_case(1, 'gated-timing', control)
    original = Path(programs[1]['path'])
    for control in finite.FD_CONTROLS:
        name = 'interval-fd-' + control
        evidence = private / (name + '.evidence.json')
        preparation = private / (name + '.launch-preparation.json')
        case = q['cases'][case_cursor]
        case_cursor += 1
        argv = [tools['python'], fixture / 'negative_launch.py', '--kind', control, '--original', original,
                '--library-root', interpreter.parent, '--preparation', preparation,
                '--evidence', evidence, '--record-fd', '{record_fd}']
        row, out, err = replay(name, argv, profile='interval', expected=1, record=True)
        ev = decode(pin(binary(evidence)).read_bytes())
        data = captures[name]['record']
        result = finite.launcher_failure(control, row, out, err, data, ev, preparation, original,
            interpreter.parent, fixture, tools['python'], cpu, (private / (name + '.record')).stat())
        need(case == dict(name=name, operations=1, profile='launcher', control=control,
             status='passed', operation_status='pre_exec_refusal', comparison=result,
             **{k: row[k] for k in ('pid', 'exit', 'reaped', 'timed_out')}),
             'original actual pre-exec descriptor guard and exact failed-outcome identity')
    need(cursor == 40 and case_cursor == 17 and namespace_links == q['namespace_links'],
         'all fixed actual commands/subjects and sealed namespace aliases replayed')
    public = finite.summary(q)
    public['private_receipt'] = fact(path)
    expected = (json.dumps(public, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    need(pin(binary(private / 'public.json')).read_bytes() == expected,
         'exact complete public projection, preserving every failed-operation label')
    for module in tuple(sys.modules.values()):
        p = getattr(module, '__file__', None)
        if p and Path(p).resolve().is_relative_to(ROOT) and Path(p).suffix == '.py':
            p = pin(p)
            need(q['inputs'].get(str(p)) == fact(p), 'every replayed reader/import is qualification-bound')
    closure()
    need(fact(path)['sha256'] == sha, 'explicit qualification receipt remains unchanged after replay')
    record['interval_namespace_aliases'] = namespace_links
    record['interval_qualification'] = dict(receipt=dict(path=str(path), **fact(path)),
        commands=40, actual_children=17, normal_children=8, full_state_pairs=2,
        required_protocol_failures=5, required_pre_exec_refusals=4,
        public=fact(private / 'public.json'),
        qualification_credit='replayed complete same-revision finite receipt; no new target execution')
    return dict(tools=tools, programs=assets)
