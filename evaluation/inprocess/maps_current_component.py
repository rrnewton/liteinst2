"""Twenty-eight component attempts; supplied owner boundaries, no TF credit."""
import importlib.util
from pathlib import Path

import maps_view as donor


MODES = tuple((profile, mode) for profile in ('projected', 'verified') for mode in range(14))
MACROS = ('MAPS_PHASE_REUSE', 'MAPS_MAINTAINED', 'TF_HANDOFF', 'TF_SAME_PAGE_LEASE',
          'TF_SEALED_CUSTODY', 'RSEQ_INACTIVE', 'MAPS_CURRENT_TF')


def fixture(builder, products, private, pin, binary, aliases, run, receipt):
    selected = donor.SELECTED; leaf = selected / 'tests/maps_current_custody'
    recipe = pin(leaf / 'build.sh'); oracle = pin(leaf / 'oracle.c'); check = pin(leaf / 'check.py')
    spec = importlib.util.spec_from_file_location('maps_current_component_check', check)
    reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
    donor.need(reader.CONTROL_COUNT == 25, 'fixed complete supplied-record control population')
    commands = donor.recipe(recipe, '"$cc_bin"')
    donor.need(len(commands) == 1 and commands[0].count('$differential') == 1,
               'one explicit component link and one closed optional macro position')
    archive = products['archive']
    donor.need(builder.extra_decoder_sources == () and builder.decoder_features == () and
               builder.record['decoder_features'] == [], 'actual original default decoder archive')
    builds = receipt['current_component_builds'] = {}; executables = {}
    for profile in ('projected', 'verified'):
        output = private / ('component-' + profile); output.mkdir()
        values = {'$cc_bin': builder.tools['cc'], '$selected_dir': selected,
                  '$parent_dir': selected.parent, '$fixture_dir': leaf,
                  '$archive': archive, '$output_dir': output}
        argv = []
        for word in commands[0]:
            if word == '$differential':
                if profile == 'verified': argv.append('-DLI2_MAPS_DIFFERENTIAL=1')
            else: argv.extend(donor.expand([word], values))
        expected = MACROS + (('MAPS_DIFFERENTIAL',) if profile == 'verified' else ())
        donor.need([x for x in argv if x.startswith('-D')] == ['-DLI2_' + x + '=1' for x in expected]
                   and [x for x in argv if x.endswith(('.c', '.S'))] == [str(oracle)]
                   and argv.count(str(archive)) == 1 and argv[-2:] == ['-o', str(output / 'maps-current-custody')]
                   and all(x in argv for x in ('-O2', '-g', '-fno-builtin', '-mgeneral-regs-only', '-Werror')),
                   'exact whole lifecycle-TU recipe and original decoder archive')
        state = builds[profile] = dict(status='failed', recipe=donor.fact(recipe),
                                       archive=donor.fact(archive), argv=argv)
        donor.headers(profile + '-component-headers', argv, [str(oracle)], archive,
                      builder, pin, aliases, run, state)
        required = ('lifecycle_loader.c', 'maps_phase.inc', 'maps_view.inc', 'maps_current_ticket.inc',
                    'fetch_loader.inc', 'fetch_rx_transfer.inc', 'fetch_page_custody.inc',
                    'fetch_current_view.inc', 'fetch_current_custody.inc', 'decoder.h')
        donor.need(all(str((selected / p).resolve()) in state['headers'] for p in required),
                   'actual complete original and current implementation/decoder closure')
        _, out, err = run(profile + '-component-link', argv, profile='finite_build', env=builder.environment)
        donor.need(out == err == b'', 'whole component link without diagnostics')
        executable = binary(output / 'maps-current-custody'); state['executable'] = donor.fact(executable)
        data, head, segments = donor.elf(executable)
        donor.need(head[1] in (2, 3) and any(p[0] == 1 and p[1] == 5 and
                   p[3] <= head[4] < p[3] + p[6] for p in segments) and
                   all(not (p[1] & 1 and p[1] & 2) for p in segments if p[0] in (1, 0x6474e551)),
                   'actual executable entry and no writable executable load or stack')
        interp = pin(donor.interpreter(executable))
        spec = importlib.util.spec_from_file_location('current_component_namespace', pin(selected.parent / 'namespace.py'))
        namespace = importlib.util.module_from_spec(spec); spec.loader.exec_module(namespace)
        donor.need(pin(namespace.parse(data)['interpreter']) == interp, 'actual fixture interpreter alias')
        objects, description = namespace.plan(executable, [Path('/usr/lib64')],
            bytes.fromhex(donor.H(data)), bytes.fromhex(donor.fact(interp)['sha256']))
        expected_libraries = {interp: set()}
        for obj in objects:
            path = pin(obj['path']); donor.need(donor.fact(path)['sha256'] == donor.H(obj['bytes']),
                                               'whole actual fixture library identity')
            expected_libraries.setdefault(path, set()).update(obj['names'])
        state['runtime_inputs'] = dict(interpreter=donor.fact(interp),
            dependencies=[dict(names=o['names'], **donor.fact(o['path'])) for o in objects])
        state['namespace_plan'] = description
        _, out, err = run(profile + '-component-libraries', [interp, '--list', executable],
                          profile='inspect', env=donor.PROGRAM_ENV)
        donor.need(not err, 'actual fixture loader listing stderr')
        donor.resolved_libraries(out, expected_libraries, interp, pin)
        state['status'] = 'passed'; executables[profile] = executable
    donor.need([(c['profile'], c['mode']) for c in receipt['component_cases']] == list(MODES),
               'exact fixed twenty-eight cases')
    for case in receipt['component_cases']:
        profile, mode = case['profile'], case['mode']; name = 'current-' + profile + '-' + str(mode)
        case['status'] = 'failed'
        try:
            row, out, err = run(name, [executables[profile], str(mode)], profile='finite',
                                expected=case['expected_exit'], env=donor.PROGRAM_ENV)
            case['result'] = reader.check(out, err, row['exit'], mode, int(profile == 'verified'))
            case['controls'] = reader.controls(out, err, row['exit'], mode, int(profile == 'verified'))
            donor.need(case['controls'] == {'refusals': 25, 'native_operations': 0},
                       'every fixed supplied-record refusal, no native credit')
            case['status'] = 'qualified_component' if mode < 3 else 'qualified_required_refusal'
        except Exception as exc:
            case['error'] = type(exc).__name__ + ': ' + str(exc)
            if receipt['error'] is None: receipt['error'] = case['error']
            last = receipt['commands'][-1] if receipt['commands'] else {}
            donor.need(last.get('name') == name and last.get('reaped') is True and
                       last.get('cleanup_errors') == [] and isinstance(last.get('descriptors'), list) and
                       all(d.get('closed') is True for d in last['descriptors']),
                       'continue only after exact component subject reaped and every descriptor closed')
        finally:
            observed = [r for r in receipt['commands'] if r['name'] == name]
            donor.need(len(observed) <= 1, 'one attempt per fixed component case')
            if observed:
                row = observed[0]
                case.update(exit=row.get('exit'), duration_ns=row.get('duration_ns'),
                    launched=type(row.get('pid')) is int, timed_out=row.get('timed_out'),
                    captures={k: {n: v[n] for n in ('bytes', 'sha256')}
                              for k, v in row.get('captures', {}).items()})
    donor.need(all(c['status'] == ('qualified_component' if c['mode'] < 3 else 'qualified_required_refusal')
                   for c in receipt['component_cases']) and
               sum(c.get('controls', {}).get('refusals', 0) for c in receipt['component_cases']) == 700,
               'all twenty-eight actual cases and seven hundred supplied refusals')
