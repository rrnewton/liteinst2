"""Six additional retired-view paths; original28 remain independently mandatory."""
import importlib.util
from pathlib import Path

import maps_view as donor


MODES = tuple((profile, mode) for profile in ('projected', 'verified') for mode in range(3))
MACROS = ('MAPS_PHASE_REUSE', 'MAPS_MAINTAINED', 'TF_HANDOFF', 'TF_SAME_PAGE_LEASE',
          'TF_SEALED_CUSTODY', 'RSEQ_INACTIVE', 'MAPS_CURRENT_TF')


def fixture(builder, products, private, pin, binary, aliases, run, receipt):
    selected = donor.SELECTED; leaf = selected / 'tests/maps_current_fallback'
    recipe = pin(leaf / 'build.sh'); oracle = pin(leaf / 'oracle.c'); check = pin(leaf / 'check.py')
    spec = importlib.util.spec_from_file_location('maps_current_fallback_check', check)
    reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(reader)
    donor.need(reader.CONTROL_COUNT == 32, 'fixed complete supplied-record control population')
    commands = donor.recipe(recipe, '"$cc_bin"')
    donor.need(len(commands) == 1 and commands[0].count('$differential') == 1,
               'one explicit component link and one closed optional macro position')
    archive = products['archive']
    donor.need(builder.extra_decoder_sources == () and builder.decoder_features == () and
               builder.record['decoder_features'] == [], 'actual original default decoder archive')
    builds = receipt['fallback_component_builds'] = {}; executables = {}
    for profile in ('projected', 'verified'):
        output = private / ('fallback-component-' + profile); output.mkdir()
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
                   and argv.count(str(archive)) == 1 and argv[-2:] == ['-o', str(output / 'maps-current-fallback')]
                   and all(x in argv for x in ('-O2', '-g', '-fno-builtin', '-mgeneral-regs-only', '-Werror')),
                   'exact whole lifecycle-TU recipe and original decoder archive')
        state = builds[profile] = dict(status='failed', recipe=donor.fact(recipe),
                                       archive=donor.fact(archive), argv=argv)
        donor.headers(profile + '-fallback-headers', argv, [str(oracle)], archive,
                      builder, pin, aliases, run, state)
        required = ('lifecycle_loader.c', 'maps_phase.inc', 'maps_view.inc', 'maps_current_ticket.inc',
                    'fetch_loader.inc', 'fetch_rx_transfer.inc', 'fetch_page_custody.inc',
                    'fetch_current_view.inc', 'fetch_current_custody.inc', 'decoder.h',
                    'tests/maps_current_custody/oracle.c')
        donor.need(all(str((selected / p).resolve()) in state['headers'] for p in required),
                   'actual complete original and current implementation/decoder closure')
        _, out, err = run(profile + '-fallback-link', argv, profile='finite_build', env=builder.environment)
        donor.need(out == err == b'', 'whole component link without diagnostics')
        executable = binary(output / 'maps-current-fallback'); state['executable'] = donor.fact(executable)
        data, head, segments = donor.elf(executable)
        donor.need(head[1] in (2, 3) and any(p[0] == 1 and p[1] == 5 and
                   p[3] <= head[4] < p[3] + p[6] for p in segments) and
                   all(not (p[1] & 1 and p[1] & 2) for p in segments if p[0] in (1, 0x6474e551)),
                   'actual executable entry and no writable executable load or stack')
        interp = pin(donor.interpreter(executable))
        spec = importlib.util.spec_from_file_location('fallback_component_namespace', pin(selected.parent / 'namespace.py'))
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
        _, out, err = run(profile + '-fallback-libraries', [interp, '--list', executable],
                          profile='inspect', env=donor.PROGRAM_ENV)
        donor.need(not err, 'actual fixture loader listing stderr')
        donor.resolved_libraries(out, expected_libraries, interp, pin)
        state['status'] = 'passed'; executables[profile] = executable
    donor.need([(c['profile'], c['mode']) for c in receipt['fallback_cases']] == list(MODES),
               'exact fixed six additional cases')
    for case in receipt['fallback_cases']:
        profile, mode = case['profile'], case['mode']; name = 'fallback-' + profile + '-' + str(mode)
        case['status'] = 'failed'
        try:
            row, out, err = run(name, [executables[profile], str(mode)], profile='finite',
                                expected=case['expected_exit'], env=donor.PROGRAM_ENV)
            case['result'] = reader.check(out, err, row['exit'], mode, int(profile == 'verified'))
            case['controls'] = reader.controls(out, err, row['exit'], mode, int(profile == 'verified'))
            donor.need(donor.digest(case['controls']) == donor.digest({'refusals': 32, 'native_operations': 0}),
                       'every fixed supplied-record refusal, no native credit')
            case['status'] = 'qualified_component' if mode == 0 else 'qualified_required_refusal'
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
    donor.need(all(c['status'] == ('qualified_component' if c['mode'] == 0 else 'qualified_required_refusal')
                   for c in receipt['fallback_cases']) and
               sum(c.get('controls', {}).get('refusals', 0) for c in receipt['fallback_cases']) == 192,
               'all six actual companion cases and192 supplied refusals')


def project(receipt):
    rows=[]
    for case in receipt['fallback_cases']:
        row={k:case.get(k) for k in ('profile','mode','expected_exit','status','exit','launched','duration_ns','timed_out','captures')}
        row.update(result=case.get('result'),reader_refusals=case.get('controls',{}).get('refusals',0),
                   error_type=(case.get('error')or'').split(':',1)[0]or None)
        rows.append(row)
    return dict(scope='additional retired-view component only',cases=rows,
        totals=dict(required_cases=6,launched=sum(c.get('launched')is True for c in rows),
            qualified=sum(c['status']in('qualified_component','qualified_required_refusal')for c in rows),
            completed=sum(c['status']=='qualified_component'for c in rows),
            required_api_refusals=sum(c['status']=='qualified_required_refusal'for c in rows),
            supplied_record_refusals=sum(c['reader_refusals']for c in rows)))


def prerequisite(public,actual):
    rows=actual['fallback_cases']
    donor.need([(c['profile'],c['mode'])for c in rows]==list(MODES) and all(
        c['status']==('qualified_component'if m==0 else 'qualified_required_refusal') and
        c['launched']is True and c['exit']==c['expected_exit']==(0 if m==0 else 125) and
        donor.digest(c['controls'])==donor.digest(dict(refusals=32,native_operations=0))
        for c,(p,m)in zip(rows,MODES,strict=True)), 'all six real companion outcomes and192 supplied refusals')
    builds=actual['fallback_component_builds']
    donor.need(set(builds)=={'projected','verified'} and all(b['status']=='passed' and
        b['archive']==actual['archive'] for b in builds.values()),
        'both exact default-archive companion builds with full input/artifact closure')
    value=project(actual)
    donor.need(donor.digest(public['fallback_component'])==donor.digest(value) and
        donor.digest(value['totals'])==donor.digest(dict(required_cases=6,
        launched=6,qualified=6,completed=2,required_api_refusals=4,supplied_record_refusals=192)),
        'complete exact companion public/private projection and mandatory population')
    return value['totals']
