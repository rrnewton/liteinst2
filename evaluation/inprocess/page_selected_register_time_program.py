"""One completed original-program lane and its genuine uninstrumented baseline."""
from pathlib import Path
import hashlib
from page_selected_register_real import resolved_libraries
from page_selected_register_time_compare import decode, parse, qualify
from page_selected import fact, interpreter, need


def execute(name, mode, selected, bridge, original, interp, extra, expected_stdout,
            disabled, namespace_api, builder, root, private, pin, binary, run, receipt, env, digest):
    row = dict(name=name, mode=mode, status='failed', environment=env,
               original=fact(original), interpreter=fact(interp), bridge=fact(bridge))
    receipt['programs'].append(row)
    objects, _ = namespace_api.plan(original, [Path('/usr/lib64')],
        bytes.fromhex(fact(original)['sha256']), bytes.fromhex(fact(interp)['sha256']))
    expected = {interp: set()}
    row['planned_dependencies'] = []
    for item in objects:
        path = pin(item['path']);expected.setdefault(path, set()).update(item['names'])
        need(fact(path)['sha256'] == hashlib.sha256(item['bytes']).hexdigest(), 'actual planned dependency bytes')
        row['planned_dependencies'].append(dict(source=str(path), names=item['names'],
                                               needed=item['info']['needed'], **fact(path)))
    _, listing, err = run('libraries-'+name, [interp, '--list', original], profile='metadata', env=env)
    need(not err, 'native loader listing stderr')
    resolved_libraries(listing, expected, interp, pin)
    carrier = private/('carrier-'+name)
    python = builder.tools['python']
    run('make-'+name, [python, root/'tools/page-entry/carrier.py', 'make', original, bridge, carrier], env=env)
    binary(carrier);need(interpreter(carrier) == bridge, 'actual timing interpreter')
    native, output, err = run('native-'+name, [original, *extra], profile='program', env=env)
    row['native_exit'] = native['exit']
    need(output == expected_stdout and not err, 'genuine unrestricted original-program output')
    directory = private/('namespace-'+name)
    argv = [python, root/'tools/page-entry/carrier.py', 'exec-loader', '--library-root', '/usr/lib64',
            '--namespace', directory]
    if disabled:argv.append('--disable-rseq')
    gated, actual, stderr = run('gated-'+name, [*argv, carrier, original, '--', original, *extra],
                               expected=None, profile='program', env=env)
    row.update(gated_exit=gated['exit'], native_capture=native['captures'], gated_capture=gated['captures'],
        whole_process_ns=dict(native=native['duration_ns'], gated=gated['duration_ns']))
    ns = decode(binary(directory/'namespace.json').read_bytes())
    launch = decode(binary(directory/'launch.json').read_bytes())
    need(len(ns['objects']) == len(objects) and ns['original_sha256'] == fact(original)['sha256'] and
         ns['interpreter_sha256'] == fact(interp)['sha256'], 'exact actual namespace roots')
    wanted = {str(x['path']): x for x in objects}
    need({x['source'] for x in ns['objects']} == set(wanted), 'complete actual sealed object set')
    for item in ns['objects']:
        before = wanted[item['source']]
        need(item['seals'] == 15 and fact(pin(item['source']))['sha256'] == item['sha256'] and
             item['names'] == before['names'] and item['needed'] == before['info']['needed'], 'sealed dependency identity')
    target_env = {k: env[k] for k in ('PATH', 'LANG', 'LC_ALL', 'TZ', 'LD_BIND_NOW')}
    target_env.update(LD_LIBRARY_PATH=str(directory),
                      LI2_DEPENDENCY_FDS=','.join(str(x) for x in launch['dependency_fds']))
    if disabled:target_env['GLIBC_TUNABLES'] = env['GLIBC_TUNABLES']
    need(launch['environment'] == target_env and launch['argv'] == list(map(str, [original, *extra])) and
         launch['carrier_sha256'] == fact(carrier)['sha256'] and
         launch['dependency_fds'] == [x['fd'] for x in ns['objects']], 'actual environment/argv/carrier/FD join')
    row.update(namespace={n: fact(directory/n) for n in ('namespace.json', 'launch.json')},
               launch_environment_sha256=digest(target_env))
    report = parse(stderr);row['report'] = report
    need(gated['exit'] == report['loader']['status'], 'actual terminal exit equals report')
    need(gated['exit'] == 0 and actual == output == expected_stdout, 'completed entire program before any timing credit')
    value = qualify(report, fact(interp)['sha256'], mode, selected)
    row.update(status='completed', qualified=value)
    return value
