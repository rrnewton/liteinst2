#!/usr/bin/env python3
"""Run the unchanged twenty connected cases plus two actual embedded CPUID entries."""
import json
from pathlib import Path
import platform
import sys

sys.dont_write_bytecode = True
import page_selected_generic as base
import page_selected_embedded_compare as embedded


def check(spec, row, command, stdout, native, before, after, decoded, original, observe, run):
    """Five additional actual decoder commands; the existing comparator is reused."""
    rows = {item['name']: item for item in spec['rows']}
    observed = {}
    for name in ('enclosing_mov', 'embedded_cpuid', 'call_embedded', 'embedded_jump', 'embedded_ret'):
        item = rows[name]
        _, out, err = run('decode-'+name+'-'+spec['name'],
                         [observe, 'decode', str(item['pc']), item['bytes']])
        base.need(not err, 'embedded decoder observer stderr')
        observed[name] = json.loads(out)
    return embedded.check(spec, row, command, stdout, native, before, after, decoded,
                          original.read_bytes(), observed)


def publish(path, receipt, private, aliases, *, repeat=False):
    """Project already checked rows; full attempts and captures remain private."""
    del aliases  # No actual argv or external path is copied into this projection.
    build = receipt.get('build', {})
    commands = receipt['commands']
    fields = ('status', 'failure_code', 'nx_faults', 'selected_steps', 'generic_tf_attempts',
              'generic_tf_steps', 'rdrand', 'rdseed', 'rdpid', 'cpuid', 'rdtsc', 'rdtscp',
              'source_syscalls', 'syscalls', 'forwarded')

    def counters(row):
        return {name: row[name] for name in fields if name in row}

    def error_type(value):
        return value.split(':', 1)[0] if value else None

    gated_exits = {row['name'][6:]: row.get('exit') for row in commands if row['name'].startswith('gated-')}
    cases = []
    for case in receipt['cases']:
        row = case.get('result', {})
        outcome = case.get('outcome', {})
        # Missing/failed cases never acquire success from a summary label.
        classification = ('incomplete' if not case['accepted'] else
                          'expected_refusal' if row.get('failure_code') else 'completed')
        item = dict(name=case['name'], accepted=case['accepted'],
            classification=classification, native_exit=case.get('native_exit'),
            gated_exit=gated_exits.get(case['name']), counters=counters(row),
            values={key: outcome[key] for key in ('cpuid0', 'r10', 'actual_call_return_pc', 'source_patches',
                'output_words', 'native_tsc', 'gated_tsc', 'before_tsc', 'after_tsc', 'aux') if key in outcome})
        if row.get('selected_last_kind'):
            item['selected_outcome'] = {key: row['selected_last_'+key] for key in
                ('kind', 'width', 'value', 'carry', 'input_destination', 'output_destination')}
        if case.get('repeat') is not None:
            r = case['repeat']
            item['repeat'] = {k: r[k] for k in ('attempts', 'completed', 'traces', 'queries')}
            item['repeat_report_sha256'] = base.digest(r)
        cases.append(item)
    diagnostic = receipt.get('ls_diagnostic')
    if diagnostic is not None:
        row = diagnostic['result']
        diagnostic = dict(status=diagnostic['status'], counters=counters(row),
            refusal={key: row[key] for key in ('detail_abs', 'detail_negative', 'tf_error', 'tf_code',
                'tf_length', 'tf_phase', 'step_route') if key in row},
            opcode_bytes=diagnostic.get('bytes'), original=diagnostic['original'],
            interpreter=diagnostic['interpreter'])
        if receipt['ls_diagnostic'].get('repeat') is not None:
            r = receipt['ls_diagnostic']['repeat']
            diagnostic['repeat'] = {k: r[k] for k in ('attempts', 'completed', 'traces', 'queries')}
            diagnostic['repeat_report_sha256'] = base.digest(r)
    public = {key: receipt.get(key) for key in ('schema', 'profile', 'status', 'scope', 'expected_revision',
        'started_utc', 'cpu', 'hardware', 'source', 'source_unchanged', 'environment', 'bounds', 'reproduce',
        'cohort_command_count', 'finite_command_count', 'hardware_observer')}
    public.update(
        required_cases=32 if repeat else 22, required_finite_commands=168 if repeat else 98,
        attempted_cases=len(cases), accepted_cases=sum(case['accepted'] is True for case in cases),
        completed_cases=sum(case['classification'] == 'completed' for case in cases),
        expected_refusals=sum(case['classification'] == 'expected_refusal' for case in cases),
        cases=cases, ls_diagnostic=diagnostic,
        commands=dict(attempted=len(commands),
            reaped=sum(row.get('reaped') is True for row in commands),
            timeouts=sum(row.get('timed_out') is True for row in commands),
            errors=sum(bool(row.get('error')) for row in commands),
            cleanup_errors=sum(len(row.get('cleanup_errors', [])) for row in commands),
            nonzero_exits=sum(type(row.get('exit')) is int and row['exit'] != 0 for row in commands),
            observed_duration_ns=sum(row['duration_ns'] for row in commands
                                     if type(row.get('duration_ns')) is int)),
        private_receipt=base.fact(private/'receipt.json'),
        command_rows_sha256=base.digest(commands), case_rows_sha256=base.digest(receipt['cases']),
        diagnostic_sha256=base.digest(receipt.get('ls_diagnostic')),
        input_manifest_sha256=base.digest(receipt['inputs_before']),
        artifact_manifest_sha256=base.digest(receipt['artifacts_before']),
        build_status=build.get('status'), build_command_completed=build.get('command_completed'),
        configuration_unchanged=build.get('configuration_unchanged'),
        tool_versions=build.get('numeric_versions'), tool_bindings_sha256=base.digest(build.get('tools', {})),
        build_evidence_sha256=base.digest(build),
        artifacts={name: {key: item[key] for key in ('bytes', 'sha256', 'mode')}
                   for name, item in build.get('artifacts', {}).items()},
        failure_type=error_type(receipt.get('error')), final_error_count=len(receipt['final_errors']),
        command_recipe=dict(build=['sh', 'tools/page-entry/selected/build.sh'],
            images=['python3', 'evaluation/inprocess/page_selected_embedded_images.py', '${RUN}/images'],
            old_twenty='76-command prefix preserves the old twenty cases; the image command appends two new artifacts.',
            each_embedded=['make-carrier', 'before-clock', 'native-original', 'gated-carrier', 'after-clock',
                'decode-last-generic', 'decode-enclosing_mov', 'decode-embedded_cpuid', 'decode-call_embedded',
                'decode-embedded_jump', 'decode-embedded_ret'],
            ls=['make-carrier', 'native /bin/ls -d .', 'gated /bin/ls -d .',
                'decode-ls-refusal only on exact unsupported-opcode outcome'],
            evidence='Private receipt retains ordered exact argv, environments, bounds, outcomes, namespace bindings and capture hashes.'))
    if repeat:
        public['command_recipe']['images'] = ['python3', 'evaluation/inprocess/page_selected_repeat_images.py', '${RUN}/images']
        public['command_recipe']['each_repeat'] = ['make-carrier', 'before-clock', 'native-original', 'gated-carrier', 'after-clock', 'decode-last-generic', 'decode-last-repeat']
        public['command_recipe']['old_twenty_two'] = 'The entire old 98-command finite prefix remains required.'
    text = json.dumps(public, indent=2, sort_keys=True, allow_nan=False)+'\n'
    base.need(not any(value and len(value) > 1 and value in text for value in
                     (str(Path.home()), str(base.ROOT), platform.node(), '/home/')),
              'private location in public receipt')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output:
        output.write(text)


if __name__ == '__main__':
    raise SystemExit(base.main(embedded=True))
