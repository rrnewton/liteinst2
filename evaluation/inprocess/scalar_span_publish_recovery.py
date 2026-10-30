"""Recover numerical output from the closed, failed TRACE cohort.

No workload is launched or requalified. The original failed receipt is immutable.
The sole publisher correction renames a loop variable that hid its CSV buffer.
"""
import argparse
import hashlib
import importlib
import json
import platform
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[2]
PUBLISHER = 'evaluation/inprocess/scalar_span_trace_performance.py'
BEFORE = """    for ordinal,stream,size,sha in capture_rows:
        need(stream not in restored[str(ordinal)],'one actual capture stream per subject')
        restored[str(ordinal)][stream]=dict(bytes=size,sha256=sha)
"""
AFTER = """    for ordinal,capture_stream,size,sha in capture_rows:
        need(capture_stream not in restored[str(ordinal)],'one actual capture stream per subject')
        restored[str(ordinal)][capture_stream]=dict(bytes=size,sha256=sha)
"""


def require(value, message):
    if not value:
        raise ValueError(message)


def fact(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value


def read_json(data):
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'nonfinite JSON'))


def executed_modules():
    # checks.admission is executed with exec_module but is not in sys.modules.
    # Traverse actual module references too, retaining a finite discovery bound.
    pending = list(sys.modules.values())
    seen = set()
    while pending:
        module = pending.pop()
        if not isinstance(module, ModuleType) or id(module) in seen:
            continue
        seen.add(id(module))
        require(len(seen) <= 8192, 'bounded executed module closure')
        yield module
        pending.extend(value for value in tuple(vars(module).values())
                       if isinstance(value, ModuleType))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', required=True, type=Path)
    parser.add_argument('--receipt-sha256', required=True)
    parser.add_argument('--output-base', required=True, type=Path)
    args = parser.parse_args()
    receipt = args.receipt.resolve(strict=True)
    private = receipt.parent
    output = args.output_base.resolve()
    require(receipt.is_relative_to(ROOT / 'target/evaluation/inprocess') and
            receipt.name == 'receipt.json', 'closed private receipt location')
    require(output.is_relative_to(ROOT) and output.suffix == '.json', 'repository JSON destination')
    require(not output.exists() and not output.with_suffix('.csv').exists(), 'new output pair')
    original = receipt.read_bytes()
    projector = Path(__file__).read_bytes()
    require(fact(original)['sha256'] == args.receipt_sha256, 'exact supplied receipt digest')
    record = read_json(original)
    require(record['profile'] == 'scalar-span-trace-performance-v1' and
            record['status'] == 'failed' and record['error'] and
            record['source_unchanged'] is True and record['cleanup_complete'] is True and
            record['final_errors'] == [], 'failed cohort with complete process/source closure')
    revision = record['expected_revision']
    require(re.fullmatch('[0-9a-f]{40}', revision) and
            revision == record['source']['revision'], 'exact tested revision')
    inputs = record['inputs_before']
    keys = [key for key in inputs if key.endswith('/' + PUBLISHER)]
    require(len(keys) == 1, 'one actual original publisher input')
    old_root = keys[0][:-len(PUBLISHER)]
    result = subprocess.run(['git', 'show', revision + ':' + PUBLISHER], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=True)
    old = result.stdout
    require(fact(old) == inputs[keys[0]], 'tested publisher Git bytes')
    require(old.decode().count(BEFORE) == 1, 'one original shadowed loop')
    corrected = old.decode().replace(BEFORE, AFTER).encode()
    require((ROOT / PUBLISHER).read_bytes() == corrected, 'only the exact variable rename')
    schema = ROOT / 'evaluation/inprocess/page_selected_rseq_schema.json'
    schema_fact = inputs.get(old_root + str(schema.relative_to(ROOT)))
    require(fact(schema.read_bytes()) == schema_fact, 'executed reader schema input')
    imported = {schema: schema_fact}
    sys.dont_write_bytecode = True
    publisher = importlib.import_module('scalar_span_trace_performance')
    for module in executed_modules():
        name = getattr(module, '__file__', None)
        if not name:
            continue
        path = Path(name).resolve()
        if not path.is_relative_to(ROOT) or path == Path(__file__).resolve():
            continue
        relative = str(path.relative_to(ROOT))
        data = path.read_bytes()
        expected = fact(corrected) if relative == PUBLISHER else inputs.get(old_root + relative)
        require(expected == fact(data), 'every imported publisher dependency matches tested bytes')
        imported[path] = fact(data)
    cases = record['cases']
    require(len(cases) == 82 and [c['ordinal'] for c in cases] == list(range(82)) and
            tuple(f"{c['workload']}-{c['repeat']}-{c['lane']}" for c in cases) == publisher.NAMES,
            'all original fixed82 subjects in original order')
    commands = {c['name']: c for c in record['commands']}
    require(len(commands) == len(record['commands']), 'unique actual commands')
    counter_fields = ('events', 'offers', 'closed', 'resumed', 'plan_misses',
                      'publications', 'hits', 'entries', 'completed', 'plan_checks', 'rseq_checks')
    maps_fields = ('queries', 'hits', 'refreshes', 'comparisons', 'mismatches',
                   'updates', 'invalidations', 'unexplained', 'stack_probes')
    raw_rows = []
    for case, label in zip(cases, publisher.NAMES, strict=True):
        command = commands[label]
        require(case['exit'] == command['exit'] and case['reaped'] is True and
                command['reaped'] is True and command['cleanup_errors'] == [] and
                all(d['closed'] for d in command['descriptors']), 'actual subject and complete cleanup')
        stderr = None
        for stream, capture in command['captures'].items():
            path = private / capture['file']
            require(path.resolve().is_relative_to(private) and not path.is_symlink(), 'private capture')
            data = path.read_bytes()
            require(fact(data) == {k: capture[k] for k in ('bytes', 'sha256')} ==
                    case['captures'][stream], 'complete actual capture digest')
            if stream == 'stderr':
                stderr = data
        if case['status'] != 'failed' or case['exit'] != 0:
            continue
        require(case['lane'] in ('span-trace', 'differential') and stderr is not None,
                'unqualified terminal counter domain')
        parsed = []
        for prefix in (b'LI2_SCALAR_SPAN ', b'LI2_MAPS_VIEW '):
            lines = [line[len(prefix):] for line in stderr.splitlines() if line.startswith(prefix)]
            require(len(lines) == 1, 'one actual unqualified producer row')
            parsed.append(read_json(lines[0]))
        span, view = parsed
        numbers = [span[key] for key in counter_fields] + span['signals'] + span['refusals'] + [
            view[key] for key in maps_fields]
        require(len(span['signals']) == 5 and len(span['refusals']) == 4 and
                all(type(v) is int and 0 <= v < 1 << 64 for v in numbers), 'typed counter observations')
        raw_rows.append([case['ordinal'], *numbers, fact(stderr)['sha256']])
    # The corrected original publisher determines every old field and retains
    # its original all82 gate. It cannot grant timing credit to this failed run.
    with tempfile.TemporaryDirectory(prefix='trace-publish-', dir=ROOT / 'target') as temporary:
        staged = Path(temporary) / output.name
        publisher.publish(staged, record, private)
        public = read_json(staged.read_bytes())
        csv = staged.with_suffix('.csv').read_bytes()
    require(public['status'] == 'failed' and all(
        row['timing_credit'] is False for workload in public['statistics'].values()
        for row in workload.values()), 'no aggregate timing or retrospective qualification')
    public['publication_recovery'] = dict(
        original_exception='AttributeError: CSV buffer shadowed by capture-stream loop variable',
        original_publisher=fact(old), corrected_publisher=fact(corrected),
        projector=fact(projector),
        scope='Data-only publication recovery. Original failed receipt, cases and gates unchanged; no new workload or qualification.',
        reproduce=['python3', 'evaluation/inprocess/scalar_span_publish_recovery.py',
                   '--receipt', str(receipt.relative_to(ROOT)), '--receipt-sha256', args.receipt_sha256,
                   '--output-base', '${NEW_OUTPUT_JSON}'])
    public['unqualified_terminal_counters'] = dict(
        scope='Typed values from authenticated stderr of failed qualification cases that exited zero. No terminal validation, aggregate timing or speedup credit.',
        columns=['ordinal', *('span.' + k for k in counter_fields),
                 *('signal.' + k for k in ('SEGV', 'TRAP', 'ILL', 'SYS', 'other')),
                 *('refusal.' + k for k in ('unsupported', 'boundary', 'graph', 'relocation')),
                 *('maps.' + k for k in maps_fields), 'stderr_sha256'], rows=raw_rows)
    text = json.dumps(public, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n'
    require(len(text.encode()) < 96 << 10 and len(csv) < 32 << 10, 'original public size caps')
    require(not any(value and len(value) > 1 and (value in text or value in csv.decode())
                    for value in (str(ROOT), str(Path.home()), platform.node(), '/home/')), 'public privacy')
    require(receipt.read_bytes() == original and Path(__file__).read_bytes() == projector and
            all(fact(path.read_bytes()) == expected
            for path, expected in imported.items()), 'immutable receipt and imported sources')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.with_suffix('.csv').open('xb') as file:
        file.write(csv)
    with output.open('x') as file:
        file.write(text)
    print(json.dumps(dict(status='failed_cohort_published', cases=82,
                          qualified=sum(c['status'] == 'passed' for c in cases),
                          unqualified_counter_rows=len(raw_rows), json=fact(text.encode()), csv=fact(csv))))


if __name__ == '__main__':
    main()
