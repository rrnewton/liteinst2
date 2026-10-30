#!/usr/bin/env python3
"""Prepare/check one perf command-metadata probe; never a performance verdict.

Execution belongs to tools/unwind-oracle/bounded_command.py. Its closed receipt
must precede inspection. Raw capture, command paths and logs stay under ignored/.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

if not __debug__:
    raise SystemExit('assertions required')
ROOT = Path(__file__).resolve().parents[2]


def pin(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def command(raw):
    argv = [str(raw/'perf'), 'record', '-e', 'instructions:uDS', '-c', '4096',
            '-P', '-T', '--sample-cpu', '--sample-identifier', '--running-time',
            '-s', '--inherit', '-m', '256', '--no-buildid-cache',
            '--no-buildid-mmap', '--buildid-all', '-o', str(raw/'perf.data'),
            '--', '/usr/bin/true', 'one spaced argument', 'literal"quote',
            '--', 'literal$(unchanged)']
    argv += ['word'+str(i) for i in range(40-len(argv))]
    assert len(argv) == 40
    return argv


def request_for(raw):
    return dict(argv=command(raw), cwd=str(ROOT), env=dict(
        PATH='/usr/bin:/bin', HOME=str(raw/'home'), XDG_CONFIG_HOME=str(raw/'config'),
        XDG_CACHE_HOME=str(raw/'cache'), PERF_BUILDID_DIR=str(raw/'buildid'),
        PERF_CONFIG=str(raw/'empty-config'), PERF_CONFIG_NOSYSTEM='1',
        PERF_CONFIG_NOGLOBAL='1', LC_ALL='C', LANG='C', PYTHONDONTWRITEBYTECODE='1'),
        stdout=str(raw/'stdout'), stderr=str(raw/'stderr'),
        cpu_seconds=20, wall_seconds=30, file_bytes=16*1024*1024)


def input_files(raw):
    return [raw/'perf', Path('/usr/bin/true'), raw/'request.json', raw/'empty-config',
             ROOT/'tools/rapid-profiler/tree-work/perf_data.py',
             ROOT/'tools/rapid-profiler/tree-work/perf_records.py',
             ROOT/'tools/unwind-oracle/bounded_command.py']


def prepare(raw, producer):
    assert raw.is_relative_to(ROOT/'ignored') and not raw.exists()
    assert producer.is_file() and producer.stat().st_size <= 64*1024*1024
    raw.mkdir()
    shutil.copy2(producer, raw/'perf')
    assert pin(producer) == pin(raw/'perf')
    for name in ('home', 'config', 'cache', 'buildid'):
        (raw/name).mkdir()
    (raw/'empty-config').write_bytes(b'')
    save(raw/'request.json', request_for(raw))
    save(raw/'inputs.json', {str(path): pin(path) for path in input_files(raw)})


def inspect(raw):
    assert raw.is_relative_to(ROOT/'ignored') and raw.is_dir()
    receipt = json.loads((raw/'receipt.json').read_text())
    assert receipt['absence_proof'] == 'ECHILD' and receipt['cleanup_error'] is None
    assert receipt['exit'] == 0 and receipt['wall_timeout'] is False
    assert receipt['aborted'] is None and receipt['cleanup_events'] == []
    assert receipt['unexpected_descendants'] == [] and receipt['inputs_unchanged'] is True
    pins = json.loads((raw/'inputs.json').read_text())
    normalized = {(ROOT/Path(name)).resolve(strict=True): value for name, value in pins.items()}
    required = {path.resolve(strict=True) for path in input_files(raw)}
    assert set(normalized) == required and len(normalized) == len(pins) == 7
    for path, expected in normalized.items():
        assert set(expected) == {'bytes', 'sha256'} and type(expected['bytes']) is int
        assert pin(path) == expected
    assert receipt['request_sha256'] == pin(raw/'request.json')['sha256']
    assert receipt['helper_sha256'] == pin(ROOT/'tools/unwind-oracle/bounded_command.py')['sha256']
    for name in ('stdout', 'stderr'):
        assert receipt[name+'_sha256'] == pin(raw/name)['sha256']
    request = json.loads((raw/'request.json').read_text())
    assert request == request_for(raw)
    directory = ROOT/'tools/rapid-profiler/tree-work'
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location('command_probe_decoder', directory/'perf_data.py')
    decoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decoder)
    assert (raw/'perf.data').stat().st_size <= 16*1024*1024
    data = (raw/'perf.data').read_bytes()
    expected = [word.encode('utf-8') for word in request['argv']]
    strict = decoder.decode(data, expected_cmdline=expected)
    diagnostic = decoder.decode_context_diagnostic(data, expected_cmdline=expected)
    feature = next(row for row in strict['features'] if row['id'] == 11)
    assert feature['argv'] == expected and len(feature['argv']) == 40
    changed = expected.copy()
    changed[-1] = b'changed-authority'
    mutant = decoder.decode(data, expected_cmdline=changed)
    assert mutant['summary']['status'] == 'REFUSED'
    assert mutant['error']['code'] == 'cmdline_authority_mismatch'
    # A successful metadata predicate never changes the full decoder's status.
    result = dict(schema='perf-command-metadata-v1',
        scope='Command metadata equality only; no sample attribution or performance verdict',
        capture=pin(raw/'perf.data'), producer=pin(raw/'perf'),
        request_sha256=pin(raw/'request.json')['sha256'],
        decoder_sha256=pin(directory/'perf_data.py')['sha256'],
        expected_words=40, observed_words=len(feature['argv']), argv_equal=True,
        strict=strict['summary'], diagnostic=diagnostic['summary'], mutant=mutant['summary'])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=('prepare', 'inspect'))
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--producer', type=Path)
    args = parser.parse_args()
    assert (args.producer is not None) == (args.phase == 'prepare')
    raw = args.raw.resolve()
    if args.phase == 'prepare':
        prepare(raw, args.producer.resolve(strict=True))
    else:
        result = inspect(raw)
        save(raw/'checked.json', result)
        print(json.dumps(dict(argv_equal=True, words=40, changed_argument_refused=True,
                             strict_status=result['strict']['status'])))


if __name__ == '__main__':
    main()
