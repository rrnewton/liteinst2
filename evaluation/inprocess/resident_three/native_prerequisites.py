"""Closed fixed native evidence; no replay and no transfer of owner authority."""
import json
import struct
from pathlib import Path
from page_selected import ENV, need

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
SELECTED = ROOT / "tools/page-entry/selected"
from ret_dispatch.run import LINK_NAMES

BUILD = [30, 512 << 20, 16 << 20, 60]
NATIVE = [5, 512 << 20, 16 << 20, 15]
PREFIX = ['tool-' + x + '-dependencies' for x in ('cc', 'cc1', 'collect2', 'as', 'ld', 'nm', 'git', 'python')]
PREFIX += ['link-' + x for x in LINK_NAMES]
PREFIX += ['compiler-specs', 'archive-exports', 'headers', 'build', 'native-dependencies', 'inspection']


def unique(pairs):
    value = dict(pairs)
    need(len(value) == len(pairs), 'duplicate prerequisite JSON key')
    return value


def load(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def closed(path, sha256, current, compile_receipt, pin, fact, profile, names, native_names, *, step_name=None):
    path = pin(path)
    need(fact(path)['sha256'] == sha256, 'exact whole native prerequisite receipt')
    old = load(path)
    need(old['profile'] == profile and old['status'] == 'observed_unqualified' and
         old['source'] == current['source'] and old['hardware'] == current['hardware'] and old['cpu'] == current['cpu'] and
         old['revision'] == current['source']['revision'] and
         all(old[k] is True for k in ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')) and
         old['error'] is None and old['final_errors'] == [] and
         all(old[k] is False for k in ('runtime_owner_credit', 'qualification_credit', 'performance_credit')),
         'successful finite native evidence at the same actual source/hardware/CPU, no owner credit')
    need(old['bounds'] == dict(build=BUILD, native=NATIVE) and old['archive_builds'] == 0,
         'original finite native/build bounds and retained archive')
    for table in ('inputs', 'artifacts'):
        for name, value in old[table].items():
            need(fact(pin(name)) == value, 'whole retained native ' + table)
    for alias, actual in old['aliases'].items():
        need(str(pin(alias)) == actual, 'exact native prerequisite aliases')
    need(all(Path(name).exists() == exists for name, exists in old['loader_presence'].items()),
         'unchanged native loader configuration presence')
    need([row['name'] for row in old['commands']] == names, 'complete exact native command schedule')
    commands = {}
    for row in old['commands']:
        need(row['bounds'] == (NATIVE if row['name'] in native_names else BUILD) and
             row['environment'] == dict(ENV) and row['capture_limit'] == (8192 if row['name'] == step_name else 16 << 20) and
             row['exit'] == row['expected_exit'] == 0 and row['reaped'] is True and
             row['timed_out'] is False and row['error'] is None and row['cleanup_errors'] == [] and
             all(d['closed'] is True for d in row['descriptors']), 'closed original bounded native command')
        streams = {'stdout', 'stderr', 'record', 'preparation'} if row['name'] == step_name else {'stdout', 'stderr'}
        need(set(row['captures']) == streams, 'complete exact native command captures')
        for capture in row['captures'].values():
            name = path.parent / capture['file']
            need(name.parent == path.parent and
                 all(fact(pin(name))[k] == capture[k] for k in ('bytes', 'sha256')),
                 'whole contained native command capture')
        need(all(row['captures'][k]['bytes'] <= row['capture_limit'] for k in ('stdout', 'stderr')),
             'actual native stdout/stderr remain within original capture bound')
        if row['name'] == step_name:
            need(row['captures']['record']['bytes'] <= row['bounds'][2], 'original private record bound')
            prep = load(pin(path.parent / row['captures']['preparation']['file']))
            need(set(prep) == {'previous_mask', 'mask', 'dispositions'} and
                 type(prep['previous_mask']) is int and 0 <= prep['previous_mask'] < 1 << 64 and
                 type(prep['mask']) is int and prep['mask'] == 0 and
                 [v['signal'] for v in prep['dispositions']] == [n for n in range(1, 65) if n not in (9, 19)] and
                 all(set(v) == {'signal', 'before', 'after'} and type(v['signal']) is int and
                     type(v['before']) is int and 0 <= v['before'] < 1 << 64 and
                     type(v['after']) is int and v['after'] == 0 for v in prep['dispositions']) and
                 [d['name'] for d in row['descriptors']] == ['record', 'preparation'] and
                 row['descriptors'][0]['fd'] == 3, 'whole actual standalone footprint signal/FD preparation')
        commands[row['name']] = row
    archive = old['archive']
    need({k: archive[k] for k in ('bytes', 'sha256', 'mode')} == compile_receipt['archive']['archive'] and
         {k: archive['receipt'][k] for k in ('bytes', 'sha256', 'mode')} == compile_receipt['archive']['receipt'] and
         archive['built_revision'] == compile_receipt['archive']['revision'] and
         archive['whole_archive_validator'] is True and archive['same_source_as_current'] is True and archive['current_decoder_source_bytes_verified'] is True and
         archive['qualification_credit'] is False and
         fact(pin(archive['path'])) == compile_receipt['archive']['archive'],
         'same fully authenticated retained decoder archive, same clean source, no qualification transfer')
    binary = old['build']['binary']
    need(fact(pin(binary['path'])) == {k: binary[k] for k in ('bytes', 'sha256', 'mode')} and
         old['inspection']['elf_bytes'] == binary['bytes'] and old['inspection']['elf_sha256'] == binary['sha256'] and
         old['inspection']['status'] == 'source_bytes_inspected' and
         old['inspection']['native_execution'] is False and old['inspection']['qualification_credit'] is False,
         'same complete inspected native ELF')
    return path, old, commands


def source_join(old, compile_receipt, names, pin, fact):
    # Both actual compiler-M closures must contain each exact production leaf.
    native = old['build']['headers']
    compiled = compile_receipt['builds']['bridge']['headers']
    for name in names:
        left = [(p, v) for p, v in native.items() if p.endswith('/' + name)]
        right = [(p, v) for p, v in compiled.items() if p.endswith('/' + name)]
        need(len(left) == len(right) == 1, 'one actual native and bridge header: ' + name)
        a, av = left[0]; b, bv = right[0]
        need(all(av[k] == bv[k] for k in ('bytes', 'sha256')) and
             all(fact(pin(a))[k] == av[k] and fact(pin(b))[k] == bv[k] for k in ('bytes', 'sha256')),
             'whole production source equality between native proof and combined bridge: ' + name)


def installed_sources(old, path, name, commands, pin, fact):
    contract = load(pin(HERE / 'CONTRACT.json'))
    collector = pin(HERE / (name + '_native.py'))
    inspector = pin(HERE / (name + '_inspect.py'))
    need(old['inputs'][str(collector)] == fact(collector) and
         old['inputs'][str(inspector)] == fact(inspector),
         'actual installed collector and full native bootstrap inspector')
    selected = path.parent / 'source/tools/page-entry/selected'
    names = contract[name + '_staging']
    need(len(names) == len(set(names)) and
         set(old['staging']) == {str(selected / n) for n in names},
         'complete natural installed native source population')
    for n in names:
        origin = pin(SELECTED / n)
        actual = pin(selected / n)
        need(old['inputs'][str(origin)] == fact(origin) and fact(actual) == fact(origin) and
             old['artifacts'][str(actual)] == fact(origin) and
             old['staging'][str(actual)] == dict(origin=str(origin), **fact(origin)),
             'whole actual native source equals current installed source: ' + n)
    need(commands['inspection']['argv'][1:] ==
         ['-I', '-S', '-B', str(inspector), old['build']['binary']['path']],
         'actual inspected whole native binary and source-owned bootstrap')
    reader = selected / ('tests/flag_stack_native/read.py' if name == 'flags' else 'tests/helper_tf_native/read.py')
    for key, row in commands.items():
        if key.startswith('read-'):
            need(row['argv'][4] == str(reader), 'actual complete installed native reader')


def flags(path, sha256, current, compile_receipt, pin, fact):
    tail = [name for placement in range(2) for name in ('native-' + str(placement), 'read-' + str(placement))]
    path, old, commands = closed(path, sha256, current, compile_receipt, pin, fact,
                                'flag-stack-native-collector-v1', PREFIX + tail, set(tail) | {'inspection'})
    installed_sources(old, path, 'flags', commands, pin, fact)
    need(set(old['placements']) == {'0', '1'}, 'both opposite native placements')
    source_join(old, compile_receipt, ('flag_stack.c', 'flag_stack.h'), pin, fact)
    result = dict(status='observed_unqualified', pairs=36, lanes=72, full_frames=144,
                  supported_pairs=16, fault_pairs=16, unsupported_state_pairs=4,
                  descriptor_controls=120, original_tf_refusals=94, runtime_owner_credit=False,
                  qualification_credit=False, performance_credit=False)
    need(old['result'] == result, 'complete original flags result and unqualified scopes')
    for placement in range(2):
        item = old['placements'][str(placement)]
        native = commands['native-' + str(placement)]; reader = commands['read-' + str(placement)]
        raw = native['captures']['stdout']
        need(item['status'] == 'observed_unqualified' and item['exit'] == 0 and
             item['command'] == native['name'] and item['reader_command'] == reader['name'] and item['raw'] == raw and
             raw['bytes'] == 6504480 and native['captures']['stderr']['bytes'] == reader['captures']['stderr']['bytes'] == 0 and
             native['argv'] == [old['build']['binary']['path'], str(placement)] and
             reader['argv'][1:4] == ['-I', '-S', '-B'] and
             reader['argv'][5:] == [str(path.parent / raw['file']), '--exit-status', '0', '--placement', str(placement),
                                   '--pid', str(native['pid']), '--cpu', str(current['cpu'])],
             'actual flags raw/reader/ELF/PID/CPU/placement invocation joins')
        data = pin(path.parent / raw['file']).read_bytes()
        header = struct.unpack_from('<64Q', data)
        need(header[11] == placement and header[15:17] == (native['pid'], current['cpu']) and
             (header[28], header[29], header[34]) == tuple(old['inspection'][k] for k in
                 ('reload_address', 'scratch_end_address', 'handler_address')),
             'actual native flags raw header joins inspected bootstrap/handler/PID/CPU')
        parsed = load(pin(path.parent / reader['captures']['stdout']['file']))
        need(parsed == item['result'] and all(parsed[k] == v for k, v in
             dict(profile='flag-stack-native-v1', status='observed_unqualified', placement=placement,
                  cases=18, lanes=36, full_frames=72, supported_pairs=8, fault_pairs=8,
                  unsupported_state_pairs=2, descriptor_controls=60, original_tf_refusals=47,
                  raw_bytes=raw['bytes'], raw_sha256=raw['sha256'], runtime_owner_credit=False,
                  qualification_credit=False, performance_credit=False).items()),
             'complete flags reader result, all original populations and raw binding')
        observations = parsed['observations']
        need([v['case'] for v in observations] == [9, 10] and
             [v['kind'] for v in observations] == ['unsupported_tf_output', 'unsupported_nt_output'] and
             observations[0]['native_event'] == 'original-next-nx' and observations[0]['native_signal'] == 11 and
             observations[0]['native_trap'] == 14 and observations[0]['tile_event'] == 'post-pop-trace' and
             observations[0]['tile_signal'] == 5 and observations[0]['tile_trap'] == 1,
             'actual unsupported TF event difference is retained, never owner-qualified')
    return dict(receipt=dict(path=str(path), **fact(path)), result=result)


def helper(path, sha256, current, compile_receipt, pin, fact):
    footprint_names = ['footprint-headers', 'footprint-build', 'footprint-undefined',
                       'footprint-native', 'footprint-read']
    chunks = ((0, 0), (0, 1), (1, 0), (1, 1))
    tail = [name for p, c in chunks for name in ('native-' + str(p) + '-' + str(c),
                                                'read-' + str(p) + '-' + str(c))]
    native_names = set(tail) | {'inspection', 'footprint-build', 'footprint-native', 'footprint-read'}
    path, old, commands = closed(path, sha256, current, compile_receipt, pin, fact,
        'helper-tf-bounded-native-v1', PREFIX + footprint_names + tail, native_names,
        step_name='footprint-native')
    installed_sources(old, path, 'helper', commands, pin, fact)
    need(set(old['chunks']) == {'0-0', '0-1', '1-0', '1-1'}, 'four fixed native helper chunks')
    source_join(old, compile_receipt, ('helper_tf.c', 'helper_tf.h'), pin, fact)
    result = dict(status='observed_unqualified', pairs=88, lanes=176, full_frames=352,
                  successful_pairs=64, memory_fault_pairs=18, pending_x87_fault_pairs=6,
                  descriptor_controls=1876, original_tf_refusals=188, old_footprint_cases=38,
                  runtime_owner_credit=False, production_sigfpe_capture_credit=False,
                  qualification_credit=False, performance_credit=False)
    need(old['result'] == result, 'complete original helper result and all finite scope labels')
    footprint = old['footprint']; native = commands['footprint-native']; reader = commands['footprint-read']
    raw = native['captures']['record']; binary = footprint['build']['binary']
    need(footprint['status'] == 'passed' and footprint['raw'] == raw and raw['bytes'] == 1270344 and
         native['argv'] == [binary['path']] and
         fact(pin(binary['path'])) == {k: binary[k] for k in ('bytes', 'sha256', 'mode')} and
         native['captures']['stderr']['bytes'] == reader['captures']['stderr']['bytes'] == 0 and
         reader['argv'][1:4] == ['-I', '-S', '-B'] and reader['argv'][5:] == [str(path.parent / raw['file'])],
         'whole separately mandatory original footprint executable/record/reader join')
    expected_path = ROOT / 'tools/page-entry/selected/tests/write_footprint/OUTCOMES.json'
    expected = load(pin(expected_path))['commands'][0]
    need(pin(path.parent / native['captures']['stdout']['file']).read_bytes() == expected['stdout'].encode(),
         'literal original footprint stdout unchanged')
    observed = load(pin(path.parent / reader['captures']['stdout']['file']))
    need(observed['profile'] == 'page-selected-write-footprint-v1' and observed['status'] == 'passed' and
         observed['result'] == footprint['result'] and observed['raw_bytes'] == raw['bytes'] and
         observed['raw_sha256'] == raw['sha256'] and all(footprint['result'][k] == v for k, v in
             dict(cases=38, actual_instructions=30, supplied_refusals=8, api_controls=6,
                  old_cases=34, added_register_only_cases=4, sealed_stats_unchanged=True).items()) and
         len(footprint['result']['rows']) == 38,
         'entire unchanged original footprint reader result and all 38 cases')
    for placement, chunk in chunks:
        key = str(placement) + '-' + str(chunk); item = old['chunks'][key]
        native = commands['native-' + key]; reader = commands['read-' + key]; raw = native['captures']['stdout']
        need(item['status'] == 'observed_unqualified' and item['exit'] == 0 and
             item['command'] == native['name'] and item['reader_command'] == reader['name'] and item['raw'] == raw and
             raw['bytes'] == 8491872 and native['captures']['stderr']['bytes'] == reader['captures']['stderr']['bytes'] == 0 and
             native['argv'] == [old['build']['binary']['path'], str(placement), str(chunk)] and
             reader['argv'][1:4] == ['-I', '-S', '-B'] and
             reader['argv'][5:] == [str(path.parent / raw['file']), '--exit-status', '0', '--placement', str(placement),
                                   '--chunk', str(chunk), '--pid', str(native['pid']), '--cpu', str(current['cpu'])],
             'actual helper raw/reader/ELF/PID/CPU/chunk invocation joins')
        data = pin(path.parent / raw['file']).read_bytes(); header = struct.unpack_from('<64Q', data)
        need(header[11:15] == (placement, chunk * 22, 22, 44) and header[15:17] == (native['pid'], current['cpu']) and
             (header[28], header[29], header[34]) == tuple(old['inspection'][k] for k in
                 ('reload_address', 'scratch_end_address', 'handler_address')),
             'actual original-PC helper raw header joins inspected bootstrap/handler/PID/CPU')
        parsed = load(pin(path.parent / reader['captures']['stdout']['file']))
        wanted = dict(profile='helper-tf-native-v1', status='observed_unqualified', placement=placement, chunk=chunk,
                      cases=22, lanes=44, full_frames=88, successful_pairs=22 if chunk == 0 else 10,
                      memory_fault_pairs=0 if chunk == 0 else 9, pending_x87_fault_pairs=0 if chunk == 0 else 3,
                      descriptor_controls=469, original_tf_refusals=47, raw_bytes=raw['bytes'], raw_sha256=raw['sha256'],
                      instruction_execution_at_original_pc=True, runtime_owner_credit=False,
                      production_sigfpe_capture_credit=False, qualification_credit=False, performance_credit=False)
        need(parsed == item['result'] == wanted, 'whole helper reader result with every original population and scope')
    return dict(receipt=dict(path=str(path), **fact(path)), result=result,
                footprint={k: footprint['result'][k] for k in ('cases', 'actual_instructions', 'supplied_refusals', 'api_controls')})
