"""Pure, fixed-population descriptive analysis; no duration-accuracy verdict.

The driver authenticates the strict leg parser, complete raw transcripts and owned
process closure. Endpoint projection cannot replace their non-endpoint proofs.
All arithmetic is integer; no filesystem, process, clock or project imports.
"""
import hashlib
import json

MASTER_HEX = '29c5ca7ec521d0d3e63adb24d9e493b63ae0e9c99ee5bd9d4a49b4791e227b48'
U64, U32 = (1 << 64)-1, (1 << 32)-1
KEY_FIELDS = ('process', 'phase', 'trial', 'leg', 'seed', 'position')
ENDPOINT_FIELDS = ('process', 'call', 'reference_start_offset',
    'reference_end_offset', 'start_offset', 'end_offset')
PROCESS_FIELDS = (*KEY_FIELDS, 'base', 'aux', 'pid', 'tid', 'generation', 'rows')
RAW_FIELDS = ('phase trial leg id repeat seed_index seed length input_fnv1a64 value '
    'instructions conditional_branches taken_branches input_bytes ret_bytes reference_sequence '
    'reference_start_ticks reference_end_ticks reference_start_aux reference_end_aux reference_rsp '
    'reference_ticks pid tid registration install function generation ordinal owner invocation '
    'history_prefix entry_pc return_pc entry_rsp return_word start_ticks end_ticks start_aux end_aux '
    'raw_ticks entry_gap_ticks return_gap_ticks ack ack_ordinal').split()
SCOPE = ('Descriptive empirical boundary-gap coverage and whole-configuration '
    'reference-enclosed contrast in TSC ticks. No body-only accuracy, callback-only '
    'cost, bare-native overhead, confidence interval or full-A5 verdict. '
    'Deterministic scheduling does not imply independent observations.')


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _uint(value, maximum=U64, minimum=0):
    _need(type(value) is int and minimum <= value <= maximum, 'unsigned integer domain')
    return value


def canonical(value):
    """Integer JSON authority: sorted keys, compact ASCII, exactly one final LF."""
    def check(item):
        if item is None or type(item) in (bool, int, str):
            return
        if type(item) is list:
            for child in item:
                check(child)
            return
        if type(item) is dict:
            _need(all(type(key) is str for key in item), 'JSON keys must be strings')
            for child in item.values():
                check(child)
            return
        raise ValueError('noncanonical JSON value')
    check(value)
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')


def catalog(master_hex):
    """The prospectively fixed 400-process schedule; seeds do not change inputs."""
    _need(type(master_hex) is str and master_hex == MASTER_HEX, 'fixed master required')
    master = bytes.fromhex(master_hex)
    phases = ('calibration', 'holdout', 'comparison')
    seeds = {(phase, trial): hashlib.sha256(b'normal-reference-study-v1\0'+master+
        b'\0'+phase.encode('ascii')+b'\0'+trial.to_bytes(4, 'big')).digest()
        for phase in phases for trial in range(1, 101)}
    _need(len(set(seeds.values())) == 300, 'phase/trial seed collision')
    ranked = sorted(range(1, 101), key=lambda trial: (hashlib.sha256(
        b'normal-reference-study-order-v1\0'+seeds['comparison', trial]).digest(), trial))
    original_first = set(ranked[:50])
    result = []
    for phase in phases:
        for trial in range(1, 101):
            legs = ('installed',)
            if phase == 'comparison':
                legs = ('original', 'installed') if trial in original_first else ('installed', 'original')
            for position, leg in enumerate(legs, 1):
                result.append(dict(process=len(result)+1, phase=phase, trial=trial,
                    leg=leg, seed=seeds[phase, trial].hex(), position=position))
    return result


def _key(key):
    _need(type(key) is dict and set(key) == set(KEY_FIELDS), 'exact catalog key required')
    process = _uint(key['process'], 400, 1)
    _need(canonical(key) == canonical(catalog(MASTER_HEX)[process-1]), 'catalog identity')


def _length(call):
    return 1 if (call-1) % 4 < 2 else 64


def _observation(observation, key):
    """Validate the lossless public representation and derive only enclosed spans."""
    _need(type(observation) is dict and set(observation) == set(PROCESS_FIELDS), 'observation fields')
    _need(canonical({name: observation[name] for name in KEY_FIELDS}) == canonical(key), 'observation key')
    base, aux = _uint(observation['base']), _uint(observation['aux'], U32)
    pid = _uint(observation['pid'], U32, 1)
    _need(_uint(observation['tid'], U32, 1) == pid, 'single-main identity')
    installed = key['leg'] == 'installed'
    if installed:
        _uint(observation['generation'], U64, 1)
    else:
        _need(observation['generation'] is None, 'original generation absent')
    rows = observation['rows']
    _need(type(rows) is list and len(rows) == 24, 'complete 24-call projection')
    values, previous = [], base
    for call, row in enumerate(rows, 1):
        _need(type(row) is dict and set(row) == set(ENDPOINT_FIELDS), 'endpoint row fields')
        _need(_uint(row['process']) == key['process'] and _uint(row['call']) == call, 'endpoint row identity')
        a = _uint(base+_uint(row['reference_start_offset']))
        b = _uint(base+_uint(row['reference_end_offset']))
        _need(previous <= a <= b and (call != 1 or a == base), 'reference chronology/base')
        previous = b
        value = dict(call=call, length=_length(call), R=b-a, H=None, Ge=None, Gr=None)
        if installed:
            s = _uint(base+_uint(row['start_offset']))
            e = _uint(base+_uint(row['end_offset']))
            _need(a <= s <= e <= b, 'nested endpoint order')
            value.update(H=e-s, Ge=s-a, Gr=b-e)
            _need(value['Ge']+value['H']+value['Gr'] == value['R'], 'gap identity')
        else:
            _need(row['start_offset'] is None and row['end_offset'] is None, 'original endpoints absent')
        values.append(value)
    return values


def project(key, strict_parser_rows):
    """Consume already strict-parsed rows; retain every endpoint exactly once.

    Rechecks the identities and endpoint domains used here, not the parser's
    complete source/stack/work/journal/Report authority. No cross-process equality.
    """
    _key(key)
    _need(type(strict_parser_rows) is list and len(strict_parser_rows) == 24, 'complete parser population')
    first = strict_parser_rows[0]
    _need(type(first) is dict and set(first) == set(RAW_FIELDS), 'parser row fields')
    installed = key['leg'] == 'installed'
    base = _uint(first['reference_start_ticks'])
    result = dict(key, base=base, aux=_uint(first['reference_start_aux'], U32),
        pid=_uint(first['pid'], U32, 1), tid=_uint(first['tid'], U32, 1),
        generation=first['generation'], rows=[])
    for call, row in enumerate(strict_parser_rows, 1):
        _need(type(row) is dict and set(row) == set(RAW_FIELDS), 'parser row fields')
        _need(type(row['phase']) is str and row['phase'] == key['phase'] and
            _uint(row['trial']) == key['trial'] and type(row['leg']) is str and
            row['leg'] == key['leg'], 'parser manifest identity')
        _need(_uint(row['id']) == call and _uint(row['reference_sequence']) == call and
            _uint(row['length']) == _length(call), 'local case identity')
        _need(_uint(row['pid'], U32, 1) == result['pid'] and
            _uint(row['tid'], U32, 1) == result['tid'], 'process identity')
        _need(_uint(row['reference_start_aux'], U32) == result['aux'] and
            _uint(row['reference_end_aux'], U32) == result['aux'], 'common AUX')
        a, b = _uint(row['reference_start_ticks']), _uint(row['reference_end_ticks'])
        _need(a <= b and _uint(row['reference_ticks']) == b-a, 'reference duration')
        endpoint = dict(process=key['process'], call=call,
            reference_start_offset=a-base, reference_end_offset=b-base,
            start_offset=None, end_offset=None)
        if installed:
            _need(_uint(row['generation'], U64, 1) == result['generation'], 'generation identity')
            s, e = _uint(row['start_ticks']), _uint(row['end_ticks'])
            _need(_uint(row['start_aux'], U32) == result['aux'] and
                _uint(row['end_aux'], U32) == result['aux'], 'callback AUX')
            _need(a <= s <= e <= b and _uint(row['raw_ticks']) == e-s and
                _uint(row['entry_gap_ticks']) == s-a and _uint(row['return_gap_ticks']) == b-e, 'raw gap identity')
            endpoint.update(start_offset=s-base, end_offset=e-base)
        else:
            _need(all(row[name] is None for name in ('generation', 'start_ticks', 'end_ticks',
                'start_aux', 'end_aux', 'raw_ticks', 'entry_gap_ticks', 'return_gap_ticks')), 'original SDK absence')
        # Both the checked arithmetic and equality to raw words are explicit.
        for raw_name, offset_name in (('reference_start_ticks', 'reference_start_offset'),
                ('reference_end_ticks', 'reference_end_offset'),
                ('start_ticks', 'start_offset'), ('end_ticks', 'end_offset')):
            offset = endpoint[offset_name]
            if offset is not None:
                _need(_uint(base+_uint(offset)) == row[raw_name], 'endpoint reconstruction')
        result['rows'].append(endpoint)
    _observation(result, key)
    return result


def _population(observations, keys):
    _need(type(observations) is list and len(observations) == len(keys), 'complete ordered population')
    return [_observation(observation, key) for observation, key in zip(observations, keys)]


def calibrate(observations):
    values = _population(observations, catalog(MASTER_HEX)[:100])
    ue = max(row['Ge'] for process in values for row in process)
    ur = max(row['Gr'] for process in values for row in process)
    budget = ue+ur
    return dict(status='EMPIRICAL_BUDGET' if budget <= U64 else 'UNRESOLVED_OVERFLOW',
        Ue=ue, Ur=ur, B=budget if budget <= U64 else None,
        calibration_sha256=hashlib.sha256(canonical(observations)).hexdigest())


def _ratio(numerator, denominator):
    return dict(numerator=numerator, denominator=denominator)


def _distribution(numerators, denominator):
    ordered = sorted(numerators)
    count = len(ordered)
    return dict(count=count, mean=_ratio(sum(ordered), count*denominator),
        minimum=_ratio(ordered[0], denominator), maximum=_ratio(ordered[-1], denominator),
        nearest_rank={str(percent): _ratio(ordered[(percent*count+99)//100-1], denominator)
            for percent in (5, 50, 95)})


def _holdout(keys, values, budget):
    processes, maximums = [], []
    counts = {name: 0 for name in ('entry', 'return', 'total', 'any_known_component_rows')}
    lengths = {str(length): dict(counts) for length in (1, 64)}
    if budget['B'] is None:
        counts['total'] = None
        for count in lengths.values():
            count['total'] = None
    for key, rows in zip(keys, values):
        maximum = max(row['Ge']+row['Gr'] for row in rows)
        maximums.append(maximum)
        exceedances = []
        for row in rows:
            any_excess = False
            for component, value, bound in (('entry', row['Ge'], budget['Ue']),
                    ('return', row['Gr'], budget['Ur']),
                    ('total', row['Ge']+row['Gr'], budget['B'])):
                if bound is not None and value > bound:
                    exceedances.append(dict(call=row['call'], length=row['length'],
                        component=component, magnitude=value-bound))
                    counts[component] += 1
                    lengths[str(row['length'])][component] += 1
                    any_excess = True
            if any_excess:
                counts['any_known_component_rows'] += 1
                lengths[str(row['length'])]['any_known_component_rows'] += 1
        processes.append(dict(process=key['process'], trial=key['trial'], max_gap=maximum,
            max_entry_gap=max(row['Ge'] for row in rows), max_return_gap=max(row['Gr'] for row in rows),
            covered=None if budget['B'] is None else maximum <= budget['B'], exceedances=exceedances))
    return dict(processes=processes, coverage=dict(denominator=100,
        covered=None if budget['B'] is None else sum(process['covered'] for process in processes),
        status='UNRESOLVED_OVERFLOW' if budget['B'] is None else 'EMPIRICAL'),
        exceedance_counts=counts, by_length=lengths, process_maxima=_distribution(maximums, 1))


def _comparison(keys, values):
    blocks = []
    for index in range(0, 200, 2):
        pair = keys[index:index+2]
        original = index if pair[0]['leg'] == 'original' else index+1
        installed = index+1 if original == index else index
        left, right = values[original], values[installed]
        block = dict(trial=pair[0]['trial'], original_process=keys[original]['process'],
            installed_process=keys[installed]['process'], order=pair[0]['leg']+'-first',
            contrast=_ratio(sum(row['R'] for row in right)-sum(row['R'] for row in left), 24),
            by_length={str(length): _ratio(
                sum(row['R'] for row in right if row['length'] == length)-
                sum(row['R'] for row in left if row['length'] == length), 12) for length in (1, 64)})
        blocks.append(block)
    groups = {}
    for order in ('original-first', 'installed-first'):
        selected = [block for block in blocks if block['order'] == order]
        _need(len(selected) == 50, 'exact order balance')
        groups[order] = dict(count=50,
            mean=_ratio(sum(block['contrast']['numerator'] for block in selected), 50*24),
            by_length={str(length): _ratio(sum(block['by_length'][str(length)]['numerator']
                for block in selected), 50*12) for length in (1, 64)})
    return dict(blocks=blocks, all_calls=_distribution([block['contrast']['numerator'] for block in blocks], 24),
        by_length={str(length): _distribution([block['by_length'][str(length)]['numerator']
            for block in blocks], 12) for length in (1, 64)}, by_order=groups)


def summarize(keys, observations, frozen_budget):
    expected = catalog(MASTER_HEX)
    _need(canonical(keys) == canonical(expected), 'exact frozen catalog')
    values = _population(observations, expected)
    budget = calibrate(observations[:100])
    _need(canonical(frozen_budget) == canonical(budget), 'frozen budget substitution')
    return dict(status='DESCRIPTIVE_COMPLETE', scope=SCOPE,
        population=dict(processes=400, installed=300, original=100, calls=9600, endpoints=33600),
        budget=budget, holdout=_holdout(expected[100:200], values[100:200], budget),
        comparison=_comparison(expected[200:], values[200:]))
