"""Exact ELF/DWARF storage inclusion in protect_image(bridge, whole=1).

This is a compiled-range proof. It does not claim observed runtime registration,
hardware isolation, successful TF execution, or any physical maps acquisition.
"""
import copy
import hashlib
import json
from pathlib import Path
import struct


NAMES = ('maps_current', 'mct_physical_receipt', 'mct_physical_id',
         'rx_current', 'rx_current_busy', 'cc', 'cc_candidate', 'cc_serial', 'cc_stats')
FIELDS = {
    'maps_current': 'serial busy live view',
    'mct_physical_receipt': 'opened close_started closed fd last_read close_result bytes rows observation',
    'mct_physical_id': '',
    'rx_current': 'version complete result borrow ticket query stage',
    'rx_current_busy': '',
    'cc': 'bound owner session_pointer session hooks opening previous original page ticket sequence serial origin_sequence major minor inode object_stat retained_fd proof',
    'cc_candidate': 'progress pc requested page_count pid tid allocation_epoch generation_epoch transactions_epoch records_epoch phase_epoch original pages backing last_backing bytes',
    'cc_serial': '',
    'cc_stats': 'attempts current_stages current_seeds physical_fallbacks retained_stages retained_checks commits cancels first_error first_detail',
}
PAGE = 4096
U64 = (1 << 64) - 1


def need(value, message):
    if not value:
        raise ValueError(message)


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate observation field')
        result[key] = value
    return result


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 65536 and raw.endswith(b'\n')
         and b'\n' not in raw[:-1] and b'\r' not in raw, 'one bounded complete metadata row')
    return json.loads(raw, object_pairs_hook=pairs)


def check(path, observation, compiler_headers):
    data = Path(path).read_bytes()

    def take(at, size):
        need(type(at) is int and type(size) is int and 0 <= at <= len(data)
             and 0 <= size <= len(data) - at, 'complete actual ELF interval')
        return data[at:at + size]

    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (3, 62, 1)
         and h[8:10] == (64, 56) and 0 < h[10] <= 32 and h[11] == 64
         and 0 < h[12] <= 4096, 'actual complete x86-64 shared bridge ELF')
    ph = [struct.unpack('<IIQQQQQQ', take(h[5] + 56 * i, 56)) for i in range(h[10])]
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6] + 64 * i, 64)) for i in range(h[12])]
    loads = []
    for index, p in enumerate(ph):
        if p[0] != 1 or not p[6]:
            continue
        need(p[5] <= p[6] and p[3] <= U64 - p[6] - (PAGE - 1)
             and p[7] == PAGE and p[2] % PAGE == p[3] % PAGE
             and p[1] in (4, 5, 6), 'whole non-WX bridge load with bounded page rounding')
        take(p[2], p[5])
        loads.append(dict(index=index, first=p[3], end=p[3] + p[6], file_bytes=p[5],
                          flags=p[1], protected_first=p[3] & -PAGE,
                          protected_end=(p[3] + p[6] + PAGE - 1) & -PAGE))
    need(loads, 'all actual nonempty bridge PT_LOAD ranges')
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1 and tables[0][9] == 24 and tables[0][5] % 24 == 0
         and 0 < tables[0][5] // 24 <= 1 << 18, 'one complete bounded ELF symbol table')
    table = tables[0]
    need(table[6] < len(sections), 'actual symbol string-table index')
    strings = sections[table[6]]
    need(strings[1] == 3, 'actual symbol string table')
    names = take(strings[4], strings[5]); found = {}
    for at in range(table[4], table[4] + table[5], 24):
        n, info, other, section, address, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(n < len(names) and b'\0' in names[n:], 'complete ELF symbol name')
        name = names[n:names.index(b'\0', n)].decode()
        if name not in NAMES:
            continue
        need(name not in found and info == 1 and other == 0 and 0 < section < len(sections)
             and 0 < size <= 1 << 20 and address <= U64 - size,
             'one complete local defined storage object: ' + name)
        s = sections[section]
        need(s[1] in (1, 8) and s[2] == 3 and s[3] <= address
             and address + size <= s[3] + s[5] <= U64,
             'whole storage object in actual allocated writable nonexecuting section')
        owners = [p for p in loads if p['first'] < address + size and address < p['end']]
        need(len(owners) == 1 and owners[0]['flags'] == 6 and
             owners[0]['first'] <= address and address + size <= owners[0]['end'],
             'whole object in exactly one RW/NX PT_LOAD by p_memsz')
        found[name] = dict(address=address, bytes=size, section=section, load=owners[0]['index'])
    need(set(found) == set(NAMES), 'all nine complete compiled state objects')
    ordered = sorted((v['address'], v['address'] + v['bytes']) for v in found.values())
    need(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])), 'nine distinct nonoverlapping objects')
    need(type(observation) is dict and set(observation) == {'version', 'symbols'}
         and type(observation['version']) is int and observation['version'] == 1
         and type(observation['symbols']) is dict and set(observation['symbols']) == set(NAMES),
         'exact complete file-only DWARF observation')
    need(type(compiler_headers) is dict and compiler_headers, 'actual compiler-M source closure')
    sources = {str(Path(p).resolve(strict=True)) for p in compiler_headers}
    for name in NAMES:
        d = observation['symbols'][name]; e = found[name]
        need(type(d) is dict and set(d) == {'address', 'bytes', 'alignment', 'type', 'source', 'fields'}
             and all(type(d[k]) is int for k in ('address', 'bytes', 'alignment'))
             and d['address'] == e['address'] and d['bytes'] == e['bytes']
             and 0 < d['alignment'] <= PAGE and not d['alignment'] & (d['alignment'] - 1)
             and d['address'] % d['alignment'] == 0 and type(d['source']) is str
             and str(Path(d['source']).resolve(strict=True)) in sources
             and type(d['type']) is str and d['type'] and type(d['fields']) is dict
             and set(d['fields']) == set(FIELDS[name].split()), 'exact ELF/DWARF/source object join: ' + name)
        if not FIELDS[name]:
            need(d['bytes'] == (4 if name == 'rx_current_busy' else 8), 'exact scalar storage ABI')
        ranges = []
        for f in d['fields'].values():
            need(type(f) is dict and set(f) == {'offset', 'bytes', 'type'}
                 and type(f['offset']) is int and type(f['bytes']) is int and type(f['type']) is str
                 and 0 <= f['offset'] < d['bytes'] and 0 < f['bytes'] <= d['bytes'] - f['offset'],
                 'whole actual member extent')
            ranges.append((f['offset'], f['offset'] + f['bytes']))
        ranges.sort()
        need(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), 'all complete direct fields disjoint')
    return dict(version=1, compiled_only=1, objects=found, loads=loads,
                bridge=dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest()),
                symbols=9, runtime_registration_observed=0, native_tf_credit=0, physical_io_credit=0)


def controls(path, observation, compiler_headers):
    check(path, observation, compiler_headers)
    trials = []
    for name in NAMES:
        for field, replacement in (('address', observation['symbols'][name]['address'] + 1),
                                   ('bytes', observation['symbols'][name]['bytes'] + 1),
                                   ('alignment', 0)):
            changed = copy.deepcopy(observation)
            changed['symbols'][name][field] = replacement
            trials.append((name + ':' + field, changed))
        changed = copy.deepcopy(observation); del changed['symbols'][name]
        trials.append((name + ':missing', changed))
        if FIELDS[name]:
            changed = copy.deepcopy(observation)
            del changed['symbols'][name]['fields'][FIELDS[name].split()[0]]
            trials.append((name + ':member', changed))
    changed = copy.deepcopy(observation); changed['version'] = True
    trials.append(('boolean_version', changed))
    changed = copy.deepcopy(observation); changed['symbols']['unexpected'] = {}
    trials.append(('extra_object', changed))
    refused = []
    for name, changed in trials:
        caught = False
        try:
            check(path, changed, compiler_headers)
        except ValueError:
            caught = True
        need(caught, 'complete storage checker refuses supplied ' + name)
        refused.append(name)
    need(len(refused) == len(set(refused)) == 44, 'all fixed storage observation controls')
    return dict(refusals=refused, actual_subjects=0, runtime_registration_observed=0,
                native_tf_credit=0, physical_io_credit=0)
