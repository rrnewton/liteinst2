"""Lossless shared strings for numerical case tables; no compressed payloads."""
from collections import Counter


def need(condition, message):
    if not condition:
        raise ValueError(message)


def project(public):
    """Keep every case value and type, sharing repeated long string values."""
    need(public['case_encoding'] == 'shared-numerical-columns-v1', 'original column encoding')
    columns = public['case_columns']; fields = sorted(public['case_subcolumns'])

    def sparse(row, keys):
        need(type(row) is list and len(row) == len(keys) + 1 and type(row[0]) is int
             and 0 <= row[0] < 1 << len(keys), 'complete dense presence row')
        need(all(row[i + 1] is None for i in range(len(keys)) if not row[0] >> i & 1),
             'missing dense cells contain only canonical null padding')
        return [row[0], *[row[i + 1] for i in range(len(keys)) if row[0] >> i & 1]]

    capture_position = columns.index('captures') + 1 if 'captures' in columns else None
    capture_values = {i: row[capture_position + 1] for i, row in enumerate(public['cases'])
                      if capture_position and row[1] >> (capture_position - 1) & 1
                      and type(row[capture_position + 1]) is dict
                      and all(type(v) is dict for v in row[capture_position + 1].values())}
    capture_columns = sorted({key for value in capture_values.values() for key in value})
    capture_fields = sorted({key for value in capture_values.values() for v in value.values() for key in v})

    def pack_dict(value, keys):
        return [sum(1 << i for i, key in enumerate(keys) if key in value),
                *[value[key] for key in keys if key in value]]

    cases = []
    for number, row in enumerate(public['cases']):
        values = list(row[1:])
        if number in capture_values:
            values[capture_position] = pack_dict({key: pack_dict(value, capture_fields)
                for key, value in capture_values[number].items()}, capture_columns)
        for i, field in enumerate(fields):
            if row[0] >> i & 1:
                position = columns.index(field) + 1
                values[position] = sparse(values[position], public['case_subcolumns'][field])
        cases.append([row[0], *sparse(values, columns)])
    counts = Counter()
    shapes = Counter()

    def count(value):
        if type(value) is str:
            counts[value] += 1
        elif type(value) is list:
            for item in value:
                count(item)
        elif type(value) is dict:
            need(all(type(key) is str for key in value), 'JSON string object keys')
            shapes[tuple(sorted(value))] += 1
            for item in value.values():
                count(item)

    count(cases)
    strings = sorted(s for s, n in counts.items() if n > 1 and len(s) >= 16)
    indices = {s: i for i, s in enumerate(strings)}
    objects = sorted(keys for keys, n in shapes.items() if n > 1 and sum(map(len, keys)) >= 8)
    object_indices = {keys: i for i, keys in enumerate(objects)}

    def encode(value):
        if type(value) is str and value in indices:
            return {'$s': indices[value]}
        if type(value) is list:
            return [encode(item) for item in value]
        if type(value) is dict:
            keys = tuple(sorted(value))
            if keys in object_indices:
                return {'$o': [object_indices[keys], *[encode(value[key]) for key in keys]]}
            if set(value) in ({'$s'}, {'$d'}, {'$o'}):
                return {'$d': [[key, encode(item)] for key, item in value.items()]}
            return {key: encode(item) for key, item in value.items()}
        return value

    result = dict(public, case_encoding='shared-numerical-columns-v2',
                case_capture_rows=sum(1 << i for i in capture_values),
                case_capture_columns=capture_columns, case_capture_fields=capture_fields,
                case_strings=strings, case_objects=[list(keys) for keys in objects], cases=encode(cases))
    if 'mapping_controls' in public:
        state = public['mapping_controls']; rows = state['cases']
        need(all(type(row) is dict for row in rows), 'mapping controls remain dictionary rows')
        keys = sorted({key for row in rows for key in row})
        result['mapping_controls'] = dict(state, case_encoding='sparse-columns-v1',
            columns=keys, cases=[pack_dict(row, keys) for row in rows])
    return result


def restore(public):
    """Restore v1 case columns, rejecting malformed typed string references."""
    need(public['case_encoding'] == 'shared-numerical-columns-v2', 'shared string column encoding')
    strings = public['case_strings']
    need(type(strings) is list and all(type(s) is str and len(s) >= 16 for s in strings)
         and strings == sorted(set(strings)), 'complete sorted unique string table')

    objects = public['case_objects']
    need(type(objects) is list and all(type(keys) is list and all(type(key) is str for key in keys)
         and keys == sorted(set(keys)) for keys in objects)
         and objects == [list(keys) for keys in sorted(set(map(tuple, objects)))], 'unique sorted object columns')

    def decode(value):
        if type(value) is list:
            return [decode(item) for item in value]
        if type(value) is dict:
            if set(value) == {'$s'}:
                index = value['$s']
                need(type(index) is int and 0 <= index < len(strings), 'exact string reference')
                return strings[index]
            if set(value) == {'$o'}:
                items = value['$o']
                need(type(items) is list and items and type(items[0]) is int
                     and 0 <= items[0] < len(objects), 'exact object column reference')
                keys = objects[items[0]]
                need(len(items) == len(keys) + 1, 'complete object column values')
                return {key: decode(item) for key, item in zip(keys, items[1:], strict=True)}
            if set(value) == {'$d'}:
                items = value['$d']
                need(type(items) is list and all(type(item) is list and len(item) == 2
                     and type(item[0]) is str for item in items), 'escaped dictionary pairs')
                need(len({key for key, _ in items}) == len(items), 'unique escaped dictionary keys')
                return {key: decode(item) for key, item in items}
            return {key: decode(item) for key, item in value.items()}
        return value

    columns = public['case_columns']; fields = sorted(public['case_subcolumns'])

    def dense(row, keys):
        need(type(row) is list and row and type(row[0]) is int
             and 0 <= row[0] < 1 << len(keys) and len(row) == row[0].bit_count() + 1,
             'complete sparse presence row')
        items = iter(row[1:])
        return [row[0], *[next(items) if row[0] >> i & 1 else None for i in range(len(keys))]]

    capture_position = columns.index('captures') + 1 if 'captures' in columns else None
    capture_rows = public['case_capture_rows']
    need(type(capture_rows) is int and 0 <= capture_rows < 1 << len(public['cases']), 'exact capture row mask')
    capture_columns = public['case_capture_columns']; capture_fields = public['case_capture_fields']
    need(all(type(keys) is list and all(type(key) is str for key in keys) and keys == sorted(set(keys))
             for keys in (capture_columns, capture_fields)), 'complete capture columns')

    def unpack_dict(value, keys):
        row = dense(value, keys)
        return {key: row[i + 1] for i, key in enumerate(keys) if row[0] >> i & 1}

    cases = []
    for number, row in enumerate(decode(public['cases'])):
        need(type(row) is list and row and type(row[0]) is int and 0 <= row[0] < 1 << len(fields),
             'complete dictionary type mask')
        values = dense(row[1:], columns)
        for i, field in enumerate(fields):
            if row[0] >> i & 1:
                index = columns.index(field)
                need(values[0] >> index & 1, 'dictionary field present in sparse case')
                values[index + 1] = dense(values[index + 1], public['case_subcolumns'][field])
        if capture_rows >> number & 1:
            need(capture_position is not None and values[0] >> (capture_position - 1) & 1,
                 'encoded capture dictionary is actually present')
            values[capture_position] = {key: unpack_dict(value, capture_fields) for key, value in
                                       unpack_dict(values[capture_position], capture_columns).items()}
        cases.append([row[0], *values])
    result = dict(public, case_encoding='shared-numerical-columns-v1', cases=cases)
    if 'mapping_controls' in result:
        state = result['mapping_controls']
        need(state['case_encoding'] == 'sparse-columns-v1', 'mapping sparse encoding')
        keys = state['columns']
        need(type(keys) is list and all(type(key) is str for key in keys) and keys == sorted(set(keys)),
             'complete mapping control columns')
        state = dict(state, cases=[unpack_dict(row, keys) for row in state['cases']])
        del state['case_encoding'], state['columns']
        result['mapping_controls'] = state
    for field in ('case_strings', 'case_objects', 'case_capture_rows', 'case_capture_columns', 'case_capture_fields'):
        del result[field]
    return result
