"""Fixed prospective LeafSet population; no execution or semantic authority."""
if not __debug__:
    raise SystemExit('assertions required')

PROFILE = 'leaf-set-whole-session-v1'
OPERATIONS = ('csv_fields', 'length', 'ascii_digits', 'ascii_spaces')
SYMBOLS = ('csv_fields', 'leaf_length', 'leaf_ascii_digits', 'leaf_ascii_spaces')
POLICIES = ('certified', 'whole', 'whole', 'whole')
FUNCTION_IDS = (11, 22, 33, 44)
KINDS = ('empty', 'budget', 'syntax')
LITERALS = (b'', b'a,b', b'"1 2", 3', b'"",42,  ', b'""""',
            b' '*64, b','*64, b'9'*64)


def case(n, k, kind):
    assert type(n) is int and 1 <= n <= 4
    assert type(k) is int and k in (10, 1000) and kind in KINDS
    if kind == 'empty':
        records = ()
    elif kind == 'budget':
        records = tuple(LITERALS[i % len(LITERALS)] for i in range(k + 1))
    else:
        records = (b'12, 3', b'"4 5",6')
    assert len(records) <= min(2048, 4096 // n)
    data = b''.join(payload + b'\n' for payload in records)
    if kind == 'syntax':
        data += b'a"b\n'
    return dict(n=n, k=k, kind=kind, name=f'n{n}-k{k}-{kind}', epochs=520,
                records=records, data=data, close=True,
                outcome='input_error' if kind == 'syntax' else 'eof',
                input_error='syntax' if kind == 'syntax' else 'none')


def references():
    return tuple(dict(index=i, n=n, k=k, kind=kind)
                 for i, (n, k, kind) in enumerate(
                     (n, k, kind) for n in range(1, 5)
                     for k in (10, 1000) for kind in KINDS))


def catalog():
    return tuple(dict(attempt=attempt, **row) for attempt in range(1, 6)
                 for row in references())
