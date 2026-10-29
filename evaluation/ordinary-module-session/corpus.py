"""Fixed input corpus for the restricted two-function CSV session.

Expected field counts come from literal fixtures or a field-list constructor,
not from a second implementation of the target scanner or input recognizer.
This file creates bytes only. It never starts a child, chooses a retry, or
changes the application's 10 ms / 2 ms / 2 s schedule.
"""
from dataclasses import dataclass

MAX_BYTES = 64
MAX_RECORDS = 2048


@dataclass(frozen=True)
class Record:
    payload: bytes
    fields: int


@dataclass(frozen=True)
class Case:
    name: str
    data: bytes
    accepted: tuple[Record, ...]
    outcome: str  # eof, input_error, or input_incomplete
    close_input: bool = True


def field_list(fields: tuple[tuple[bytes, bool], ...]) -> Record:
    """Serialize a declarative list of fields; count the list, not the bytes."""
    assert fields
    encoded = []
    for data, quoted in fields:
        assert type(data) is bytes and type(quoted) is bool
        assert all(0x20 <= byte <= 0x7e for byte in data)
        if quoted:
            encoded.append(b'"' + data.replace(b'"', b'""') + b'"')
        else:
            assert b',' not in data and b'"' not in data
            encoded.append(data)
    payload = b','.join(encoded)
    assert len(payload) <= MAX_BYTES
    return Record(payload, len(fields))


# The existing finite application's complete literal population is retained.
# These literal expected counts do not depend on a parser or the constructor.
LITERALS = (
    Record(b'', 1),
    Record(b'a', 1),
    Record(b'a,b,c', 3),
    Record(b',', 2),
    Record(b',,', 3),
    Record(b'a,', 2),
    Record(b',a', 2),
    Record(b'""', 1),
    Record(b'"a,b"', 1),
    Record(b'"a","b"', 2),
    Record(b'a,"b,c",d', 3),
    Record(b'"a""b",c', 2),
    Record(b'""""', 1),
    Record(b'"",""', 2),
    Record(b'plain,"say ""hi""",,tail', 4),
    Record(b'"comma,, and ""quote""",last,', 3),
)


def framed(records: tuple[Record, ...]) -> bytes:
    assert len(records) <= MAX_RECORDS
    assert all(len(record.payload) <= MAX_BYTES for record in records)
    return b''.join(record.payload + b'\n' for record in records)


def valid_population() -> tuple[Record, ...]:
    # Every possible legal payload length, both empty/nonempty target paths,
    # both leading/trailing spaces, and each printable byte as an actual field.
    lengths = tuple(field_list(((b'x' * n, False),)) for n in range(65))
    printable = tuple(
        field_list(((bytes([byte]), byte in (0x22, 0x2c)), (b'x', False)))
        for byte in range(0x20, 0x7f)
    )
    edges = (
        field_list(tuple((b'', False) for _ in range(65))),
        field_list(((b'x' * 62, True),)),
        field_list(((b' ' * 64, False),)),
        field_list(((b' lead ', False), (b' tail ', True))),
        field_list(((b'"' * 31, True),)),
        field_list(((b',"', True), (b'', False), (b' ', False))),
    )
    return LITERALS + lengths + printable + edges


# Each suffix must refuse before accepting any of its records. Prefixes are
# deliberately nonempty: refusal must not drop already accepted work.
INVALID_SUFFIXES = (
    ('quote_in_unquoted', b'a"b\n'),
    ('text_after_close', b'"a"b\n'),
    ('space_after_close', b'"a" \n'),
    ('space_before_open', b' "a"\n'),
    ('unclosed_empty', b'"\n'),
    ('unclosed_text', b'"a\n'),
    ('odd_quotes', b'"""\n'),
    ('escaped_without_close', b'"a""\n'),
    ('embedded_lf', b'"a\nb"\n'),
    ('carriage_return', b'a\r\n'),
    ('nul', b'a\x00b\n'),
    ('tab', b'a\tb\n'),
    ('control', b'a\x1fb\n'),
    ('delete', b'a\x7fb\n'),
    ('non_ascii_low', b'a\x80b\n'),
    ('non_ascii_high', b'a\xffb\n'),
    ('overlong_plain', b'x' * 65 + b'\n'),
    ('overlong_quoted', b'"' + b'x' * 63 + b'"\n'),
    ('unterminated_plain', b'a'),
    ('unterminated_quoted', b'"a"'),
    ('unterminated_64', b'x' * 64),
)


def cases() -> tuple[Case, ...]:
    population = valid_population()
    maximum = (field_list(((b'x' * 64, False),)),) * MAX_RECORDS
    prefix = (Record(b'a,b', 2), Record(b'""', 1), Record(b'', 1))
    values = [
        Case('empty_file', b'', (), 'eof'),
        Case('empty_record', b'\n', (Record(b'', 1),), 'eof'),
        Case('grammar_population', framed(population), population, 'eof'),
        Case('maximum_records_and_bytes', framed(maximum), maximum, 'eof'),
    ]
    values.extend(
        Case('invalid_' + name, framed(prefix) + suffix, prefix, 'input_error')
        for name, suffix in INVALID_SUFFIXES
    )
    # The cap is not EOF: even one additional byte must refuse. At exactly the
    # cap a still-open pipe is incomplete until EOF is actually observed.
    values.extend((
        Case('record_cap_extra_lf', framed(maximum) + b'\n', maximum, 'input_error'),
        Case('record_cap_extra_byte', framed(maximum) + b'x', maximum, 'input_error'),
        Case('record_cap_without_eof', framed(maximum), maximum, 'input_incomplete', False),
        Case('empty_open_pipe', b'', (), 'input_incomplete', False),
        Case('partial_open_record', framed(prefix) + b'"a', prefix, 'input_incomplete', False),
    ))
    assert len(values) == 30 and len({case.name for case in values}) == len(values)
    return tuple(values)
