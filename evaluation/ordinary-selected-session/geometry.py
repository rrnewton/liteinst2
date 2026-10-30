"""Fixed fixture symbol facts from pinned readelf --wide --symbols output.

This parser supplies no ELF-byte, instruction, page, custody or native authority.
The owner separately authenticates the command/tool/input and complete bodies.
Old ordinary-module-native.selection and its LOCAL/DEFAULT rules are unchanged.
"""
import re

if not __debug__:
    raise SystemExit('assertions required')

NAMES = ('first_equal', 'uppercase_count')
CAP = 4 * 1024 * 1024
U64 = (1 << 64) - 1
HEADER = re.compile(r"Symbol table '([^']+)' contains ([1-9][0-9]*) entries:")
COLUMNS = ('Num:', 'Value', 'Size', 'Type', 'Bind', 'Vis', 'Ndx', 'Name')


def decimal(word):
    assert re.fullmatch(r'0|[1-9][0-9]*', word)
    return int(word)


def definitions(data, *, stripped):
    """Return both exact definitions; reject ambiguous origins and duplicates."""
    assert type(data) is bytes and 0 < len(data) <= CAP and data.endswith(b'\n')
    assert type(stripped) is bool
    assert all(byte == 10 or byte == 9 or 0x20 <= byte <= 0x7e for byte in data)
    lines = data.decode('ascii').split('\n')
    wanted = ('.dynsym',) if stripped else ('.dynsym', '.symtab')
    tables, cursor = [], 0
    while cursor < len(lines):
        if lines[cursor] == '':
            cursor += 1
            continue
        match = HEADER.fullmatch(lines[cursor])
        assert match is not None and len(tables) < len(wanted)
        origin, count = match[1], int(match[2])
        assert origin == wanted[len(tables)] and 1 <= count <= 65536
        cursor += 1
        assert cursor < len(lines) and tuple(lines[cursor].split()) == COLUMNS
        cursor += 1
        selected = {}
        for index in range(count):
            assert cursor < len(lines)
            row = lines[cursor].split()
            cursor += 1
            assert len(row) in (7, 8) and row[0] == str(index) + ':'
            assert re.fullmatch(r'[0-9a-fA-F]{16}', row[1])
            size = decimal(row[2])
            assert size <= U64
            name = row[7] if len(row) == 8 else ''
            if name.split('@', 1)[0] not in NAMES:
                continue
            assert name in NAMES and name not in selected
            assert row[3:6] == ['FUNC', 'GLOBAL', 'PROTECTED']
            section = decimal(row[6])
            va = int(row[1], 16)
            assert section > 0 and va > 0 and 5 <= size <= 256 and va + size <= U64
            selected[name] = dict(name=name, elf_va=va, extent=size, symbol_type=row[3],
                                  binding=row[4], visibility=row[5], section_index=section)
        assert set(selected) == set(NAMES)
        tables.append(tuple(selected[name] for name in NAMES))
    assert len(tables) == len(wanted) and all(table == tables[0] for table in tables)
    first, second = tables[0]
    assert first['elf_va'] + first['extent'] <= second['elf_va']
    return tables[0]


def preserved(unstripped, stripped):
    """Require the surviving dynamic definitions to match all original facts."""
    before = definitions(unstripped, stripped=False)
    after = definitions(stripped, stripped=True)
    assert before == after
    return after
