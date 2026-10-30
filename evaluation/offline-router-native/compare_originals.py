#!/usr/bin/env python3
"""Compare both saved original layouts; this does not admit either capture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

CAP = 1048576
DISASSEMBLY_SHA = '0ae4995cccbeeb3d414849962b9b946b5e9c3fa3b391cdfd403ea5405730e374'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read(path):
    need(path.is_absolute() and path.resolve(strict=True) == path, 'canonical comparison input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= CAP, 'bounded regular comparison input')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(CAP + 1)
        need(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(fd)) == stamp(path.lstat()),
             'stable complete comparison input')
        return raw
    finally:
        os.close(fd)


def inventory_bytes(d, program, image, heads):
    """Reconstruct every row from validated code, never from saved inventory."""
    rows = ['role\tindex\tpc\tfile_offset\tlength\tselected_jump']
    startup, _ = d.source_roster()
    kernel = d.C.instructions(program)
    count = selected_count = 0
    for role in d.ROLES:
        base = d.BASES['.text.' + role]
        expected_count = len(startup) if role == 'start' else len(kernel) if role == 'kernel' else 1
        need(len(heads[role]) == expected_count, 'derived complete role population')
        offset = image.owned(base, sum(len(code) for _,code in heads[role]), 5)[0]
        for index, (off, code) in enumerate(heads[role]):
            selected = (startup[index].startswith('j') if role == 'start' else
                        kernel[index]['target'] is not None if role == 'kernel' else False)
            rows.append(f'{role}\t{index}\t{base+off}\t{offset+off}\t{len(code)}\t{int(selected)}')
            count += 1; selected_count += int(selected)
    need((count, selected_count) == d.COUNTS[program], 'derived complete head/selected population')
    raw = ('\n'.join(rows) + '\n').encode('ascii')
    need(len(raw) <= CAP, 'derived inventory bound')
    return raw


def elf_metadata(image):
    """Retain actual metadata fields and whole table hashes, not raw table dumps."""
    raw = image.raw
    shoff = int.from_bytes(raw[40:48], 'little')
    fields = ('name_offset','type','flags','address','file_offset','bytes',
              'link','info','alignment','entry_size')
    names = {index:name for name,index in image.by_name.items()}
    sections = []
    for index, row in enumerate(image.sec):
        payload = b'' if row[1] == 8 else raw[row[4]:row[4]+row[5]]
        sections.append(dict(index=index,name=names.get(index,''),**dict(zip(fields,row)),
            file_bytes=len(payload),sha256=sha(payload)))
    symbol = image.sec[image.symtab]
    return dict(e_shoff=shoff,section_count=len(image.sec),
        section_table=dict(bytes=64*len(image.sec),sha256=sha(raw[shoff:shoff+64*len(image.sec)])),
        sections=sections,
        symbol_table=dict(index=image.symtab,entries=len(image.symbols),local_entries=symbol[7],
                          string_table=symbol[6],bytes=symbol[5],sha256=sections[image.symtab]['sha256']),
        string_tables=[dict(index=row['index'],bytes=row['bytes'],sha256=row['sha256'])
                       for row in sections if row['type']==3])


def file_differences(old, new):
    """Account for every differing byte in fixed blocks; at most 256 rows."""
    need(len(old) <= CAP and len(new) <= CAP, 'whole-file comparison bound')
    rows = []; total = 0
    for offset in range(0, max(len(old),len(new)), 4096):
        left, right = old[offset:offset+4096], new[offset:offset+4096]
        if left == right:
            continue
        differences = sum(a != b for a,b in zip(left,right)) + abs(len(left)-len(right))
        total += differences
        rows.append(dict(offset=offset,different_positions=differences,
            old=dict(bytes=len(left),sha256=sha(left)),new=dict(bytes=len(right),sha256=sha(right))))
    return dict(block_bytes=4096,different_positions=total,blocks=rows)


def compare(d, program, old_run, new_run):
    versions = []
    for run in (old_run, new_run):
        original = read(run/'originals'/program/'original')
        obj = read(run/'originals'/program/'subject.o')
        image, reloc, sizes = d.ownership(original, obj, program)
        head_raw = read(run/'materials'/(program+'-heads.txt'))
        heads = d.head_transport(program, head_raw, original, obj, sizes)
        d.code_and_relocations(image, reloc, heads, program)
        inventory = read(run/'materials'/(program+'-inventory.tsv'))
        need(inventory == inventory_bytes(d, program, image, heads),
             'saved inventory equals independently derived complete inventory')
        versions.append((original, obj, image, heads, inventory))
    old, new = versions
    need(old[1] == new[1], 'exact original instruction object')
    need(old[2].entry == new[2].entry and old[2].ph == new[2].ph, 'exact entry and all program headers')
    need(old[0][:40] == new[0][:40] and old[0][48:64] == new[0][48:64],
         'ELF header differs only in section-table offset')
    need(old[2].section('.header_pad')[2] == 3 and new[2].section('.header_pad')[2] == 2,
         'explicit writable-to-readonly padding section change')
    sections = {}
    for name in ('.note.fixture', '.header_pad', '.text', '.data'):
        a, b = old[2].section(name), new[2].section(name)
        need(a[1] == b[1] and a[3:] == b[3:] and (name == '.header_pad' or a[2] == b[2]),
             'unchanged allocated section ownership')
        left = old[2].data(old[2].by_name[name])
        right = new[2].data(new[2].by_name[name])
        need(left == right, 'exact complete allocated section bytes')
        sections[name] = dict(bytes=len(left), sha256=sha(left))
    need(old[3] == new[3] and old[4] == new[4], 'exact complete instruction heads and selection inventory')
    count, selected = d.COUNTS[program]
    rows = new[4].decode('ascii').splitlines()
    need(rows[0] == 'role\tindex\tpc\tfile_offset\tlength\tselected_jump'
         and len(rows) == count+1 and sum(int(row.split('\t')[-1]) for row in rows[1:]) == selected,
         'unchanged full head/selected population')
    return dict(program=program, heads=count, selected=selected, sections=sections,
        original_object_sha256=sha(old[1]), inventory_sha256=sha(new[4]),
        original_files=[dict(bytes=len(v[0]), sha256=sha(v[0])) for v in versions],
        metadata=dict(old=elf_metadata(old[2]),new=elf_metadata(new[2])),
        whole_file_differences=file_differences(old[0],new[0]),
        all_program_headers_equal=True, all_instruction_heads_equal=True,
        complete_text_data_note_padding_equal=True, whole_file_equal=old[0] == new[0])


def main():
    need(not sys.flags.optimize, 'assertions required by the pinned original decoder')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('old-run', 'new-run', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    source = root/'evaluation/offline-corpus/disassembly.py'
    raw = read(source)
    need(sha(raw) == DISASSEMBLY_SHA, 'exact unchanged original decoder')
    d = types.ModuleType('_original_comparison_disassembly')
    d.__file__ = str(source)
    exec(compile(raw, str(source), 'exec'), d.__dict__)
    result = dict(schema='LI2STARTUP-ORIGINAL-COMPARISON-2',
        programs=[compare(d, p, args.old_run, args.new_run) for p in ('checksum', 'rle-roundtrip')],
        native_dispatches=0, capture_admitted=False, qualification_complete=False)
    content = (json.dumps(result, indent=2)+'\n').encode('ascii')
    need(len(content) <= CAP, 'compact complete comparison output')
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as stream:
        need(stream.write(content) == len(content), 'whole comparison output')
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(dict(programs=2, heads=187, selected=42, sha256=sha(content))))


if __name__ == '__main__':
    main()
