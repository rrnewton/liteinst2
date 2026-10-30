#!/usr/bin/env python3
"""Exact package facts, not an implementation of the unsafe loader admission.

This module never executes an ELF, invokes a producer, or creates an admission
from a receipt's booleans. Unknown final-admission authorities fail closed.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

MIB = 1048576
PROGRAMS = ('checksum', 'rle-roundtrip')
COUNTS = {'checksum': (80, 16), 'rle-roundtrip': (107, 26)}
SYMBOL = b'LITEINST_BOOTSTRAP_COMPLETION_V1'
PROFILE = 'li2-offline-router-package-v1'


class Refused(Exception):
    def __init__(self, stage, detail):
        super().__init__(stage + ': ' + detail)
        self.stage, self.detail = stage, detail


def require(ok, stage, detail):
    if not ok:
        raise Refused(stage, detail)


def keys(value, expected, stage):
    require(type(value) is dict and set(value) == set(expected), stage, 'exact keys')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def hexdigest(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'shape', 'sha256')
    return value


def uint(value, cap=(1 << 64) - 1):
    require(type(value) is int and 0 <= value <= cap, 'shape', 'bounded integer')
    return value


def decode(raw):
    require(type(raw) is bytes and len(raw) <= MIB, 'manifest', 'size')
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, 'manifest', 'duplicate JSON key')
            out[key] = value
        return out
    def constant(_):
        raise Refused('manifest', 'nonfinite JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def path_name(value):
    require(type(value) is str and value.startswith('/') and len(value) <= 4096
            and re.fullmatch(r'/[A-Za-z0-9_./+-]+', value), 'path', 'absolute ASCII path')
    parts = value.split('/')[1:]
    require(0 < len(parts) <= 64 and all(p not in ('', '.', '..') for p in parts),
            'path', 'canonical components')
    return value


def stamp(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns]


def open_regular(path):
    """No symlink in ANY component; retain only the owned regular-file fd."""
    path_name(path)
    parts = path.split('/')[1:]
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            observed = os.fstat(fd)
            require(stat.S_ISREG(observed.st_mode), 'custody', 'regular file')
            require(stamp(observed) == stamp(os.stat(parts[-1], dir_fd=parent,
                                                     follow_symlinks=False)),
                    'custody', 'open/path identity')
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)


class Custody:
    """Exact held inode plus pathname bytes, before/after each execution.

    This detects drift; it does not make a mutable same-user pathname sealed.
    That lifetime assumption must be covered by the final admission authority.
    """
    def __init__(self):
        self.files = {}
        self.total = 0

    def retain(self, record, cap):
        keys(record, ('path', 'bytes', 'sha256', 'stat'), 'file-pin')
        path = path_name(record['path'])
        uint(record['bytes'], cap)
        hexdigest(record['sha256'])
        require(type(record['stat']) is list and len(record['stat']) == 6
                and all(type(n) is int and n >= 0 for n in record['stat']),
                'file-pin', 'stat tuple')
        if path in self.files:
            require(self.files[path][0] == record, 'file-pin', 'conflicting pin')
            return self.files[path][2]
        require(self.total + record['bytes'] <= 198 * MIB + 65536,
                'file-bound', 'aggregate input bytes')
        fd = open_regular(path)
        try:
            require(stamp(os.fstat(fd)) == record['stat'], 'custody', 'initial inode metadata')
            raw = self._read(fd, record)
            self.files[path] = (record, fd, raw)
            self.total += len(raw)
            return raw
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _read(fd, record):
        raw = bytearray()
        while len(raw) < record['bytes']:
            part = os.pread(fd, min(65536, record['bytes'] - len(raw)), len(raw))
            require(bool(part), 'custody', 'short file')
            raw.extend(part)
        require(os.pread(fd, 1, len(raw)) == b'', 'custody', 'file extended')
        require(stamp(os.fstat(fd)) == record['stat'] and digest(raw) == record['sha256'],
                'custody', 'bytes/metadata changed')
        return bytes(raw)

    def verify(self):
        for record, held, expected in self.files.values():
            current = open_regular(record['path'])
            try:
                require(stamp(os.fstat(current)) == record['stat'], 'custody', 'path replaced')
                require(self._read(current, record) == expected == self._read(held, record),
                        'custody', 'retained bytes changed')
            finally:
                os.close(current)

    def close(self):
        for _, fd, _ in self.files.values():
            os.close(fd)
        self.files.clear()


class Elf:
    """Bounded little-endian x86-64 ELF inspection; no external readelf output."""
    def __init__(self, raw):
        require(type(raw) is bytes and 64 <= len(raw) <= 16 * MIB,
                'elf', 'file size')
        self.raw = raw
        ident = raw[:16]
        require(ident[:7] == b'\x7fELF\x02\x01\x01' and ident[7] in (0, 3) and ident[8] == 0
                and ident[9:] == b'\0' * 7, 'elf', 'ELF64 little-endian System V')
        (self.kind, machine, version, self.entry, phoff, shoff, flags,
         ehsize, phsize, phnum, shsize, shnum, shnames) = self.unpack('<HHIQQQIHHHHHH', 16)
        require(self.kind in (2, 3) and machine == 62 and version == 1 and flags == 0
                and ehsize == 64 and phsize == 56 and 1 <= phnum <= 128
                and shsize == 64 and 1 <= shnum <= 4096 and shnames < shnum,
                'elf', 'fixed ELF header/no extended indices')
        self.ph = [self.unpack('<IIQQQQQQ', phoff + 56 * i) for i in range(phnum)]
        self.sh = [self.unpack('<IIQQQQIIQQ', shoff + 64 * i) for i in range(shnum)]
        self.loads = []
        for p in self.ph:
            kind, perms, offset, address, _, filesz, memsz, align = p
            require(filesz <= memsz and address + memsz < 1 << 64, 'elf', 'segment extents')
            self.slice(offset, filesz)
            if kind == 1:
                require(perms & ~7 == 0 and perms & 3 != 3 and align in (1, 4096, 2097152)
                        and offset % 4096 == address % 4096, 'elf', 'LOAD flags/alignment')
                self.loads.append(p)
        require(self.loads, 'elf', 'LOAD required')
        for i, p in enumerate(self.loads):
            for q in self.loads[i + 1:]:
                require(not (p[3] < q[3] + q[6] and q[3] < p[3] + p[6]),
                        'elf', 'overlapping LOADs')
        for s in self.sh:
            if s[1] != 8:
                self.slice(s[4], s[5])

    def slice(self, offset, length):
        require(0 <= offset <= len(self.raw) and 0 <= length <= len(self.raw) - offset,
                'elf', 'file bounds')
        return self.raw[offset:offset + length]

    def unpack(self, layout, offset):
        return struct.unpack(layout, self.slice(offset, struct.calcsize(layout)))

    def file_owner(self, address, length, stage='elf'):
        require(0 <= address < 1 << 64 and 0 <= length < 1 << 64
                and address + length < 1 << 64, stage, 'virtual file extent')
        owners = [p for p in self.loads if p[3] <= address
                  and address + length <= p[3] + p[5]]
        require(len(owners) == 1, stage, 'one file-backed virtual owner')
        p = owners[0]
        return p, p[2] + address - p[3]

    def at(self, address, length):
        _, offset = self.file_owner(address, length)
        return self.slice(offset, length)

    def mapped_bytes(self, address, offset, length):
        """Authenticate table bytes by the mapping the kernel actually loads.

        Equality of section address/size/type does not authenticate sh_offset.
        Even an identical copy elsewhere is not the owning file range.
        """
        owner, actual = self.file_owner(address, length, 'completion-relocation')
        require(owner[1] & 4 and actual == offset,
                'completion-relocation', 'table file offset/LOAD owner')
        return self.slice(actual, length)

    def dynamic_tags(self):
        segments = [p for p in self.ph if p[0] == 2]
        require(len(segments) <= 1, 'completion-relocation', 'unique PT_DYNAMIC')
        tags = {}
        for p in segments:
            require(p[5] % 16 == 0 and p[5] <= MIB,
                    'completion-relocation', 'dynamic bounds')
            raw = self.mapped_bytes(p[3], p[2], p[5])
            ended = False
            for at in range(0, len(raw), 16):
                tag, value = struct.unpack_from('<qQ', raw, at)
                if ended:
                    require(tag == value == 0, 'completion-relocation', 'dynamic NULL tail')
                elif tag == 0:
                    ended = True
                elif tag in (2, 5, 6, 7, 8, 9, 10, 11, 17, 18, 19, 20, 23, 35, 36, 37):
                    require(tag not in tags, 'completion-relocation', 'duplicate dynamic tag')
                    tags[tag] = value
            require(ended, 'completion-relocation', 'dynamic terminator')
        return tags

    def dynamic_symbols(self, tags, tables):
        required = (5, 6, 10, 11)  # DT_STRTAB/SYMTAB/STRSZ/SYMENT
        if not any(tag in tags for tag in required):
            return None
        require(all(tag in tags for tag in required) and tags[11] == 24,
                'completion-relocation', 'complete dynamic symbol/string tags')
        matches = [i for i, s in enumerate(self.sh)
                   if s[1] == 11 and s[3] == tags[6]]
        require(len(matches) == 1, 'completion-relocation', 'unique actual DT_SYMTAB section')
        index = matches[0]
        symbols = self.sh[index]
        require(index in tables and symbols[2] & 2,
                'completion-relocation', 'allocated dynamic symbol table')
        self.mapped_bytes(symbols[3], symbols[4], symbols[5])
        strings = self.sh[symbols[6]]
        require(strings[1] == 3 and strings[2] & 2
                and strings[3] == tags[5] and strings[5] == tags[10],
                'completion-relocation', 'actual DT_STRTAB/STRSZ owner')
        self.mapped_bytes(strings[3], strings[4], strings[5])
        return index

    @staticmethod
    def check_relocations(raw, width, symbols, address):
        for at in range(0, len(raw), width):
            target, info = struct.unpack_from('<QQ', raw, at)
            index, kind = info >> 32, info & 0xffffffff
            require(index < len(symbols), 'completion-relocation', 'symbol index')
            # Preserve the conservative sixteen-byte x86-64 relocation extent.
            require(not (target < address + 8 and address < target + 16)
                    and symbols[index][0] != SYMBOL,
                    'completion-relocation', 'relocation aliases completion')
            require(kind != 5 or symbols[index][0] != SYMBOL,
                    'completion-relocation', 'copy relocation')

    def symbols(self, section_index):
        section = self.sh[section_index]
        require(section[1] in (2, 11) and section[9] == 24 and section[5] % 24 == 0
                and section[5] <= MIB and section[6] < len(self.sh),
                'completion-symbol', 'bounded symbol table')
        strings = self.sh[section[6]]
        require(strings[1] == 3 and strings[5] <= MIB, 'completion-symbol', 'string table')
        names = self.slice(strings[4], strings[5])
        result = []
        for offset in range(section[4], section[4] + section[5], 24):
            symbol = self.unpack('<IBBHQQ', offset)
            start = symbol[0]
            require(start < len(names), 'completion-symbol', 'name offset')
            end = names.find(b'\0', start)
            require(end >= start, 'completion-symbol', 'terminated name')
            result.append((names[start:end], symbol))
        return result

    def completion(self):
        require(self.kind == 3, 'completion-symbol', 'bootstrap must be ET_DYN')
        tables = {i: self.symbols(i) for i, s in enumerate(self.sh) if s[1] in (2, 11)}
        matches = [(i, n, s) for i, table in tables.items()
                   for n, (name, s) in enumerate(table) if name == SYMBOL]
        require(matches, 'completion-symbol', 'object definition absent')
        definitions = {tuple(s[1:]) for _, _, s in matches}
        require(len(definitions) == 1, 'completion-symbol', 'conflicting definitions')
        _, info, visibility, section_index, address, size = matches[0][2]
        require(info & 15 == 1 and (info >> 4 == 0 or visibility & 3 == 2)
                and visibility & ~3 == 0 and info >> 4 in (0, 1)
                and size == 8 and address % 8 == 0
                and 0 < section_index < len(self.sh),
                'completion-symbol', 'nonpreemptible aligned eight-byte OBJECT')
        section = self.sh[section_index]
        require(section[1] in (1, 8) and section[2] & 3 == 3
                and section[2] & (4 | 0x400) == 0 and section[8] >= 8
                and section[3] <= address and address + 8 <= section[3] + section[5],
                'completion-symbol', 'allocated writable non-TLS section extent')
        owners = [p for p in self.loads if p[3] <= address and address + 8 <= p[3] + p[6]]
        require(len(owners) == 1 and owners[0][1] == 6,
                'completion-symbol', 'unique RW/non-X LOAD')
        owner = owners[0]
        if address + 8 <= owner[3] + owner[5]:
            require(section[1] == 1, 'completion-symbol', 'file/section storage agrees')
            offset = owner[2] + address - owner[3]
            require(offset == section[4] + address - section[3]
                    and self.slice(offset, 8) == b'\0' * 8,
                    'completion-symbol', 'file-backed initial zero')
        else:
            require(address >= owner[3] + owner[5] and section[1] == 8,
                    'completion-symbol', 'whole object zero-fill')
            offset = None
        # Retain all section-based checks, then independently enumerate and scan
        # the actual LOAD-backed dynamic tables. Headers cannot redirect reads.
        reloc_sections = []
        for i, s in enumerate(self.sh):
            require(s[1] != 19, 'completion-relocation', 'RELR unsupported')
            if s[1] not in (4, 9):
                continue
            width = 24 if s[1] == 4 else 16
            require(s[9] == width and s[5] % width == 0 and s[5] <= MIB
                    and s[6] in tables, 'completion-relocation', 'bounded REL/RELA')
            reloc_sections.append(i)
            self.check_relocations(self.slice(s[4], s[5]), width, tables[s[6]], address)
        tags = self.dynamic_tags()
        require(not any(t in tags for t in (35, 36, 37)), 'completion-relocation', 'DT_RELR unsupported')
        dynamic_symbols = self.dynamic_symbols(tags, tables)
        ranges = []
        for addr_tag, size_tag, entry_tag, width, kind in ((7, 8, 9, 24, 4), (17, 18, 19, 16, 9)):
            if any(t in tags for t in (addr_tag, size_tag, entry_tag)):
                require(all(t in tags for t in (addr_tag, size_tag, entry_tag))
                        and tags[entry_tag] == width,
                        'completion-relocation', 'complete dynamic relocation tags')
                ranges.append((tags[addr_tag], tags[size_tag], width, kind))
        if any(t in tags for t in (2, 20, 23)):
            kind = {7: 4, 17: 9}.get(tags.get(20))
            require(all(t in tags for t in (2, 20, 23)) and kind is not None,
                    'completion-relocation', 'complete PLT relocation tags')
            ranges.append((tags[23], tags[2], 24 if kind == 4 else 16, kind))
        for table_address, length, width, kind in ranges:
            require(length <= MIB and length % width == 0,
                    'completion-relocation', 'bounded actual dynamic relocation table')
            relocation_matches = [self.sh[i] for i in reloc_sections
                       if (self.sh[i][3], self.sh[i][5], self.sh[i][1]) == (table_address, length, kind)]
            require(len(relocation_matches) == 1, 'completion-relocation', 'unique dynamic relocation coverage')
            section = relocation_matches[0]
            require(section[2] & 2 and dynamic_symbols is not None and section[6] == dynamic_symbols,
                    'completion-relocation', 'actual dynamic relocation symbol owner')
            raw = self.mapped_bytes(table_address, section[4], length)
            self.check_relocations(raw, width, tables[dynamic_symbols], address)
        return dict(name=SYMBOL.decode(), address=address, bytes=8, alignment=8,
                    file_offset=offset, load=list(owner), visibility=visibility & 3,
                    binding=matches[0][2][1] >> 4)


def inspect_manifest(raw, custody):
    """Retain concrete package facts. Result deliberately has no execution grant."""
    value = decode(raw)
    keys(value, ('schema', 'profile', 'revision', 'programs', 'loader_inputs',
                 'dependency_edges', 'search_directories', 'admission'), 'manifest')
    require(value['schema'] == 1 and value['profile'] == PROFILE
            and type(value['revision']) is str
            and re.fullmatch('[0-9a-f]{40}', value['revision']), 'manifest', 'profile/revision')
    require(type(value['programs']) is list and [p.get('name') for p in value['programs']]
            == list(PROGRAMS), 'manifest', 'both complete programs in fixed order')
    facts = []
    graph_files = {}
    for p in value['programs']:
        keys(p, ('name', 'heads', 'selected', 'original', 'main', 'bootstrap',
                 'interpreter', 'catalog', 'dependencies', 'entry', 'w01', 'build'), 'program')
        require((p['heads'], p['selected']) == COUNTS[p['name']], 'program', 'full denominator')
        binaries = {}
        for role, cap in (('original', MIB), ('main', 16*MIB), ('bootstrap', 16*MIB),
                          ('interpreter', 16*MIB), ('catalog', 64*MIB), ('w01', MIB), ('build', MIB)):
            binaries[role] = custody.retain(p[role], cap)
        original, main, bootstrap, loader = [Elf(binaries[r]) for r in
                                            ('original', 'main', 'bootstrap', 'interpreter')]
        require(original.kind == main.kind == 2 and loader.kind == 3
                and original.entry == main.entry == uint(p['entry']),
                'program', 'unchanged static main entry')
        interp = [x for x in main.ph if x[0] == 3]
        require(len(interp) == 1 and main.slice(interp[0][2], interp[0][5])
                == p['interpreter']['path'].encode() + b'\0', 'program', 'exact PT_INTERP')
        require(type(p['dependencies']) is list and 1 <= len(p['dependencies']) <= 16,
                'dependency', 'finite nonempty graph')
        dep_total = 0
        for record in [p['bootstrap'], p['interpreter'], *p['dependencies']]:
            data = custody.retain(record, 16*MIB)
            dep_total += len(data)
            require(dep_total <= 128*MIB, 'dependency', 'file aggregate')
            Elf(data)
            if record['path'] in graph_files:
                require(graph_files[record['path']] == record, 'dependency', 'conflicting shared owner')
            graph_files[record['path']] = record
        require(len({r['path'] for r in p['dependencies']}) == len(p['dependencies'])
                and p['bootstrap']['path'] not in {r['path'] for r in p['dependencies']},
                'dependency', 'duplicate dependency/bootstrap')
        facts.append(dict(program=p['name'], entry=p['entry'], completion=bootstrap.completion()))
    keys(value['loader_inputs'], ('preload', 'cache'), 'loader-inputs')
    preload = value['loader_inputs']['preload']
    keys(preload, ('path', 'state', 'file'), 'loader-inputs')
    require(preload['path'] == '/etc/ld.so.preload', 'loader-inputs', 'preload input')
    if preload['state'] == 'ABSENT':
        require(preload['file'] is None and not os.path.lexists(preload['path']),
                'loader-inputs', 'preload absence')
    elif preload['state'] == 'EMPTY_REGULAR':
        require(preload['file']['path'] == preload['path']
                and custody.retain(preload['file'], 0) == b'', 'loader-inputs', 'empty preload')
    else:
        raise Refused('loader-inputs', 'unknown preload state')
    require(value['loader_inputs']['cache']['path'] == '/etc/ld.so.cache',
            'loader-inputs', 'cache input')
    custody.retain(value['loader_inputs']['cache'], 16*MIB)
    require(type(value['dependency_edges']) is list and len(value['dependency_edges']) <= 256,
            'dependency', 'bounded edge roster')
    seen = set()
    for edge in value['dependency_edges']:
        keys(edge, ('from', 'needed', 'to', 'search_evidence'), 'dependency-edge')
        require(edge['from'] in graph_files and edge['to'] in graph_files
                and type(edge['needed']) is str and 0 < len(edge['needed']) <= 4096,
                'dependency-edge', 'owned endpoints/name')
        identity = (edge['from'], edge['needed'])
        require(identity not in seen, 'dependency-edge', 'duplicate resolution')
        seen.add(identity)
        hexdigest(edge['search_evidence'])
    require(type(value['search_directories']) is list
            and 1 <= len(value['search_directories']) <= 64, 'loader-inputs', 'search roster')
    for directory in value['search_directories']:
        keys(directory, ('path', 'snapshot'), 'loader-inputs')
        path_name(directory['path'])
        custody.retain(directory['snapshot'], MIB)
    keys(value['admission'], ('authority', 'receipt', 'unsafe_contract'), 'admission')
    hexdigest(value['admission']['unsafe_contract'])
    custody.retain(value['admission']['receipt'], MIB)
    custody.verify()
    return value, facts


def require_final_admission(manifest, facts, custody):
    """The new W01/final-package authority has not been implemented/reviewed.

    Do NOT replace this with a receipt boolean, a nonzero digest, or completion=1.
    Integration must independently join graph/search/config/runtime/build/unsafe
    contract evidence and return a private capability on its reviewed exact bytes.
    """
    del manifest, facts, custody
    raise Refused('final-package-admission', 'NO_SUPPORTED_AUTHORITY')
