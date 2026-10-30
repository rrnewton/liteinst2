"""Finite GNU startup facts under an explicit unsafe platform contract.

The caller must supply a separately frozen contract SHA and actual saved W01
and bootstrap joins. Inventory and a contract digest alone never authorize a
launch. Paths remain mutable: the explicit lifetime obligation is indispensable.
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
ROLES = ('loader', 'libc', 'libgcc')
SONAMES = {'ld-linux-x86-64.so.2': 'loader', 'libc.so.6': 'libc', 'libgcc_s.so.1': 'libgcc'}
OBLIGATIONS = {
  "file_and_mapping_lifetime": "No actor may replace or modify package, loader, dependency, search or configuration inputs from preflight through child exit. Owned descriptors and before/after identity checks detect violations; they do not seal mutable pathnames. Bootstrap mappings and router-owned storage remain live for the process lifetime.",
  "history_and_entry": "Only normal kernel exec of the unchanged authored static ET_EXEC entry is permitted. Before bootstrap commit there is one initial thread, no application callback, no asynchronous reentry into application code, and no earlier execution of the patched main.",
  "loader_and_dependencies": "I accept the exact pinned GNU loader, libc and libgcc implementation and this finite dependency/search graph as trusted startup code, including their relocation, IFUNC, TLS, constructor, CET and allocator behavior. The recorded file facts alone do not establish this trust.",
  "runtime_readiness": "The pinned loader establishes libc, Rust allocation and TLS readiness before the bootstrap constructor. The constructor exclusively owns the Rust panic-hook transition; no other thread, signal handler or callback accesses that hook during initialization.",
  "scope_and_failures": "This accepts only the two complete authored programs under the fixed observer and20-pair/40-invocation N01 populations. Every mismatch or unavailable condition refuses, with no retry, subset, repaired RIP/code or relaxed comparison. Startup completion grants no route coverage, native correctness or performance claim.",
  "signals_stack_and_isa": "The launcher controls inherited signal state and supplies the reviewed empty environment and exact argv. Runtime admission and the observer must still check actual stack, xstate, target ISA, signal and mapping conditions; a contract identifier never substitutes for those checks."
}


def need(ok, detail):
    if not ok:
        raise ValueError(detail)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def exact(a, b):
    return canonical(a) == canonical(b)


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, 'exact digest')
    return value


def decode(raw):
    need(type(raw) is bytes and len(raw) <= MIB, 'bounded final JSON')
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate final JSON key')
            value[key] = item
        return value
    def constant(_):
        raise ValueError('nonfinite final JSON number')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def keys(value, fields, detail):
    need(type(value) is dict and set(value) == set(fields), detail)


def directory_observation(package, path):
    """Nonrecursive names/alias snapshot; semantics come from reviewed loader."""
    package.path_name(path)
    # Existing ancestors must be canonical. A missing hwcaps parent is allowed,
    # but a symlinked or non-directory existing ancestor is never followed.
    current = Path('/')
    for part in Path(path).parts[1:]:
        current = current/part
        try:
            info = current.lstat()
        except FileNotFoundError:
            return dict(path=path, state='ABSENT', identity=None, entries_sha256=None)
        need(stat.S_ISDIR(info.st_mode), 'search path ancestor is a real directory')
    before = os.stat(path, follow_symlinks=False)
    entries = []
    with os.scandir(path) as scan:
        for entry in scan:
            need(len(entries) < 4096, 'bounded search directory roster')
            info = entry.stat(follow_symlinks=False)
            kind = ('symlink' if stat.S_ISLNK(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode)
                    else 'file' if stat.S_ISREG(info.st_mode) else 'other')
            entries.append(dict(name=entry.name, kind=kind, link=os.readlink(entry.path) if kind == 'symlink' else None))
    after = os.stat(path, follow_symlinks=False)
    need(package.stamp(before) == package.stamp(after), 'search directory changed while read')
    entries.sort(key=lambda row: row['name'])
    return dict(path=path, state='PRESENT', identity=package.stamp(before)[:3], entries_sha256=sha(canonical(entries)))


def alias_observation(package, path):
    package.path_name(path)
    parent = Path(path).parent
    need(parent.resolve(strict=True) == parent, 'canonical alias parent')
    before = os.lstat(path)
    need(stat.S_ISLNK(before.st_mode), 'actual pathname alias')
    target = os.readlink(path)
    need(package.stamp(os.lstat(path)) == package.stamp(before), 'alias changed while read')
    return dict(path=path, target=target, identity=package.stamp(before))


def contract(raw, expected, package, held):
    """Recheck bytes/identities; acceptance of unsafe meaning stays explicit."""
    need(os.uname().sysname == 'Linux' and os.uname().machine == 'x86_64' and
         os.sysconf('SC_PAGE_SIZE') == 4096, 'actual Linux x86-64 4096-byte page platform')
    need(sha(raw) == digest(expected), 'externally frozen platform contract')
    value = decode(raw)
    keys(value, ('schema', 'authority', 'platform', 'files', 'sonames', 'loader_inputs',
        'search_directories', 'aliases', 'obligations', 'review_basis', 'environment',
        'programs', 'datasets_per_program', 'N01_program_dataset_pairs', 'N01_invocations'), 'exact platform contract shape')
    need(value['schema'] == 'LI2STARTUP-PLATFORM-CONTRACT-1' and
         value['authority'] == 'EXPLICIT_UNSAFE_GNU_STATIC_EXEC_V1' and
         value['platform'] == 'linux-x86_64-gnu-4096', 'supported explicit unsafe authority')
    need(exact(value['obligations'], OBLIGATIONS) and type(value['review_basis']) is str and
         128 <= len(value['review_basis']) <= 32768, 'whole explicit unsafe obligations and concrete review basis')
    need(exact(value['environment'], {}) and exact(value['programs'], list(PROGRAMS)) and
         exact([value['datasets_per_program'], value['N01_program_dataset_pairs'], value['N01_invocations']], [10, 20, 40]),
         'empty environment and unchanged complete native population')
    need(exact(value['sonames'], SONAMES), 'finite exact loader name graph')
    keys(value['files'], ROLES, 'exact loader/libc/libgcc inventory')
    files = {role: held.retain(value['files'][role], 16*MIB) for role in ROLES}
    need(len({pin['path'] for pin in value['files'].values()}) == 3 and
         len({tuple(pin['stat'][:2]) for pin in value['files'].values()}) == 3, 'distinct platform objects')
    for pin in value['files'].values():
        need(pin['stat'][2] & 0o6000 == 0, 'no set-ID platform file')
    inputs = value['loader_inputs']
    keys(inputs, ('cache', 'preload'), 'exact loader input roster')
    need(inputs['cache']['path'] == '/etc/ld.so.cache', 'actual GNU cache path')
    held.retain(inputs['cache'], MIB)
    preload = inputs['preload']
    keys(preload, ('path', 'state', 'file'), 'exact preload state')
    need(preload['path'] == '/etc/ld.so.preload', 'actual GNU preload path')
    if preload['state'] == 'ABSENT':
        need(preload['file'] is None and not os.path.lexists(preload['path']), 'preload remains absent')
    else:
        need(preload['state'] == 'EMPTY_REGULAR' and preload['file']['path'] == preload['path'] and
             held.retain(preload['file'], 0) == b'', 'preload is the exact empty regular file')
    search, aliases = value['search_directories'], value['aliases']
    need(type(search) is list and 1 <= len(search) <= 64 and type(aliases) is list and len(aliases) <= 64,
         'bounded explicit search/alias population')
    need(len({row['path'] for row in search}) == len(search) and len({row['path'] for row in aliases}) == len(aliases),
         'unique search and alias paths')
    for row in search:
        need(exact(row, directory_observation(package, row['path'])), 'exact reviewed search directory state')
    for row in aliases:
        need(exact(row, alias_observation(package, row['path'])), 'exact reviewed path alias')
    return value, files


def no_cet(notes):
    for note in notes:
        for prop in note['properties']:
            if prop['kind'] == 0xc0000002:  # GNU_PROPERTY_X86_FEATURE_1_AND
                raw = bytes.fromhex(prop['bytes'])
                need(len(raw) == 4 and struct.unpack('<I', raw)[0] & 3 == 0,
                     'finite profile has no IBT or SHSTK GNU property')


def library_facts(raw, role, package, dso):
    elf = package.Elf(raw)
    need(elf.kind == 3, 'platform library ET_DYN')
    pages = dso.load_pages(elf)
    tags, offsets = dso.dynamic(elf)
    need(all(k in tags for k in (5, 6, 10, 11)) and tags[11] == 24 and tags[10] <= MIB,
         'platform dynamic string/symbol tables')
    strings = elf.at(tags[5], tags[10])
    tables = {i: elf.symbols(i) for i, s in enumerate(elf.sh) if s[1] in (2, 11)}
    symbols = tables[elf.dynamic_symbols(tags, tables)]
    needed = [dso.string(strings, at) for at in offsets]
    expected = {'loader': [], 'libc': ['ld-linux-x86-64.so.2'], 'libgcc': ['libc.so.6']}[role]
    need(needed == expected and 15 not in tags and 29 not in tags, 'exact platform dependency edges/no search injection')
    soname = dso.string(strings, tags[14]) if 14 in tags else None
    need(soname == next(name for name, r in SONAMES.items() if r == role), 'actual platform SONAME')
    need(22 not in tags and not tags.get(30, 0) & 4, 'no platform text relocations')
    records = dso.relocations(elf, tags)
    need(all(r['symbol'] < len(symbols) for r in records), 'platform relocation symbol ownership')
    stack = [p for p in elf.ph if p[0] == 0x6474e551]
    need(len(stack) == 1 and stack[0][1] == 6, 'platform GNU stack remains RW/non-X')
    notes = dso.notes(elf)
    # Platform code may contain ENDBR/IBT notes. The reviewed loader contract
    # covers its behavior with an unmarked main and non-CET bootstrap. Do not
    # silently strip those facts or infer current kernel SHSTK from ELF notes.
    return dict(schema='LI2STARTUP-PLATFORM-LIBRARY-FACTS-1', role=role, bytes=len(raw), sha256=sha(raw),
        entry=elf.entry, loads=[list(p) for p in elf.loads], page_owners=pages,
        needed=needed, soname=soname, dynamic_tags={str(k): v for k, v in sorted(tags.items())},
        symbols=[dict(index=i, name=n.hex(), info=s[1], visibility=s[2], section=s[3], value=s[4], bytes=s[5])
                 for i, (n, s) in enumerate(symbols)], relocations=records,
        constructors=dso.constructors(elf, tags, records, symbols), notes=notes,
        tls=[list(p) for p in elf.ph if p[0] == 7], stack=list(stack[0]),
        relro=[list(p) for p in elf.ph if p[0] == 0x6474e552])


def library_facts_v2(raw, role, package, dso, namespace):
    """Named whole-namespace dependency profile; the v1 function is unchanged."""
    need(namespace.objects[role]['elf'].raw == raw, 'actual namespace dependency bytes')
    elf = package.Elf(raw)
    need(elf.kind == 3, 'platform library ET_DYN')
    pages = dso.load_pages(elf)
    tags, offsets = dso.dynamic(elf)
    need(all(k in tags for k in (5, 6, 10, 11)) and tags[11] == 24 and tags[10] <= MIB,
         'platform dynamic string/symbol tables')
    strings = elf.at(tags[5], tags[10])
    tables = {i: elf.symbols(i) for i, s in enumerate(elf.sh) if s[1] in (2, 11)}
    symbols = tables[elf.dynamic_symbols(tags, tables)]
    needed = [dso.string(strings, at) for at in offsets]
    expected = {'loader': [], 'libc': ['ld-linux-x86-64.so.2'], 'libgcc': ['libc.so.6']}[role]
    need(needed == expected and 15 not in tags and 29 not in tags, 'exact platform dependency edges/no search injection')
    soname = dso.string(strings, tags[14]) if 14 in tags else None
    need(soname == next(name for name, r in SONAMES.items() if r == role), 'actual platform SONAME')
    need(22 not in tags and not tags.get(30, 0) & 4, 'no platform text relocations')
    records = dso.relocations(elf, tags)
    need(all(r['symbol'] < len(symbols) for r in records), 'platform relocation symbol ownership')
    stack = [p for p in elf.ph if p[0] == 0x6474e551]
    need(len(stack) == 1 and stack[0][1] == 6, 'platform GNU stack remains RW/non-X')
    notes = dso.notes(elf)
    # Platform code may contain ENDBR/IBT notes. The reviewed loader contract
    # covers its behavior with an unmarked main and non-CET bootstrap. Do not
    # silently strip those facts or infer current kernel SHSTK from ELF notes.
    return dict(schema='LI2STARTUP-PLATFORM-LIBRARY-FACTS-2',
        constructor_profile='gnu-five-object-unique-versioned-constructor-v1', namespace=namespace.identities, role=role, bytes=len(raw), sha256=sha(raw),
        entry=elf.entry, loads=[list(p) for p in elf.loads], page_owners=pages,
        needed=needed, soname=soname, dynamic_tags={str(k): v for k, v in sorted(tags.items())},
        symbols=[dict(index=i, name=n.hex(), info=s[1], visibility=s[2], section=s[3], value=s[4], bytes=s[5])
                 for i, (n, s) in enumerate(symbols)], relocations=records,
        constructors=namespace.constructors(role, records), notes=notes,
        tls=[list(p) for p in elf.ph if p[0] == 7], stack=list(stack[0]),
        relro=[list(p) for p in elf.ph if p[0] == 0x6474e552])


def object_pages(raw, pin, package, dso):
    """Actual initial/relocated page owners; only immutable bytes are compared."""
    elf = package.Elf(raw)
    need(sha(raw) == pin['sha256'] and len(raw) == pin['bytes'], 'actual object bytes and pin')
    owners = dso.load_pages(elf)
    relros = [p for p in elf.ph if p[0] == 0x6474e552]
    need(len(relros) <= 1, 'finite unique RELRO')
    protected = None
    if relros:
        p = relros[0]
        need(p[6] > 0 and p[2] % 4096 == p[3] % 4096, 'nonempty congruent RELRO')
        start, end = p[3] & ~4095, (p[3] + p[6]) & ~4095
        need(start < end and any(o['flags'] == 6 and o['start'] <= start < end <= o['end'] for o in owners),
             'RELRO rounded range has one writable LOAD owner')
        protected = (start, end)
    result = []
    for owner in owners:
        flags = owner['flags']
        need(flags in (4, 5, 6) and owner['end'] < 1 << 47, 'readable bounded non-WX mapped pages')
        count = (owner['end'] - owner['start']) // 4096
        need(count <= 65536-len(result), 'unchanged observer page-count bound')
        initial = {4: 'r--p', 5: 'r-xp', 6: 'rw-p'}[flags]
        for address in range(owner['start'], owner['end'], 4096):
            backed = address < owner['file_end']
            offset = owner['file_offset'] + address-owner['start'] if backed else 0
            immutable = None
            if flags != 6:
                need(backed and owner['file_zero_tail'] is None, 'immutable page wholly backed without loader zero writes')
                immutable = (raw[offset:offset+4096] + bytes(4096))[:4096].hex()
            final = 'r--p' if protected and protected[0] <= address < protected[1] else initial
            result.append(dict(relative=address, file_offset=offset, permissions_at_exec=initial,
                permissions_at_entry=final, file_backed=backed, bytes=immutable))
    return dict(file=pin, pages=result)


def main_facts(item, contract_value, contract_sha, package, dso, *, dependency=None):
    main = item['main']
    raw = main['product']['candidate.elf']
    elf, original = package.Elf(raw), package.Elf(main['original'])
    need(elf.kind == original.kind == 2 and elf.entry == original.entry and
         all(p[0] not in (2, 3) for p in original.ph), 'unchanged original static ET_EXEC entry')
    interps = [p for p in elf.ph if p[0] == 3]
    need(len(interps) == 1 and 1 < interps[0][5] <= 4096, 'actual bounded main interpreter')
    p = interps[0]
    interp = elf.mapped_bytes(p[3], p[2], p[5])
    need(interp == contract_value['files']['loader']['path'].encode('ascii') + b'\0', 'exact canonical pinned main interpreter')
    tags, needed = dso.dynamic(elf)
    if dependency is None:
        need(set(tags) == {5, 10} and len(needed) == 1 and tags[10] <= MIB,
             'main carrier has only readonly strings and one dependency')
    else:
        # Profile2 passes the exact separately pinned checker module. Re-read
        # actual ELF facts here; a stored profile label is not acceptance.
        dependency.main_namespace(elf, tags, needed, dso)
    bootstrap = dso.string(elf.at(tags[5], tags[10]), needed[0])
    policy = main['policy']
    need(bootstrap == policy['bootstrap'] == item['bootstrap_pin']['path'] and
         policy['interpreter'] == contract_value['files']['loader']['path'] and policy['contract'] == contract_sha,
         'actual main/policy/bootstrap/unsafe contract join')
    expected_deps = sorted((pin['path'], pin['sha256']) for pin in contract_value['files'].values())
    need(policy['dependencies'] == expected_deps, 'exact full policy dependency inventory')
    no_cet(dso.notes(elf)); no_cet(item['linked']['notes'])
    needed = item['linked']['needed']
    need(needed and len(set(needed)) == len(needed) and all(name in SONAMES for name in needed) and
         {'libc.so.6', 'libgcc_s.so.1'} <= set(needed) and item['linked']['rpath'] is None and item['linked']['runpath'] is None,
         'bootstrap uses only reviewed GNU dependency names/no search injection')
    owner, offset = elf.file_owner(elf.entry, 15)
    need(owner[1] == 5, 'actual entry lies in executable nonwritable bytes')
    return dict(entry=elf.entry, entry_bytes=raw[offset:offset+15].hex())
