#!/usr/bin/env python3
"""Release build closure for the distinct two-image/one-lifetime group.

The caller retains the existing Build/process bounds and finalizer. This helper
checks actual archive, policy, compiler inputs and storage; it grants no native
qualification. Existing fixed and dynamic build helpers remain unchanged.
"""
import json
from pathlib import Path
import re
import shutil
import struct

from maps_view import (need, fact, SELECTED, UNITS, MACROS, recipe, expand, headers,
                       bridge_check, ENV, hidden_memset, body_check, digest, H)
from linked_epoch_build import FIXED_DOMAIN
from scalar_span_trace_build import fast_bytes
from persistent_epoch_build import FEATURES, POLICY_INPUTS as BASE_POLICY_INPUTS, dynamic_original_image

REPLACEMENTS = {
    'persistent_plan.h': 'persistent_group_plan.h',
    'persistent_plan.c': 'persistent_group_plan.c',
    'persistent_compact.h': 'persistent_group_compact.h',
    'persistent_compact.c': 'persistent_group_compact.c',
    'persistent_lifetime.h': 'persistent_group_lifetime.h',
    'persistent_runtime.h': 'persistent_group_runtime.h',
    'persistent_source.inc': 'persistent_group_source.inc',
    'persistent_rseq.inc': 'persistent_group_rseq.inc',
    'persistent_controller.inc': 'persistent_group_controller.inc',
    'build-persistent-epoch.sh': 'build-persistent-group.sh',
    'persistent_epoch_binding.py': 'persistent_group_binding.py',
}
POLICY_INPUTS = tuple(REPLACEMENTS.get(name, name) for name in BASE_POLICY_INPUTS) + (
    'persistent_plan.h', 'persistent_compact.h', 'persistent_epoch_binding.py',
)
DISPATCH_POLICY_INPUTS = tuple({'build-persistent-group.sh': 'build-persistent-resident.sh',
    'persistent_group_binding.py': 'persistent_resident_binding.py'}.get(name, name)
    for name in POLICY_INPUTS) + ('persistent_group_binding.py', 'linked_jmp_dispatch.h', 'linked_jmp_dispatch.c')
DISPATCH_PROVIDERS = ('li2_decoder_decode', 'li2_jd_describe', 'li2_jd_emit', 'li2_jd_validate',
                      'li2_jd_recover', 'li2_pg_dispatch_binding', 'li2_pg_compact_dispatch')

PROVIDERS = ('li2_decoder_link_none', 'li2_link_plan_page', 'li2_link_plan_validate',
             'li2_decoder_mov_store', 'li2_pg_plan_pages', 'li2_pg_plan_validate',
             'li2_pg_miss_valid', 'li2_pg_placement', 'li2_pg_compact_build',
             'li2_pg_compact_validate', 'li2_pg_compact_guard', 'li2_pg_compact_recover',
             'li2_mg_emit', 'li2_mg_recover', 'li2_pg_owner_phase', 'li2_pg_owner_layout',
             'li2_pg_source_prepare', 'li2_pg_source_release', 'li2_pg_source_cancel',
             'li2_pg_source_key_equal', 'li2_pg_rseq_begin', 'li2_pg_rseq_close', 'li2_pg_rseq_cancel')


def binding_config(builder, archive, image, output, pin, binary, run, *, dispatch=False, counters=False):
    need(type(dispatch) is bool, 'explicit typed resident policy selector')
    need(type(counters) is bool and not (counters and dispatch), 'counter and resident policy selectors are mutually exclusive')
    image = pin(binary(image)); original = dynamic_original_image(image); values = []
    policy_inputs = (DISPATCH_POLICY_INPUTS if dispatch else POLICY_INPUTS) + (
        ('persistent_group_counters.h', 'persistent_group_counters.inc',
         'build-persistent-group-counters.sh', 'persistent_group_counter_binding.py') if counters else ())
    for name in policy_inputs:
        path = pin(SELECTED/name); value = fact(path)
        if name in FIXED_DOMAIN:
            size, sha = FIXED_DOMAIN[name]
            need(digest(value) == digest(dict(bytes=size, sha256=sha)), 'unchanged reviewed scalar/NONE decoder domain')
        if name.endswith('.rs'):
            need(digest(builder.record['dep_info'].get('tools/page-entry/selected/'+name)) == digest(value),
                 'actual archive compiled each bound decoder source')
        values.append(dict(path=name, **value))
    archive = pin(archive); archive_fact = fact(archive)
    policy = digest(dict(sources=values, original=original))
    literal = lambda sha: '{'+','.join('0x'+sha[i:i+2] for i in range(0, 64, 2))+'}'
    linked = ('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n'
              '#define LI2_LINK_BINDING_VERSION 1\n'
              '#define LI2_LINK_ARCHIVE_SHA256 '+literal(archive_fact['sha256'])+'\n'
              '#define LI2_LINK_POLICY_SHA256 '+literal(policy)+'\n#endif\n').encode()
    persistent = ('#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n'
                  '#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION '+('2' if dispatch else '1')+'\n'
                  '#define LI2_PG_ARCHIVE_SHA256 '+literal(archive_fact['sha256'])+'\n'
                  '#define LI2_PG_POLICY_SHA256 '+literal(policy)+'\n#endif\n').encode()
    expected = {'linked_epoch_config.h': linked, 'persistent_group_config.h': persistent}
    manifest = output/('persistent_resident_binding.json' if dispatch else 'persistent_group_binding.json')
    need(not manifest.exists() and not any((output/n).exists() for n in expected), 'fresh binding outputs')
    _, out, err = run('persistent-group-policy-binding', [builder.tools['python'], '-B',
                     SELECTED/('persistent_group_counter_binding.py' if counters else 'persistent_resident_binding.py' if dispatch else 'persistent_group_binding.py'),
                     SELECTED, archive, image, output], env=builder.environment)
    need(out == err == b'', 'source-owned persistent binder has no diagnostics')
    header_facts = {}
    for name, data in expected.items():
        path = pin(binary(output/name))
        need(path.read_bytes() == data, 'whole independent archive/policy/image header')
        header_facts[name] = dict(path=str(path), **fact(path))
    record = dict(version=2 if dispatch else 1,
                  profile='persistent-group-final-counters-v1' if counters else 'persistent-resident-dispatch-v2' if dispatch else 'persistent-group-two-image-v1', archive=archive_fact,
                  policy_sha256=policy, original=original, sources=values,
                  headers={name: dict(bytes=len(data), sha256=H(data)) for name, data in expected.items()})
    manifest = pin(binary(manifest))
    need(manifest.read_bytes() == (json.dumps(record, sort_keys=True)+'\n').encode(), 'complete typed persistent binding manifest')
    return dict(**record, header_paths=header_facts, manifest=dict(path=str(manifest), **fact(manifest)))


def protected_extents(builder, bridge, symbols, pin, run, state):
    """Derive actual group storage from DWARF; never execute the bridge."""
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    gdb_environment = dict(builder.environment, MALLOC_ARENA_MAX='1')
    _, out, err = run('persistent-group-gdb-version', [gdb, '--version'], profile='inspect', env=gdb_environment)
    need(out and not err, 'actual GDB tool identity')
    expression = ('printf "LI2_PG_EXTENTS %llu %llu %llu %llu %llu %llu %llu %llu\\n", '
                  '(unsigned long long)sizeof(struct pe_payload), (unsigned long long)sizeof(pe), '
                  '(unsigned long long)sizeof(struct li2_pg_compact), '
                  '(unsigned long long)sizeof(struct li2_pg_plan), '
                  '(unsigned long long)sizeof(((struct li2_pg_compact*)0)->image), '
                  '(unsigned long long)sizeof(((struct li2_pg_compact*)0)->stub_image), '
                  '(unsigned long long)sizeof(struct li2_mg_plan), '
                  '(unsigned long long)sizeof(struct li2_pg_layout)')
    _, out, err = run('persistent-group-protected-extents', [gdb, '-nx', '-nh', '-batch',
                     '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
                     '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
                     '-ex', 'file '+str(bridge), '-ex', expression], profile='inspect', env=gdb_environment)
    match = re.fullmatch(rb'LI2_PG_EXTENTS ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)\n', out)
    need(not err and match is not None, 'one actual group DWARF storage-size result')
    payload, owner, compact, full, images, stubs, recovery, layout = map(int, match.groups())
    rounded = (payload+4095) & ~4095
    need((compact, full, images, stubs, recovery, layout) == (353600, 981312, 65536, 4096, 6488, 40) and
         compact < payload <= rounded <= 96*4096 and owner > payload,
         'actual typed group primary, full reconstruction, two images and stub storage')
    rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [b'pe']]
    need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b', b'B') and
         int(rows[0][1], 16) == owner, 'actual ELF group owner equals DWARF extent')
    state['protected_extents'] = dict(payload=payload, proof_rounded=rounded, owner=owner,
        compact=compact, full=full, images=images, stubs=stubs, code=images+stubs,
        code_extents=3, code_pages=17, slots=4096, spill=4096, allocation=19*4096,
        recovery=recovery, layout=layout)


def capture_config(builder, image, output, pin, binary, run):
    """Independent actual-ELF observation selectors, with no admission authority."""
    image = pin(binary(image)); original = dynamic_original_image(image); data = image.read_bytes()
    def take(at, count):
        need(type(at) is int and type(count) is int and 0 <= at <= len(data) and
             0 <= count <= len(data)-at, 'bounded group observation ELF range')
        return data[at:at+count]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[1] == 2 and h[11] == 64 and 0 < h[12] <= 256,
         'actual bounded ET_EXEC group observation image')
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6]+i*64, 64)) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1 and tables[0][9] == 24 and tables[0][5] % 24 == 0 and
         tables[0][6] < len(sections), 'one complete group observation symbol table')
    table = tables[0]; strings = sections[table[6]]
    need(strings[1] == 3, 'actual group observation string table')
    names = take(strings[4], strings[5]); found = {}
    expected = {'region_app_head': (0xe00, 125), 'region_app_a_exit': (0xf0a, 0),
                'region_app_second_page': (4096, 0)}
    for at in range(table[4], table[4]+table[5], 24):
        name, info, other, section, value, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(name < len(names) and b'\0' in names[name:], 'complete actual observation symbol name')
        raw = names[name:names.index(b'\0', name)]
        for wanted in expected:
            if raw == wanted.encode():
                need(section != 0 and wanted not in found and
                     (wanted != 'region_app_head' or info & 15 == 2), 'unique actual observation symbol')
                found[wanted] = (value, size)
    need(set(found) == set(expected), 'all three group observation symbols')
    base = found['region_app_head'][0] & ~4095
    need(4096 <= base and base+8192 < 1 << 31 and
         found == {name: (base+offset, size) for name, (offset, size) in expected.items()},
         'exact actual group head, trampoline and complete second page geometry')
    programs = [struct.unpack('<IIQQQQQQ', take(h[5]+i*56, 56)) for i in range(h[10])]
    owners = [p for p in programs if p[0] == 1 and p[1] == 5 and p[5] <= p[6] and
              p[3] <= base and base-p[3]+8192 <= p[5]]
    need(len(owners) == 1 and all(p == owners[0] for p in programs if p[0] == 1 and
         p[3] < base+8192 and base < p[3]+p[6]), 'whole source pair has one nonoverlapping RX file owner')
    p = owners[0]; source = take(p[2]+base-p[3], 8192)
    need(source[0xdfe:0xe00] == b'\x66\x90' and
         source[0xf0a:0xf13] == bytes.fromhex('4987ca4d87dc41ffe3'),
         'actual predecessor and unsupported trampoline bytes')
    values = dict(HEAD=found['region_app_head'][0], EXIT=found['region_app_a_exit'][0])
    header = ('#ifndef LI2_PERSISTENT_GROUP_CAPTURE_CONFIG_H\n'
              '#define LI2_PERSISTENT_GROUP_CAPTURE_CONFIG_H\n#define LI2_PG_CAPTURE_VERSION 1\n'+
              ''.join('#define LI2_PG_'+key+'_RVA 0x%xULL\n' % value for key, value in values.items())+
              '#endif\n').encode()
    destination = output/'persistent_group_capture_config.h'
    need(not destination.exists(), 'fresh group observation configuration')
    script = pin(SELECTED/'persistent_group_capture_binding.py')
    _, out, err = run('persistent-group-capture-binding',
                     [builder.tools['python'], '-B', script, image, output], env=builder.environment)
    need(out == err == b'', 'group observation binder has no diagnostics')
    destination = pin(binary(destination))
    need(destination.read_bytes() == header, 'whole independently derived group observation header')
    return dict(version=1, original=original, symbols=values, source_pages=[base, base+4096],
                script=dict(path=str(script), **fact(script)), header=dict(path=str(destination), **fact(destination)))


def capture_extents(builder, bridge, symbols, pin, run, state):
    """Actual emitted capture sizes, independently joined to the ELF BSS symbol."""
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    expression = ('printf "LI2_PGO_EXTENTS %llu %llu %llu %llu %llu %llu\\n", '
                  '(unsigned long long)sizeof(pgo_wire), '
                  '(unsigned long long)sizeof(struct pgo_epoch), '
                  '(unsigned long long)sizeof(struct pgo_miss), '
                  '(unsigned long long)sizeof(struct pgo_slot_progress), '
                  '(unsigned long long)sizeof(struct pgo_stage), '
                  '(unsigned long long)sizeof(struct pgo_epoch_info)')
    _, out, err = run('persistent-group-capture-extents', [gdb, '-nx', '-nh', '-batch',
                     '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
                     '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
                     '-ex', 'file '+str(bridge), '-ex', expression], profile='inspect',
                     env=dict(builder.environment, MALLOC_ARENA_MAX='1'))
    match = re.fullmatch(rb'LI2_PGO_EXTENTS ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)\n', out)
    need(not err and match is not None, 'one exact actual group capture DWARF extent row')
    sizes = tuple(map(int, match.groups()))
    need(sizes == (4183424, 1444288, 322240, 3792, 46296, 15160) and sizes[0]+64 < 4*1024*1024,
         'actual whole loop-only capture fits unchanged4MiB record bound')
    rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [b'pgo_wire']]
    need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b', b'B') and
         int(rows[0][1], 16) == sizes[0], 'actual capture ELF BSS exactly equals actual DWARF wire')
    state['capture_extents'] = dict(zip(('wire', 'epoch', 'miss', 'slot_progress', 'stage', 'epoch_info'), sizes))
    state['capture_extents'].update(footer=64, stream=sizes[0]+64, record_limit=4*1024*1024)


def resident_capture_config(builder, image, output, pin, binary, run):
    """Independent actual-ELF observation selectors, with no admission authority."""
    image = pin(binary(image)); original = dynamic_original_image(image); data = image.read_bytes()
    def take(at, count):
        need(type(at) is int and type(count) is int and 0 <= at <= len(data) and
             0 <= count <= len(data)-at, 'bounded resident observation ELF range')
        return data[at:at+count]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[1] == 2 and h[11] == 64 and 0 < h[12] <= 256,
         'actual bounded ET_EXEC resident observation image')
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6]+i*64, 64)) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1 and tables[0][9] == 24 and tables[0][5] % 24 == 0 and
         tables[0][6] < len(sections), 'one complete resident observation symbol table')
    table = tables[0]; strings = sections[table[6]]
    need(strings[1] == 3, 'actual resident observation string table')
    names = take(strings[4], strings[5]); found = {}
    expected = {'region_app_head': (0xe00, 125), 'region_app_dispatch': (0xf18, 0),
                'region_app_second_page': (4096, 0)}
    for at in range(table[4], table[4]+table[5], 24):
        name, info, other, section, value, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(name < len(names) and b'\0' in names[name:], 'complete actual observation symbol name')
        raw = names[name:names.index(b'\0', name)]
        for wanted in (*expected, 'region_app_capture'):
            if raw == wanted.encode():
                need(section != 0 and wanted not in found and
                     (wanted != 'region_app_head' or info & 15 == 2), 'unique actual observation symbol')
                found[wanted] = (value, size)
    need(set(found) == set(expected) | {'region_app_capture'}, 'all four resident observation symbols')
    base = found['region_app_head'][0] & ~4095
    need(4096 <= base and base+8192 < 1 << 31 and
         all(found[name] == (base+offset, size) for name, (offset, size) in expected.items()),
         'exact actual resident head, dispatch and complete second page geometry')
    programs = [struct.unpack('<IIQQQQQQ', take(h[5]+i*56, 56)) for i in range(h[10])]
    owners = [p for p in programs if p[0] == 1 and p[1] == 5 and p[5] <= p[6] and
              p[3] <= base and base-p[3]+8192 <= p[5]]
    need(len(owners) == 1 and all(p == owners[0] for p in programs if p[0] == 1 and
         p[3] < base+8192 and base < p[3]+p[6]), 'whole source pair has one nonoverlapping RX file owner')
    p = owners[0]; source = take(p[2]+base-p[3], 8192)
    need(source[0xdfe:0xe00] == b'\x66\x90' and
         source[0xf0a:0xf1a] == bytes.fromhex('b9020000004989d24889da4c89d3ffe2'),
         'actual predecessor and resident dispatch-tail bytes')
    next_pc, next_size = found['region_app_capture']
    need(4096 <= next_pc < 1 << 31 and next_pc % 4096 == 0 and next_size == 6 and
         not base <= next_pc < base+8192, 'distinct actual next-TRACE suffix page')
    next_owner = [p for p in programs if p[0] == 1 and p[1] == 5 and p[5] <= p[6] and
                  p[3] <= next_pc and next_pc-p[3]+4096 <= p[5]]
    need(len(next_owner) == 1 and all(p == next_owner[0] for p in programs if p[0] == 1 and
         p[3] < next_pc+4096 and next_pc < p[3]+p[6]), 'one complete nonoverlapping RX suffix file page')
    p = next_owner[0]
    need(take(p[2]+next_pc-p[3], 6) == bytes.fromhex('ff2500000000'), 'actual transparent suffix JMP')
    values = dict(HEAD=found['region_app_head'][0], DISPATCH=found['region_app_dispatch'][0], NEXT=next_pc)
    header = ('#ifndef LI2_PERSISTENT_RESIDENT_CAPTURE_CONFIG_H\n'
              '#define LI2_PERSISTENT_RESIDENT_CAPTURE_CONFIG_H\n#define LI2_PR_CAPTURE_VERSION 2\n'+
              ''.join('#define LI2_PR_'+key+'_RVA 0x%xULL\n' % value for key, value in values.items())+
              '#endif\n').encode()
    destination = output/'persistent_resident_capture_config.h'
    need(not destination.exists(), 'fresh resident observation configuration')
    script = pin(SELECTED/'persistent_resident_capture_binding.py')
    _, out, err = run('persistent-resident-capture-binding',
                     [builder.tools['python'], '-B', script, image, output], env=builder.environment)
    need(out == err == b'', 'resident observation binder has no diagnostics')
    destination = pin(binary(destination))
    need(destination.read_bytes() == header, 'whole independently derived resident observation header')
    return dict(version=2, original=original, symbols=values, source_pages=[base, base+4096],
                script=dict(path=str(script), **fact(script)), header=dict(path=str(destination), **fact(destination)))

def resident_capture_extents(builder, bridge, symbols, pin, run, state):
    """Actual resident wire/epoch/next-event sizes, joined to actual ELF storage."""
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    expression = ('printf "LI2_PRO_EXTENTS %llu %llu %llu %llu %llu\\n", '
                  '(unsigned long long)sizeof(pro_wire), '
                  '(unsigned long long)sizeof(struct pro_epoch), '
                  '(unsigned long long)sizeof(struct pro_next), '
                  '(unsigned long long)sizeof(struct pro_stage), '
                  '(unsigned long long)sizeof(struct pro_epoch_info)')
    _, out, err = run('persistent-resident-capture-extents', [gdb, '-nx', '-nh', '-batch',
                     '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
                     '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
                     '-ex', 'file '+str(bridge), '-ex', expression], profile='inspect',
                     env=dict(builder.environment, MALLOC_ARENA_MAX='1'))
    match = re.fullmatch(rb'LI2_PRO_EXTENTS ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)\n', out)
    need(not err and match is not None, 'one exact actual resident capture DWARF extent row')
    sizes = tuple(map(int, match.groups()))
    need(sizes == (1719936, 1446080, 267968, 46896, 15160) and sizes[0]+64 < 4*1024*1024,
         'actual literal resident capture fits unchanged4MiB record bound')
    rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [b'pro_wire']]
    need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b', b'B') and
         int(rows[0][1], 16) == sizes[0], 'actual resident capture ELF equals actual DWARF wire')
    state['capture_extents'] = dict(zip(('wire', 'epoch', 'next', 'stage', 'epoch_info'), sizes))
    state['capture_extents'].update(footer=64, stream=sizes[0]+64, record_limit=4*1024*1024)


def build_bridge(builder, products, private, pin, binary, aliases, run, record, image, *, capture=False, dispatch=False, counters=False):
    need(type(dispatch) is bool, 'explicit typed resident release or separate capture selector')
    need(type(capture) is bool, 'explicit separate group capture selector')
    need(type(counters) is bool and not (capture and counters), 'separate release-only final-counter selector')
    need(not (dispatch and counters), 'counter and resident build selectors are mutually exclusive')
    need(builder.mov_guard is True and builder.linked_epoch is True and builder.scalar_span is True and
         builder.extra_decoder_sources == ('region.rs', 'mov_guard.rs') and
         builder.decoder_features == FEATURES and builder.record.get('decoder_features') == list(FEATURES) and
         builder.environment.get('LI2_DECODER_FEATURES') == 'linked-epoch,mov-guard',
         'one explicit persistent decoder feature/source closure')
    archive = pin(products['archive']); retained = builder.record['artifacts']['decoder.a']
    need(builder.record['status'] == 'passed' and builder.record['command_completed'] is True and
         archive == builder.paths['archive'] == builder.retained/'decoder.a' and str(archive) == retained['path'] and
         digest(fact(archive)) == digest({k: retained[k] for k in ('bytes', 'sha256')}), 'fresh retained actual persistent archive')
    need(all(type(builder.record['archive_text_exports'].get(n)) is int and
         builder.record['archive_text_exports'][n] == 1 for n in
         ('li2_decoder_region_describe', 'li2_decoder_span_describe', 'li2_decoder_link_none',
          'li2_decoder_mov_store', 'li2_decoder_tf_classify', 'li2_decoder_write_footprint')),
         'every actual descriptor/NONE provider is present exactly once')
    output = private/('persistent-group-counters' if counters else ('persistent-resident-capture' if capture else 'persistent-resident-release') if dispatch else ('persistent-group-capture' if capture else 'persistent-group-release')); output.mkdir()
    binding = binding_config(builder, archive, image, output, pin, binary, run, dispatch=dispatch, counters=counters)
    observation = (resident_capture_config if dispatch else capture_config)(builder, image, output, pin, binary, run) if capture else None
    script = pin(SELECTED/('build-persistent-group-counters.sh' if counters else ('build-persistent-resident-capture.sh' if capture else 'build-persistent-resident.sh') if dispatch else ('build-persistent-group-capture.sh' if capture else 'build-persistent-group.sh'))); rows = recipe(script, '"$cc_bin"')
    need(len(rows) == 1, 'one source-owned persistent compiler recipe')
    argv = expand(rows[0], {'$cc_bin': builder.tools['cc'], '$selected_dir': SELECTED,
                  '$parent_dir': SELECTED.parent, '$archive': archive, '$output': output})
    units = [str(SELECTED.parent/x) for x in UNITS]+[str(SELECTED/x) for x in
             ('unrolled_hash_plan.c', 'region_plan.c', 'linked_plan.c', 'persistent_group_plan.c',
              'persistent_group_compact.c', 'linked_mov_guard.c')]
    if dispatch:
        units.append(str(SELECTED/'linked_jmp_dispatch.c'))
    macros = ('PERSISTENT_GROUP', 'PERSISTENT_EPOCH', 'MOV_GUARD', 'LINKED_EPOCH', 'SCALAR_SPAN', 'SCALAR_SPAN_TRACE',
              'SPAN_FAST_BYTES', 'MAPS_CURRENT_TF', 'SCALAR_REGION', 'SCALAR_REGION_REUSE',
              'INITIAL_CODE_PROTECTION', 'UNROLLED_HASH', 'MAPS_MAINTAINED')+MACROS
    if dispatch:
        macros = ('PERSISTENT_DISPATCH',)+macros
    if capture:
        macros = ('PERSISTENT_RESIDENT_CAPTURE' if dispatch else 'PERSISTENT_GROUP_CAPTURE',)+macros
    if counters:
        macros = ('PERSISTENT_GROUP_COUNTERS',)+macros
    name = 'bridge-persistent-group-counters.so' if counters else ('bridge-persistent-resident-capture.so' if capture else 'bridge-persistent-resident.so') if dispatch else ('bridge-persistent-group-capture.so' if capture else 'bridge-persistent-group.so')
    need(argv[-2:] == ['-o', str(output/name)] and
         [x for x in argv if x.endswith(('.c', '.S'))] == units and
         [x for x in argv if x.startswith('-DLI2_')] == ['-DLI2_'+n+'=1' for n in macros] and
         all(x in argv for x in ('-O2', '-g', '-nostdlib', '-shared', '-fPIC', '-fvisibility=hidden',
             '-mgeneral-regs-only', '-fno-builtin', '-fno-tree-loop-distribute-patterns',
             '-fno-tree-vectorize', '-Wall', '-Wextra', '-Werror')),
         'exact25-TU resident no-FP release recipe' if dispatch else 'exact24-TU group-only no-FP release recipe')
    state = record['release_build'] = dict(status='failed',
              profile='persistent-group-final-counters-v1' if counters else ('persistent-resident-loop-capture-v2' if capture else 'persistent-resident-dispatch-v2') if dispatch else ('persistent-group-loop-capture-v1' if capture else 'persistent-group-two-image-v1'),
              recipe=fact(script), archive=fact(archive), argv=argv, persistent_binding=binding,
              capture=capture, qualification_credit=False)
    if dispatch:
        state['dispatch'] = dict(version=2, heads_min=1, heads_max=128, header_abi=1,
            shared_boundaries=8, code_pages=17, emitter_slot_bytes=512, emitter_boundaries=64)
    if capture:
        state['capture_config'] = observation
    headers('persistent-group-release-headers', argv, units, archive, builder, pin, aliases, run, state)
    for value in binding['sources']:
        if value['path'].endswith(('.c', '.h', '.inc')):
            need(digest(state['headers'].get(str((SELECTED/value['path']).resolve()))) ==
                 digest({k: value[k] for k in ('bytes', 'sha256')}), 'every bound C policy source is in compiler-M closure')
    for value in binding['header_paths'].values():
        need(digest(state['headers'].get(value['path'])) == digest({k: value[k] for k in ('bytes', 'sha256')}),
             'both actual generated immutable configuration headers are compiler inputs')
    required = ('maps_phase.inc', 'maps_view.inc', 'initial_code_protection.h', 'selected_unrolled_hash.inc',
                'unrolled_source.inc', 'rseq_unrolled.inc', 'region_source.inc', 'selected_scalar_region.inc',
                'selected_scalar_reuse.inc', 'tf_span_transfer.h', 'span_fetch.h', 'span_source.h',
                'rseq_span.inc', 'fetch_current_custody.h', 'fetch_current_custody.inc', 'maps_current_ticket.h')
    need(all(str((SELECTED/n).resolve()) in state['headers'] for n in required), 'whole inherited map/custody/owner source closure')
    names = {Path(n).name for n in state['headers']}
    if dispatch:
        need(str((SELECTED/'linked_jmp_dispatch.h').resolve()) in state['headers'],
             'actual resident descriptor and recovery header is a compiler input')
    required_group = ('persistent_group_plan.h', 'persistent_group_compact.h',
                      'persistent_group_lifetime.h', 'persistent_group_runtime.h',
                      'persistent_group_source.inc', 'persistent_group_rseq.inc',
                      'persistent_group_controller.inc')
    forbidden = {'persistent_plan.c', 'persistent_compact.c', 'persistent_lifetime.h',
                 'persistent_runtime.h', 'persistent_source.inc', 'persistent_rseq.inc',
                 'persistent_controller.inc', 'persistent_dynamic_controller.inc',
                 'persistent_dynamic_plan.h', 'persistent_dynamic_plan.inc',
                 'persistent_epoch_config.h', 'persistent_dynamic_capture_config.h',
                 'selected_scalar_span.inc', 'selected_scalar_span_reuse.inc', 'unrolled_hash_nested_fp.h'}
    counter_names = {'persistent_group_counters.h', 'persistent_group_counters.inc'}
    need(names.intersection(counter_names) == (counter_names if counters else set()),
         'exact counter bootstrap/header compiler closure only in explicit release diagnostic')
    observation_names = {'persistent_group_observe.h', 'persistent_group_observe.inc',
                         'persistent_group_observe_memory.h', 'persistent_group_observe_memory.inc'}
    if dispatch:
        observation_names = {n.replace('persistent_group_', 'persistent_resident_') for n in observation_names}
    if capture:
        need(all(str((SELECTED/n).resolve()) in state['headers'] for n in observation_names) and
             digest(state['headers'].get(observation['header']['path'])) ==
             digest({k: observation['header'][k] for k in ('bytes', 'sha256')}),
             'all four actual observation leaves and exact generated capture header are compiler inputs')
    need(all(str((SELECTED/n).resolve()) in state['headers'] for n in required_group) and
         not names.intersection(forbidden) and
         not any(('observe' in n and not (capture and n in observation_names)) or
                 n.startswith(('linked_preedge_', 'linked_native_hint')) for n in names),
         'exact group release source closure without an old owner, classifier, capture or wire alias')
    bridge = Path(argv[-1]); run('persistent-group-release-link', argv, profile='release_build', env=builder.environment)
    state['bridge'] = fact(binary(bridge)); state['elf'] = bridge_check(bridge)
    _, out, err = run('persistent-group-release-undefined', [builder.tools['nm'], '-u', bridge], profile='inspect', env=builder.environment)
    need(out == err == b'', 'persistent bridge has no unresolved imports')
    _, symbols, err = run('persistent-group-release-symbols', [builder.tools['nm'], '-S', '--defined-only', bridge], profile='inspect', env=builder.environment)
    need(not err, 'complete actual persistent symbol census')
    for name in PROVIDERS+(DISPATCH_PROVIDERS if dispatch else ())+(('li2_pro_trace_closed',) if dispatch and capture else ()):
        found = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [name.encode()]]
        need(len(found) == 1 and len(found[0]) == 4 and found[0][2] in (b't', b'T') and int(found[0][1], 16) > 0,
             'actual nonempty persistent proof/owner provider '+name)
    objdump = pin(shutil.which('objdump', path=ENV['PATH']))
    _, out, err = run('persistent-group-objdump-version', [objdump, '--version'], env=builder.environment)
    need(out and not err, 'actual objdump tool identity')
    _, assembly, err = run('persistent-group-release-memset', [objdump, '-d', '-w', '-M', 'att', '--disassemble=memset', bridge], profile='inspect', env=builder.environment)
    need(not err, 'actual reset disassembly')
    state['reset'] = hidden_memset(bridge, body_check(bridge, symbols, assembly, 'fast', symbol_name='memset'))
    protected_extents(builder, bridge, symbols, pin, run, state)
    if counters:
        for wanted, extent in ((b'pgc_bootstrap', 752), (b'li2_pgc_current', 8)):
            rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [wanted]]
            need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b', b'B', b'd', b'D') and
                 int(rows[0][1], 16) == extent, 'actual final-counter storage/type extent')
        state['counter_schema'] = dict(version=2, bytes=752, page=4096, initial_seals=6, final_seals=23)
        state['counters'] = True
    if capture:
        (resident_capture_extents if dispatch else capture_extents)(builder, bridge, symbols, pin, run, state)
    fast_bytes(builder, output, pin, binary, aliases, run, state)
    need(digest(fact(archive)) == digest(binding['archive']) and fact(image) == binding['original']['image'] and
         all(fact(SELECTED/v['path']) == {k: v[k] for k in ('bytes', 'sha256')} for v in binding['sources']) and
         all(fact(v['path']) == {k: v[k] for k in ('bytes', 'sha256')} for v in binding['header_paths'].values()) and
         fact(binding['manifest']['path']) == {k: binding['manifest'][k] for k in ('bytes', 'sha256')},
         'archive, original image, full policy and configuration unchanged through build and byte oracle')
    if capture:
        need(all(fact(observation[key]['path']) == {k: observation[key][k] for k in ('bytes', 'sha256')}
                 for key in ('script', 'header')) and
             all(fact(path) == value for path, value in state['headers'].items()) and fact(script) == state['recipe'],
             'actual capture source, selectors and complete compiler input closure unchanged through byte oracle')
    state['status'] = 'passed'
    return bridge
