#!/usr/bin/env python3
"""Actual archive/image/build closure for one registered persistent primitive.

This helper has no capture or qualification mode. Its caller owns unchanged
source/process bounds, input/artifact rehashing, and the generic Build finalizer.
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

FEATURES = ('scalar-region', 'scalar-span', 'linked-epoch', 'mov-guard')
POLICY_INPUTS = ('decoder/Cargo.toml', 'decoder/src/lib.rs', 'decoder/src/region.rs', 'decoder/src/mov_guard.rs', 'decoder/src/tf.rs', 'decoder/src/write_footprint.rs', 'region_decode.h', 'linked_plan.h', 'linked_plan.c', 'linked_source.h', 'linked_source.inc', 'linked_rseq.h', 'linked_rseq.inc', 'linked_proof.h', 'linked_proof.inc', 'linked_controller.inc', 'linked_reuse.inc', 'lifecycle_loader.c', 'span_source.inc', 'rseq_guard.c', 'rseq_region.inc', 'runtime_loader.c', 'selected_globals.inc', 'selected_chain.inc', 'native_lifecycle.inc', 'native_pair_lifecycle.inc', 'tf_span_transfer.inc', 'span_fetch.inc', 'span_fast_bytes.h', 'persistent_plan.h', 'persistent_plan.c', 'persistent_compact.h', 'persistent_compact.c', 'persistent_lifetime.h', 'persistent_runtime.h', 'persistent_source.inc', 'persistent_rseq.inc', 'persistent_controller.inc', 'linked_mov_guard.h', 'linked_mov_guard.c', '../bridge.c', 'build-persistent-epoch.sh', 'persistent_epoch_binding.py')
PROVIDERS = ('li2_decoder_link_none', 'li2_link_plan_page', 'li2_link_plan_validate',
             'li2_decoder_mov_store', 'li2_pe_plan_pages', 'li2_pe_plan_validate',
             'li2_pe_compact_build', 'li2_pe_compact_validate', 'li2_pe_compact_guard',
             'li2_pe_compact_recover', 'li2_mg_emit', 'li2_mg_recover',
             'li2_pe_owner_phase', 'li2_pe_source_prepare', 'li2_pe_source_release',
             'li2_pe_rseq_begin', 'li2_pe_rseq_close')


def original_image(path):
    """Derive only the immutable configuration; the app reader owns semantics."""
    data = path.read_bytes()
    def take(at, n):
        need(type(at) is int and type(n) is int and 0 <= at <= len(data) and
             0 <= n <= len(data) - at, 'bounded persistent image range')
        return data[at:at+n]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (2, 62, 1) and
         h[8:10] == (64, 56) and 0 < h[10] <= 32 and h[11] == 64 and 0 < h[12] <= 256,
         'bounded actual original ET_EXEC image')
    loads = [struct.unpack('<IIQQQQQQ', take(h[5] + i*56, 56)) for i in range(h[10])]
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6] + i*64, 64)) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1, 'one complete actual symbol table')
    t = tables[0]
    need(t[9] == 24 and t[5] % 24 == 0 and t[6] < len(sections), 'whole symbol table extents')
    table = sections[t[6]]
    need(table[1] == 3, 'symbol string table type')
    names = take(table[4], table[5]); symbols = {}
    wanted = {b'region_app_head', b'region_app_second_page'}
    for at in range(t[4], t[4]+t[5], 24):
        n, info, other, section, pc, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(n < len(names) and b'\0' in names[n:], 'whole actual symbol name')
        name = names[n:names.index(b'\0', n)]
        if name in wanted:
            need(section and name not in symbols, 'unique defined persistent source symbol')
            symbols[name] = (pc, size)
    need(set(symbols) == wanted, 'complete persistent source symbol pair')
    head, size = symbols[b'region_app_head']; second = symbols[b'region_app_second_page'][0]
    first = head & ~4095
    need(4096 <= first and head == first+0x200 and 15 <= size <= 4096-0x200 and
         second == first+4096 and second+4096 < 1 << 31, 'actual adjacent low source pages')
    owner = [s for s in loads if s[0] == 1 and s[1] == 5 and s[5] <= s[6] and
             s[3] <= first and first-s[3]+8192 <= s[5]]
    need(len(owner) == 1 and all(s == owner[0] for s in loads if s[0] == 1 and
         s[3] < second+4096 and first < s[3]+s[6]), 'complete source has one RX file owner and no overlapping load')
    segment = owner[0]; source = take(segment[2]+first-segment[3], 8192)
    need(source[0x1fe:0x200] == b'\x66\x90', 'actual genuine TRACE predecessor bytes')
    return dict(image=fact(path), head_rva=head, second_page_rva=second,
                source_pages=[first, second], source=dict(bytes=8192, sha256=H(source)))


def binding_config(builder, archive, image, output, pin, binary, run):
    image = pin(binary(image)); original = original_image(image); values = []
    for name in POLICY_INPUTS:
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
    persistent = ('#ifndef LI2_PERSISTENT_EPOCH_CONFIG_H\n#define LI2_PERSISTENT_EPOCH_CONFIG_H\n'
                  '#define LI2_PE_BINDING_VERSION 1\n'
                  '#define LI2_PE_ARCHIVE_SHA256 '+literal(archive_fact['sha256'])+'\n'
                  '#define LI2_PE_POLICY_SHA256 '+literal(policy)+'\n'
                  '#define LI2_PE_APP_HEAD_RVA 0x%xULL\n' % original['head_rva']+
                  '#define LI2_PE_APP_SECOND_PAGE_RVA 0x%xULL\n' % original['second_page_rva']+'#endif\n').encode()
    expected = {'linked_epoch_config.h': linked, 'persistent_epoch_config.h': persistent}
    manifest = output/'persistent_epoch_binding.json'
    need(not manifest.exists() and not any((output/n).exists() for n in expected), 'fresh binding outputs')
    _, out, err = run('persistent-policy-binding', [builder.tools['python'], '-B',
                     SELECTED/'persistent_epoch_binding.py', SELECTED, archive, image, output], env=builder.environment)
    need(out == err == b'', 'source-owned persistent binder has no diagnostics')
    header_facts = {}
    for name, data in expected.items():
        path = pin(binary(output/name))
        need(path.read_bytes() == data, 'whole independent archive/policy/image header')
        header_facts[name] = dict(path=str(path), **fact(path))
    record = dict(version=1, profile='persistent-registered-two-page-v1', archive=archive_fact,
                  policy_sha256=policy, original=original, sources=values,
                  headers={name: dict(bytes=len(data), sha256=H(data)) for name, data in expected.items()})
    manifest = pin(binary(manifest))
    need(manifest.read_bytes() == (json.dumps(record, sort_keys=True)+'\n').encode(), 'complete typed persistent binding manifest')
    return dict(**record, header_paths=header_facts, manifest=dict(path=str(manifest), **fact(manifest)))


def protected_extents(builder, bridge, symbols, pin, run, state):
    """Inspect compiler-derived storage sizes without executing the bridge."""
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    _, out, err = run('persistent-gdb-version', [gdb, '--version'], profile='inspect', env=builder.environment)
    need(out and not err, 'actual GDB tool identity')
    expression = ('printf "LI2_PE_EXTENTS %llu %llu %llu %llu %llu\\n", '
                  '(unsigned long long)sizeof(struct pe_payload), (unsigned long long)sizeof(pe), '
                  '(unsigned long long)sizeof(struct li2_pe_compact), '
                  '(unsigned long long)sizeof(((struct li2_pe_compact*)0)->image), '
                  '(unsigned long long)sizeof(struct li2_mg_plan)')
    _, out, err = run('persistent-protected-extents', [gdb, '-nx', '-nh', '-batch',
                     '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
                     '-ex', 'file '+str(bridge), '-ex', expression], profile='inspect', env=builder.environment)
    match = re.fullmatch(rb'LI2_PE_EXTENTS ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)\n', out)
    need(not err and match is not None, 'one actual DWARF storage-size result')
    payload, owner, compact, code, recovery = map(int, match.groups())
    rounded = (payload+4095) & ~4095
    need(compact == 182168 and code == 32768 and recovery == 6488 and
         compact < payload <= rounded <= 64*4096 and owner > payload, 'actual bounded persistent primary and reconstruction storage')
    rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [b'pe']]
    need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b', b'B') and
         int(rows[0][1], 16) == owner, 'actual ELF owner storage equals DWARF extent')
    state['protected_extents'] = dict(payload=payload, proof_rounded=rounded, owner=owner,
                                     compact=compact, code=code, spill=4096, recovery=recovery)


def build_bridge(builder, products, private, pin, binary, aliases, run, record, image):
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
    output = private/'persistent-release'; output.mkdir()
    binding = binding_config(builder, archive, image, output, pin, binary, run)
    script = pin(SELECTED/'build-persistent-epoch.sh'); rows = recipe(script, '"$cc_bin"')
    need(len(rows) == 1, 'one source-owned persistent compiler recipe')
    argv = expand(rows[0], {'$cc_bin': builder.tools['cc'], '$selected_dir': SELECTED,
                  '$parent_dir': SELECTED.parent, '$archive': archive, '$output': output})
    units = [str(SELECTED.parent/x) for x in UNITS]+[str(SELECTED/x) for x in
             ('unrolled_hash_plan.c', 'region_plan.c', 'linked_plan.c', 'persistent_plan.c',
              'persistent_compact.c', 'linked_mov_guard.c')]
    macros = ('PERSISTENT_EPOCH', 'MOV_GUARD', 'LINKED_EPOCH', 'SCALAR_SPAN', 'SCALAR_SPAN_TRACE',
              'SPAN_FAST_BYTES', 'MAPS_CURRENT_TF', 'SCALAR_REGION', 'SCALAR_REGION_REUSE',
              'INITIAL_CODE_PROTECTION', 'UNROLLED_HASH', 'MAPS_MAINTAINED')+MACROS
    need(argv[-2:] == ['-o', str(output/'bridge-persistent-epoch.so')] and
         [x for x in argv if x.endswith(('.c', '.S'))] == units and
         [x for x in argv if x.startswith('-DLI2_')] == ['-DLI2_'+n+'=1' for n in macros] and
         all(x in argv for x in ('-O2', '-g', '-nostdlib', '-shared', '-fPIC', '-fvisibility=hidden',
             '-mgeneral-regs-only', '-fno-builtin', '-fno-tree-loop-distribute-patterns',
             '-fno-tree-vectorize', '-Wall', '-Wextra', '-Werror')), 'exact24-TU persistent-only no-FP release recipe')
    state = record['release_build'] = dict(status='failed', profile='persistent-registered-two-page-v1',
              recipe=fact(script), archive=fact(archive), argv=argv, persistent_binding=binding,
              capture=False, qualification_credit=False)
    headers('persistent-release-headers', argv, units, archive, builder, pin, aliases, run, state)
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
    need(not any('observe' in Path(n).name or Path(n).name.startswith(('linked_preedge_', 'linked_native_hint'))
                 or Path(n).name in ('selected_scalar_span.inc', 'selected_scalar_span_reuse.inc', 'unrolled_hash_nested_fp.h')
                 for n in state['headers']), 'persistent primitive has no preedge, hint, observer or legacy capture closure')
    bridge = Path(argv[-1]); run('persistent-release-link', argv, profile='release_build', env=builder.environment)
    state['bridge'] = fact(binary(bridge)); state['elf'] = bridge_check(bridge)
    _, out, err = run('persistent-release-undefined', [builder.tools['nm'], '-u', bridge], profile='inspect', env=builder.environment)
    need(out == err == b'', 'persistent bridge has no unresolved imports')
    _, symbols, err = run('persistent-release-symbols', [builder.tools['nm'], '-S', '--defined-only', bridge], profile='inspect', env=builder.environment)
    need(not err, 'complete actual persistent symbol census')
    for name in PROVIDERS:
        found = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [name.encode()]]
        need(len(found) == 1 and len(found[0]) == 4 and found[0][2] in (b't', b'T') and int(found[0][1], 16) > 0,
             'actual nonempty persistent proof/owner provider '+name)
    objdump = pin(shutil.which('objdump', path=ENV['PATH']))
    _, out, err = run('persistent-objdump-version', [objdump, '--version'], env=builder.environment)
    need(out and not err, 'actual objdump tool identity')
    _, assembly, err = run('persistent-release-memset', [objdump, '-d', '-w', '-M', 'att', '--disassemble=memset', bridge], profile='inspect', env=builder.environment)
    need(not err, 'actual reset disassembly')
    state['reset'] = hidden_memset(bridge, body_check(bridge, symbols, assembly, 'fast', symbol_name='memset'))
    protected_extents(builder, bridge, symbols, pin, run, state)
    fast_bytes(builder, output, pin, binary, aliases, run, state)
    need(digest(fact(archive)) == digest(binding['archive']) and fact(image) == binding['original']['image'] and
         all(fact(SELECTED/v['path']) == {k: v[k] for k in ('bytes', 'sha256')} for v in binding['sources']) and
         all(fact(v['path']) == {k: v[k] for k in ('bytes', 'sha256')} for v in binding['header_paths'].values()) and
         fact(binding['manifest']['path']) == {k: binding['manifest'][k] for k in ('bytes', 'sha256')},
         'archive, original image, full policy and configuration unchanged through build and byte oracle')
    state['status'] = 'passed'
    return bridge
