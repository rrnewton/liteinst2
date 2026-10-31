#!/usr/bin/env python3
"""Shared active domain and maintained-rseq builds; old profiles stay exact."""
import json
from pathlib import Path
import re
import shutil
import struct
from maps_view import (need, fact, SELECTED, UNITS, MACROS, recipe, expand, headers,
                       bridge_check, ENV, hidden_memset, body_check, digest, H)
from linked_epoch_build import FIXED_DOMAIN, fixed_domain_source
from scalar_span_trace_build import fast_bytes
from persistent_epoch_build import FEATURES, dynamic_original_image
from persistent_group_build import DISPATCH_POLICY_INPUTS, PROVIDERS, DISPATCH_PROVIDERS
POLICY_INPUTS = tuple({'build-persistent-resident.sh':'build-persistent-active-domain.sh',
    'persistent_resident_binding.py':'persistent_active_domain_binding.py'}.get(n,n)
    for n in DISPATCH_POLICY_INPUTS)+('persistent_retained_two.inc','linked_jmp_domain.h','linked_jmp_domain_emit.inc',
    'persistent_active_domain.h','persistent_active_domain_types.inc','persistent_active_domain.inc',
    'rseq_current_data.h','rseq_current_data.inc','linked_native_probe.h','linked_native_probe.inc','linked_native_probe_report.inc','maps_parse_memo.inc')


# The active owner drains through the domain wrapper; the linked image keeps
# the singleton release body only as an internal compiler clone.
# Preserve every other donor provider and require the shared-domain seams.
ACTIVE_PROVIDERS = tuple('li2_pgd_source_release' if name == 'li2_pg_source_release' else name
                         for name in PROVIDERS) + DISPATCH_PROVIDERS + (
    'li2_pgd_owner_view', 'li2_pgd_source_bind', 'li2_pgd_source_opened',
    'li2_pgd_source_pair_equal', 'li2_pgd_source_progress', 'li2_pgd_source_terminal',
    'li2_pgd_rseq_bind', 'li2_lifecycle_rseq_data_current',
    'li2_lifecycle_link_native_probe_choose', 'li2_lifecycle_link_native_probe_refault',
    'li2_lifecycle_link_native_probe_outcome',
    'li2_lifecycle_link_native_probe_progress',
)

def binding_config(builder, archive, image, output, pin, binary, run, *, mode):
    need(mode in ('release','capture','differential','counters'), 'explicit domain mode')
    image = pin(binary(image))
    original = dynamic_original_image(image)
    values = []
    policy_inputs=POLICY_INPUTS
    if mode!='release':policy_inputs+=('build-persistent-active-domain-'+mode+'.sh',)
    if mode=='counters':policy_inputs+=('persistent_group_counters.h','persistent_group_counters.inc')
    for name in policy_inputs:
        path = pin(SELECTED / name)
        value = fact(path)
        if name in FIXED_DOMAIN:
            size, sha = fixed_domain_source(name,path)
            need(digest(value) == digest(dict(bytes=size, sha256=sha)), 'unchanged reviewed scalar/NONE decoder domain')
        if name.endswith('.rs'):
            need(digest(builder.record['dep_info'].get('tools/page-entry/selected/' + name)) == digest(value), 'actual archive compiled each bound decoder source')
        values.append(dict(path=name, **value))
    archive = pin(archive)
    archive_fact = fact(archive)
    policy = digest(dict(sources=values, original=original, mode=mode))
    literal = lambda sha: '{' + ','.join(('0x' + sha[i:i + 2] for i in range(0, 64, 2))) + '}'
    linked = ('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINK_BINDING_VERSION 1\n#define LI2_LINK_ARCHIVE_SHA256 ' + literal(archive_fact['sha256']) + '\n#define LI2_LINK_POLICY_SHA256 ' + literal(policy) + '\n#endif\n').encode()
    persistent = ('#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION ' + '4' + '\n#define LI2_PG_ARCHIVE_SHA256 ' + literal(archive_fact['sha256']) + '\n#define LI2_PG_POLICY_SHA256 ' + literal(policy) + '\n#endif\n').encode()
    expected = {'linked_epoch_config.h': linked, 'persistent_group_config.h': persistent}
    manifest = output / 'persistent_active_domain_binding.json'
    need(not manifest.exists() and (not any(((output / n).exists() for n in expected))), 'fresh binding outputs')
    _, out, err = run('persistent-group-policy-binding', [builder.tools['python'], '-B', SELECTED / 'persistent_active_domain_binding.py', SELECTED, archive, image, output, mode], env=builder.environment)
    need(out == err == b'', 'source-owned persistent binder has no diagnostics')
    header_facts = {}
    for name, data in expected.items():
        path = pin(binary(output / name))
        need(path.read_bytes() == data, 'whole independent archive/policy/image header')
        header_facts[name] = dict(path=str(path), **fact(path))
    record = dict(version=4, profile='persistent-active-domain-'+mode+'-v4', mode=mode, native_probe=True, parse_memo=True, archive=archive_fact, policy_sha256=policy, original=original, sources=values, headers={name: dict(bytes=len(data), sha256=H(data)) for name, data in expected.items()})
    manifest = pin(binary(manifest))
    need(manifest.read_bytes() == (json.dumps(record, sort_keys=True) + '\n').encode(), 'complete typed persistent binding manifest')
    return dict(**record, header_paths=header_facts, manifest=dict(path=str(manifest), **fact(manifest)))


def build_bridge(builder, products, private, pin, binary, aliases, run, record, image, *, capture=False, retained_counters=False, differential=False):
    need(type(capture) is bool and type(differential) is bool and (not differential or capture),
         'differential validation is an explicit capture mode')
    mode='counters' if retained_counters else 'differential' if differential else 'capture' if capture else 'release'
    need(type(retained_counters) is bool and not (capture and retained_counters),
         'explicit active-domain counters require release without capture')
    need(builder.mov_guard is True and builder.linked_epoch is True and (builder.scalar_span is True) and (builder.extra_decoder_sources == ('region.rs', 'mov_guard.rs')) and (builder.decoder_features == FEATURES) and (builder.record.get('decoder_features') == list(FEATURES)) and (builder.environment.get('LI2_DECODER_FEATURES') == 'linked-epoch,mov-guard'), 'one explicit persistent decoder feature/source closure')
    archive = pin(products['archive'])
    retained = builder.record['artifacts']['decoder.a']
    need(builder.record['status'] == 'passed' and builder.record['command_completed'] is True and (archive == builder.paths['archive'] == builder.retained / 'decoder.a') and (str(archive) == retained['path']) and (digest(fact(archive)) == digest({k: retained[k] for k in ('bytes', 'sha256')})), 'fresh retained actual persistent archive')
    need(all((type(builder.record['archive_text_exports'].get(n)) is int and builder.record['archive_text_exports'][n] == 1 for n in ('li2_decoder_region_describe', 'li2_decoder_span_describe', 'li2_decoder_link_none', 'li2_decoder_mov_store', 'li2_decoder_tf_classify', 'li2_decoder_write_footprint'))), 'every actual descriptor/NONE provider is present exactly once')
    output = private / ('persistent-active-domain-'+mode)
    output.mkdir()
    binding = binding_config(builder, archive, image, output, pin, binary, run, mode=mode)
    observation = capture_config(builder, image, output, pin, binary, run) if capture else None
    script = pin(SELECTED / ('build-persistent-active-domain'+('' if mode=='release' else '-'+mode)+'.sh'))
    rows = recipe(script, '"$cc_bin"')
    need(len(rows) == 1, 'one source-owned persistent compiler recipe')
    argv = expand(rows[0], {'$cc_bin': builder.tools['cc'], '$selected_dir': SELECTED, '$parent_dir': SELECTED.parent, '$archive': archive, '$output': output})
    units = [str(SELECTED.parent / x) for x in UNITS] + [str(SELECTED / x) for x in ('unrolled_hash_plan.c', 'region_plan.c', 'linked_plan.c', 'persistent_group_plan.c', 'persistent_group_compact.c', 'linked_mov_guard.c')]
    units.append(str(SELECTED / 'linked_jmp_dispatch.c'))
    macros = ('PERSISTENT_GROUP', 'PERSISTENT_EPOCH', 'MOV_GUARD', 'LINKED_EPOCH', 'SCALAR_SPAN', 'SCALAR_SPAN_TRACE', 'SPAN_FAST_BYTES', 'MAPS_CURRENT_TF', 'SCALAR_REGION', 'SCALAR_REGION_REUSE', 'INITIAL_CODE_PROTECTION', 'UNROLLED_HASH', 'MAPS_MAINTAINED') + MACROS
    macros = ('MAPS_PARSE_MEMO','LINKED_NATIVE_PROBE','PERSISTENT_ACTIVE_DOMAIN','RSEQ_CURRENT_DATA','PERSISTENT_RETAINED_TWO','PERSISTENT_DISPATCH') + macros
    if capture:
        macros = ('PERSISTENT_ACTIVE_DOMAIN_CAPTURE',) + macros
    if differential:
        macros = ('MAPS_DIFFERENTIAL',) + macros
    if retained_counters:
        macros = ('PERSISTENT_RETAINED_TWO_COUNTERS', 'PERSISTENT_GROUP_COUNTERS') + macros
    name='bridge-persistent-active-domain'+('' if mode=='release' else '-'+mode)+'.so'
    need(argv[-2:] == ['-o', str(output / name)] and [x for x in argv if x.endswith(('.c', '.S'))] == units and ([x for x in argv if x.startswith('-DLI2_')] == ['-DLI2_' + n + '=1' for n in macros]) and all((x in argv for x in ('-O2', '-g', '-nostdlib', '-shared', '-fPIC', '-fvisibility=hidden', '-mgeneral-regs-only', '-fno-builtin', '-fno-tree-loop-distribute-patterns', '-fno-tree-vectorize', '-Wall', '-Wextra', '-Werror'))), 'exact25-TU resident no-FP release recipe')
    state = record['release_build'] = dict(status='failed', profile='persistent-active-domain-'+mode+'-v4', recipe=fact(script), archive=fact(archive), argv=argv, persistent_binding=binding, capture=capture, qualification_credit=False)
    state['active_domain'] = dict(version=4, slots=2, same_source_pair=True, joint_receipts=3, directory_heads=256,
        maintained_rseq=True,differential=differential,native_probe=True,parse_memo=True,immutable_reconstruction='two-shared-certificates' if capture else None)
    state['dispatch'] = dict(version=3, heads_min=1, heads_max=128, header_abi=1, shared_boundaries=8, code_pages=17, emitter_slot_bytes=512, emitter_boundaries=64)
    if capture:
        state['capture_config'] = observation
    headers('persistent-group-release-headers', argv, units, archive, builder, pin, aliases, run, state)
    for value in binding['sources']:
        if value['path'].endswith(('.c', '.h', '.inc')):
            need(digest(state['headers'].get(str((SELECTED / value['path']).resolve()))) == digest({k: value[k] for k in ('bytes', 'sha256')}), 'every bound C policy source is in compiler-M closure')
    for value in binding['header_paths'].values():
        need(digest(state['headers'].get(value['path'])) == digest({k: value[k] for k in ('bytes', 'sha256')}), 'both actual generated immutable configuration headers are compiler inputs')
    required = ('maps_phase.inc', 'maps_view.inc', 'initial_code_protection.h', 'selected_unrolled_hash.inc', 'unrolled_source.inc', 'rseq_unrolled.inc', 'region_source.inc', 'selected_scalar_region.inc', 'selected_scalar_reuse.inc', 'tf_span_transfer.h', 'span_fetch.h', 'span_source.h', 'rseq_span.inc', 'fetch_current_custody.h', 'fetch_current_custody.inc', 'maps_current_ticket.h')
    need(all((str((SELECTED / n).resolve()) in state['headers'] for n in required)), 'whole inherited map/custody/owner source closure')
    names = {Path(n).name for n in state['headers']}
    need(str((SELECTED / 'linked_jmp_dispatch.h').resolve()) in state['headers'], 'actual resident descriptor and recovery header is a compiler input')
    required_group = ('persistent_group_plan.h', 'persistent_group_compact.h', 'persistent_group_lifetime.h', 'persistent_group_runtime.h', 'persistent_group_source.inc', 'persistent_group_rseq.inc', 'persistent_group_controller.inc','persistent_retained_two.inc','persistent_active_domain.inc',
        'persistent_active_domain.h','persistent_active_domain_types.inc','linked_jmp_domain.h','linked_jmp_domain_emit.inc',
        'rseq_current_data.h','rseq_current_data.inc','linked_native_probe.h','linked_native_probe.inc','linked_native_probe_report.inc','maps_parse_memo.inc')
    forbidden = {'persistent_plan.c', 'persistent_compact.c', 'persistent_lifetime.h', 'persistent_runtime.h', 'persistent_source.inc', 'persistent_rseq.inc', 'persistent_controller.inc', 'persistent_dynamic_controller.inc', 'persistent_dynamic_plan.h', 'persistent_dynamic_plan.inc', 'persistent_epoch_config.h', 'persistent_dynamic_capture_config.h', 'selected_scalar_span.inc', 'selected_scalar_span_reuse.inc', 'unrolled_hash_nested_fp.h'}
    counter_names = {'persistent_group_counters.h', 'persistent_group_counters.inc'}
    need(names.intersection(counter_names) == (counter_names if retained_counters else set()), 'exact counter bootstrap/header compiler closure only in explicit release diagnostic')
    observation_names = {'persistent_group_observe.h', 'persistent_group_observe.inc', 'persistent_group_observe_memory.h', 'persistent_group_observe_memory.inc'}
    observation_names = {n.replace('persistent_group_', 'persistent_active_domain_') for n in observation_names}
    if capture:
        need(all((str((SELECTED / n).resolve()) in state['headers'] for n in observation_names)) and digest(state['headers'].get(observation['header']['path'])) == digest({k: observation['header'][k] for k in ('bytes', 'sha256')}), 'all four actual observation leaves and exact generated capture header are compiler inputs')
    need(all((str((SELECTED / n).resolve()) in state['headers'] for n in required_group)) and (not names.intersection(forbidden)) and (not any(('observe' in n and (not (capture and n in observation_names)) or n.startswith(('linked_preedge_', 'linked_native_hint')) for n in names))), 'exact group release source closure without an old owner, classifier, capture or wire alias')
    bridge = Path(argv[-1])
    run('persistent-group-release-link', argv, profile='release_build', env=builder.environment)
    state['bridge'] = fact(binary(bridge))
    state['elf'] = bridge_check(bridge)
    _, out, err = run('persistent-group-release-undefined', [builder.tools['nm'], '-u', bridge], profile='inspect', env=builder.environment)
    need(out == err == b'', 'persistent bridge has no unresolved imports')
    _, symbols, err = run('persistent-group-release-symbols', [builder.tools['nm'], '-S', '--defined-only', bridge], profile='inspect', env=builder.environment)
    need(not err, 'complete actual persistent symbol census')
    for name in ACTIVE_PROVIDERS + (('li2_pdao_trace_closed',) if capture else ()):
        found = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [name.encode()]]
        need(len(found) == 1 and len(found[0]) == 4 and (found[0][2] in (b't', b'T')) and (int(found[0][1], 16) > 0), 'actual nonempty persistent proof/owner provider ' + name)
    memo = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [b'maps_parse_memo']]
    need(len(memo) == 1 and len(memo[0]) == 4 and memo[0][2] in (b'b', b'B') and
         int(memo[0][0], 16) > 0 and int(memo[0][1], 16) == 376856,
         'actual complete parser-memo BSS storage in the protected bridge image')
    state['parse_memo_storage'] = dict(symbol='maps_parse_memo', bytes=376856, address=int(memo[0][0], 16))
    objdump = pin(shutil.which('objdump', path=ENV['PATH']))
    _, out, err = run('persistent-group-objdump-version', [objdump, '--version'], env=builder.environment)
    need(out and (not err), 'actual objdump tool identity')
    _, assembly, err = run('persistent-group-release-memset', [objdump, '-d', '-w', '-M', 'att', '--disassemble=memset', bridge], profile='inspect', env=builder.environment)
    need(not err, 'actual reset disassembly')
    state['reset'] = hidden_memset(bridge, body_check(bridge, symbols, assembly, 'fast', symbol_name='memset'))
    domain_protected_extents(builder, bridge, symbols, pin, run, state)
    retained_extents(builder, bridge, symbols, pin, run, state)
    if retained_counters:
        for wanted, extent in ((b'pgc_bootstrap', 752), (b'li2_pgc_current', 8)):
            rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [wanted]]
            need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b', b'B', b'd', b'D') and
                 int(rows[0][1], 16) == extent, 'actual final-counter storage/type extent')
        state['counter_schema'] = dict(version=2, bytes=752, page=4096, initial_seals=6, final_seals=23)
        state['counters'] = True
        state['retained_counters'] = True
    if capture:
        capture_extents(builder, bridge, symbols, pin, run, state)
    fast_bytes(builder, output, pin, binary, aliases, run, state)
    need(digest(fact(archive)) == digest(binding['archive']) and fact(image) == binding['original']['image'] and all((fact(SELECTED / v['path']) == {k: v[k] for k in ('bytes', 'sha256')} for v in binding['sources'])) and all((fact(v['path']) == {k: v[k] for k in ('bytes', 'sha256')} for v in binding['header_paths'].values())) and (fact(binding['manifest']['path']) == {k: binding['manifest'][k] for k in ('bytes', 'sha256')}), 'archive, original image, full policy and configuration unchanged through build and byte oracle')
    if capture:
        need(all((fact(observation[key]['path']) == {k: observation[key][k] for k in ('bytes', 'sha256')} for key in ('script', 'header'))) and all((fact(path) == value for path, value in state['headers'].items())) and (fact(script) == state['recipe']), 'actual capture source, selectors and complete compiler input closure unchanged through byte oracle')
    state['status'] = 'passed'
    return bridge


def capture_config(builder, image, output, pin, binary, run):
    """Independent actual-ELF observation selectors, with no admission authority."""
    image = pin(binary(image)); original = dynamic_original_image(image); data = image.read_bytes()
    def take(at, count):
        need(type(at) is int and type(count) is int and 0 <= at <= len(data) and
             0 <= count <= len(data)-at, 'bounded active_domain observation ELF range')
        return data[at:at+count]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[1] == 2 and h[11] == 64 and 0 < h[12] <= 256,
         'actual bounded ET_EXEC active_domain observation image')
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6]+i*64, 64)) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1 and tables[0][9] == 24 and tables[0][5] % 24 == 0 and
         tables[0][6] < len(sections), 'one complete active_domain observation symbol table')
    table = tables[0]; strings = sections[table[6]]
    need(strings[1] == 3, 'actual active_domain observation string table')
    names = take(strings[4], strings[5]); found = {}
    expected = {'region_app_head':(0x200,6),'region_app_block_b':(0x400,15),
                'region_app_second_page':(4096,0)}
    for at in range(table[4], table[4]+table[5], 24):
        name, info, other, section, value, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(name < len(names) and b'\0' in names[name:], 'complete actual observation symbol name')
        raw = names[name:names.index(b'\0', name)]
        for wanted in (*expected, 'region_app_capture'):
            if raw == wanted.encode():
                need(section != 0 and wanted not in found and
                     (wanted != 'region_app_head' or info & 15 == 2), 'unique actual observation symbol')
                found[wanted] = (value, size)
    need(set(found) == set(expected) | {'region_app_capture'}, 'all four active-domain observation symbols')
    base = found['region_app_head'][0] & ~4095
    need(4096 <= base and base+8192 < 1 << 31 and
         all(found[name] == (base+offset, size) for name, (offset, size) in expected.items()),
         'exact actual active_domain exact roots, misses and complete second page geometry')
    programs = [struct.unpack('<IIQQQQQQ', take(h[5]+i*56, 56)) for i in range(h[10])]
    owners = [p for p in programs if p[0] == 1 and p[1] == 5 and p[5] <= p[6] and
              p[3] <= base and base-p[3]+8192 <= p[5]]
    need(len(owners) == 1 and all(p == owners[0] for p in programs if p[0] == 1 and
         p[3] < base+8192 and base < p[3]+p[6]), 'whole source pair has one nonoverlapping RX file owner')
    p = owners[0]; source = take(p[2]+base-p[3], 8192)
    expected_source = bytearray(b'\xcc'*8192)
    expected_source[0x1fe:0x200] = b'\x66\x90'
    expected_source[0x200:0x206]=bytes.fromhex('4883c001ffe2')
    expected_source[0x400:0x40f]=bytes.fromhex('4883c0024883e90175034889f3ffe3')
    need(source == bytes(expected_source), 'whole actual active A/B instructions and padding')
    next_pc, next_size = found['region_app_capture']
    need(4096 <= next_pc < 1 << 31 and next_pc % 4096 == 0 and next_size == 6 and
         not base <= next_pc < base+8192, 'distinct actual next-TRACE suffix page')
    next_owner = [p for p in programs if p[0] == 1 and p[1] == 5 and p[5] <= p[6] and
                  p[3] <= next_pc and next_pc-p[3]+4096 <= p[5]]
    need(len(next_owner) == 1 and all(p == next_owner[0] for p in programs if p[0] == 1 and
         p[3] < next_pc+4096 and next_pc < p[3]+p[6]), 'one complete nonoverlapping RX suffix file page')
    p = next_owner[0]
    need(take(p[2]+next_pc-p[3], 6) == bytes.fromhex('ff2500000000'), 'actual transparent suffix JMP')
    values = dict(A=found['region_app_head'][0],B=found['region_app_block_b'][0],NEXT=next_pc)
    header = ('#ifndef LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE_CONFIG_H\n'
              '#define LI2_PERSISTENT_ACTIVE_DOMAIN_CAPTURE_CONFIG_H\n#define LI2_PDA_CAPTURE_VERSION 4\n'+
              ''.join('#define LI2_PDA_'+key+'_RVA 0x%xULL\n' % value for key, value in values.items())+
              '#endif\n').encode()
    destination = output/'persistent_active_domain_capture_config.h'
    need(not destination.exists(), 'fresh active_domain observation configuration')
    script = pin(SELECTED/'persistent_active_domain_capture_binding.py')
    _, out, err = run('persistent-active_domain-capture-binding',
                     [builder.tools['python'], '-B', script, image, output], env=builder.environment)
    need(out == err == b'', 'active_domain observation binder has no diagnostics')
    destination = pin(binary(destination))
    need(destination.read_bytes() == header, 'whole independently derived active_domain observation header')
    return dict(version=4, original=original, symbols=values, source_pages=[base, base+4096],
                script=dict(path=str(script), **fact(script)), header=dict(path=str(destination), **fact(destination)))


def domain_protected_extents(builder, bridge, symbols, pin, run, state):
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
    need((compact, full, images, stubs, recovery, layout) == (353608, 981320, 65536, 4096, 6488, 48) and
         compact < payload <= rounded <= 96*4096 and payload == 362640 and owner == 3923456,
         'actual typed group primary, full reconstruction, two images and stub storage')
    rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [b'pe']]
    need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b', b'B') and
         int(rows[0][1], 16) == owner, 'actual ELF group owner equals DWARF extent')
    state['protected_extents'] = dict(payload=payload, proof_rounded=rounded, owner=owner,
        compact=compact, full=full, images=images, stubs=stubs, code=images+stubs,
        code_extents_per_member=3, code_pages_per_member=17, domain_code_extents_max=6, domain_code_pages_max=34, slots=4096, spill=4096, allocation=19*4096,
        recovery=recovery, layout=layout)


def retained_extents(builder, bridge, symbols, pin, run, state):
    """Actual two-slot authority/storage, with one independent ELF owner join."""
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    expression = ('printf "LI2_PTR_EXTENTS %llu %llu %llu %llu %llu\\n", '
        '(unsigned long long)sizeof(struct li2_ptr_slot_ref), '
        '(unsigned long long)sizeof(struct li2_ptr_slot), '
        '(unsigned long long)sizeof(pe.retained), '
        '(unsigned long long)sizeof(pe.retained)/sizeof(pe.retained[0]), '
        '(unsigned long long)sizeof(pe.retained[0].publication)')
    _, out, err = run('persistent-retained-two-extents', [gdb, '-nx', '-nh', '-batch',
        '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
        '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
        '-ex', 'file '+str(bridge), '-ex', expression], profile='inspect',
        env=dict(builder.environment, MALLOC_ARENA_MAX='1'))
    match = re.fullmatch(rb'LI2_PTR_EXTENTS ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)\n', out)
    need(not err and match is not None, 'exact actual retained slot DWARF result')
    sizes = tuple(map(int, match.groups()))
    need(sizes == (24,398088,796176,2,362640) and
         state['protected_extents']['payload'] == sizes[-1] and
         state['protected_extents']['owner'] > sizes[2],
         'two complete actual active-domain retained authorities and immutable publication mirrors')
    state['retained_extents'] = dict(zip(('reference','slot','slots','count','publication'),sizes))


def capture_extents(builder, bridge, symbols, pin, run, state):
    """Actual shared literals and complete mutable transcripts under original cap."""
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    expression = ('printf "LI2_PDAO_EXTENTS %llu %llu %llu %llu %llu %llu %llu\\n", '
        '(unsigned long long)sizeof(pdao_wire), '
        '(unsigned long long)sizeof(struct pdao_certificate), '
        '(unsigned long long)sizeof(struct pdao_epoch), '
        '(unsigned long long)sizeof(struct pdao_next), '
        '(unsigned long long)sizeof(struct pdao_stage), '
        '(unsigned long long)sizeof(struct pdao_slots), '
        '(unsigned long long)sizeof(struct pdao_epoch_info)')
    _, out, err = run('persistent-active-domain-capture-extents', [gdb, '-nx', '-nh', '-batch',
        '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
        '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
        '-ex', 'file '+str(bridge), '-ex', expression], profile='inspect',
        env=dict(builder.environment, MALLOC_ARENA_MAX='1'))
    match = re.fullmatch(rb'LI2_PDAO_EXTENTS ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)\n', out)
    need(not err and match is not None, 'exact actual active-domain capture DWARF result')
    sizes = tuple(map(int, match.groups()))
    need(sizes == (4161664,434240,952448,267968,102504,71384,15176) and
         sizes[0]+64 < 4*1024*1024, 'whole exact active-domain capture fits original4MiB')
    rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [b'pdao_wire']]
    need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b',b'B') and
         int(rows[0][1],16) == sizes[0], 'actual active-domain ELF BSS equals DWARF wire')
    state['capture_extents'] = dict(zip(('wire','certificate','epoch','next','stage','slots','epoch_info'),sizes))
    state['capture_extents'].update(footer=64,stream=sizes[0]+64,record_limit=4*1024*1024,
        representation='two literal immutable certificates, complete joint-domain records and whole per-checkpoint byte comparisons')
