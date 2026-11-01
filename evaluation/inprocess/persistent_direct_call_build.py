#!/usr/bin/env python3
"""Generic CALL+RET counters with complete source, layout and byte guards."""
import hashlib
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
from persistent_ret_build import (capture_config, domain_protected_extents, retained_extents,
    subentry_extents, cross_pair_extents, capture_extents, direct_frontier_extents, call_extents)
from persistent_group_build import DISPATCH_POLICY_INPUTS, PROVIDERS, DISPATCH_PROVIDERS
DIRECT_POLICY_INPUTS = tuple({'build-persistent-resident.sh':'build-persistent-direct-frontier.sh',
    'persistent_resident_binding.py':'persistent_direct_frontier_binding.py'}.get(n,n)
    for n in DISPATCH_POLICY_INPUTS)+('persistent_retained_two.inc','linked_jmp_domain.h','linked_jmp_domain_emit.inc',
    'persistent_active_domain.h','persistent_active_domain_types.inc','persistent_active_domain.inc',
    'rseq_current_data.h','rseq_current_data.inc','linked_native_probe.h','linked_native_probe.inc','linked_native_probe_report.inc','maps_parse_memo.inc','persistent_subentry.h','persistent_subentry.inc','persistent_subentry_source.inc','persistent_cross_pair.h','persistent_cross_pair_source.inc','linked_direct_dispatch.h','linked_direct_dispatch.c')

CALL_POLICY_INPUTS = tuple({'build-persistent-direct-frontier.sh':'build-persistent-call.sh',
    'persistent_direct_frontier_binding.py':'persistent_call_binding.py'}.get(n,n)
    for n in DIRECT_POLICY_INPUTS) + ('linked_call_dispatch.h','linked_call_dispatch.c',
    'maps_call_stack.h','maps_call_stack.inc','persistent_call_window.inc',
    'persistent_direct_frontier_binding.py')
POLICY_INPUTS = tuple({'build-persistent-call.sh':'build-persistent-direct-call.sh',
    'persistent_call_binding.py':'persistent_direct_call_binding.py'}.get(n,n)
    for n in CALL_POLICY_INPUTS) + ('persistent_call_binding.py',
    'linked_ret_dispatch.h','linked_ret_dispatch.c','persistent_ret_resume.h',
    'persistent_ret_resume.inc','tf_chain.inc')


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
    'li2_pgs_head_lookup','li2_pgs_entry_source','li2_pgs_entry_value','li2_pgs_owner_entry',
    'li2_lifecycle_initialize_empty',
    'li2_tf_chain_span_cross_page_eligible','li2_tf_chain_span_close_cross_page',
    'li2_tf_chain_span_direct_eligible','li2_tf_chain_span_close_direct',
    'li2_pgx_owner_offer','li2_pgx_source_prepare','li2_pgx_guard_union','li2_pgx_source_value',
    'li2_dd_span','li2_dd_describe','li2_dd_arm','li2_dd_emit','li2_dd_validate','li2_dd_recover',
    'li2_pg_compact_direct','li2_pg_compact_exit',
)

ACTIVE_PROVIDERS += ('li2_cd_direct_target','li2_cd_describe','li2_cd_emit','li2_cd_validate','li2_cd_recover',
    'li2_pg_call_binding','li2_pg_compact_call')

ACTIVE_PROVIDERS += ('li2_rd_describe', 'li2_rd_emit', 'li2_rd_validate', 'li2_rd_recover', 'li2_rd_recover_loaded_miss', 'li2_pg_ret_binding', 'li2_pg_compact_ret', 'li2_pg_compact_recover_ret', 'li2_pg_compact_ret_loaded_miss')

CAPTURE_INPUTS = ('persistent_direct_frontier_observe.h', 'persistent_direct_frontier_observe.inc', 'persistent_direct_frontier_observe_memory.h', 'persistent_direct_frontier_observe_memory.inc', 'persistent_direct_frontier_capture_binding.py', 'capture_rle.h', 'capture_rle.c')

def binding_config(builder, archive, image, output, pin, binary, run, *, mode):
    need(mode == 'counters', 'this CALL+RET adapter requires explicit release counters')
    image = pin(binary(image))
    original = dynamic_original_image(image)
    values = []
    policy_inputs=POLICY_INPUTS
    if mode!='release':policy_inputs+=('build-persistent-direct-call-'+mode+'.sh',)
    if mode=='counters':policy_inputs+=('persistent_group_counters.h','persistent_group_counters.inc')
    if mode in ('capture','differential'):policy_inputs+=CAPTURE_INPUTS
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
    manifest = output / 'persistent_direct_call_binding.json'
    need(not manifest.exists() and (not any(((output / n).exists() for n in expected))), 'fresh binding outputs')
    _, out, err = run('persistent-group-policy-binding', [builder.tools['python'], '-B', SELECTED / 'persistent_direct_call_binding.py', SELECTED, archive, image, output, mode], env=builder.environment)
    need(out == err == b'', 'source-owned persistent binder has no diagnostics')
    header_facts = {}
    for name, data in expected.items():
        path = pin(binary(output / name))
        need(path.read_bytes() == data, 'whole independent archive/policy/image header')
        header_facts[name] = dict(path=str(path), **fact(path))
    record = dict(version=1, profile='persistent-direct-call-'+mode+'-v1', mode=mode, native_probe=True, parse_memo=True, unregistered=True, subentry=True, cross_pair=True, direct_frontier=True, call_dispatch=True, ret_dispatch=True, return_heads=True, direct_call=True, plan_version=9, maps_differential=False, typed_capture=False, archive=archive_fact, policy_sha256=policy, original=original, sources=values, headers={name: dict(bytes=len(data), sha256=H(data)) for name, data in expected.items()})
    manifest = pin(binary(manifest))
    need(manifest.read_bytes() == (json.dumps(record, sort_keys=True) + '\n').encode(), 'complete typed persistent binding manifest')
    return dict(**record, header_paths=header_facts, manifest=dict(path=str(manifest), **fact(manifest)))


def build_bridge(builder, products, private, pin, binary, aliases, run, record, image, *, capture=False, retained_counters=False, differential=False):
    need(type(capture) is bool and type(differential) is bool and (not differential or capture),
         'differential validation is an explicit capture mode')
    need(capture is False and retained_counters is True and differential is False,
         'CALL+RET program experiment has release counters and no typed capture')
    mode='counters'
    need(type(retained_counters) is bool and not (capture and retained_counters),
         'explicit active-domain counters require release without capture')
    need(builder.mov_guard is True and builder.linked_epoch is True and (builder.scalar_span is True) and (builder.extra_decoder_sources == ('region.rs', 'mov_guard.rs')) and (builder.decoder_features == FEATURES) and (builder.record.get('decoder_features') == list(FEATURES)) and (builder.environment.get('LI2_DECODER_FEATURES') == 'linked-epoch,mov-guard'), 'one explicit persistent decoder feature/source closure')
    archive = pin(products['archive'])
    retained = builder.record['artifacts']['decoder.a']
    need(builder.record['status'] == 'passed' and builder.record['command_completed'] is True and (archive == builder.paths['archive'] == builder.retained / 'decoder.a') and (str(archive) == retained['path']) and (digest(fact(archive)) == digest({k: retained[k] for k in ('bytes', 'sha256')})), 'fresh retained actual persistent archive')
    need(all((type(builder.record['archive_text_exports'].get(n)) is int and builder.record['archive_text_exports'][n] == 1 for n in ('li2_decoder_region_describe', 'li2_decoder_span_describe', 'li2_decoder_link_none', 'li2_decoder_mov_store', 'li2_decoder_tf_classify', 'li2_decoder_write_footprint'))), 'every actual descriptor/NONE provider is present exactly once')
    output = private / ('persistent-direct-call-'+mode)
    output.mkdir()
    binding = binding_config(builder, archive, image, output, pin, binary, run, mode=mode)
    observation = capture_config(builder, image, output, pin, binary, run) if capture else None
    script = pin(SELECTED / ('build-persistent-direct-call'+('' if mode=='release' else '-'+mode)+'.sh'))
    rows = recipe(script, '"$cc_bin"')
    need(len(rows) == 1, 'one source-owned persistent compiler recipe')
    argv = expand(rows[0], {'$cc_bin': builder.tools['cc'], '$selected_dir': SELECTED, '$parent_dir': SELECTED.parent, '$archive': archive, '$output': output})
    units = [str(SELECTED.parent / x) for x in UNITS] + [str(SELECTED / x) for x in ('unrolled_hash_plan.c', 'region_plan.c', 'linked_plan.c', 'persistent_group_plan.c', 'persistent_group_compact.c', 'linked_mov_guard.c')]
    units.append(str(SELECTED / 'linked_jmp_dispatch.c'))
    units.append(str(SELECTED / 'linked_direct_dispatch.c'))
    units.append(str(SELECTED / 'linked_call_dispatch.c'))
    units.append(str(SELECTED / 'linked_ret_dispatch.c'))
    if capture:units.append(str(SELECTED/'capture_rle.c'))
    macros = ('PERSISTENT_GROUP', 'PERSISTENT_EPOCH', 'MOV_GUARD', 'LINKED_EPOCH', 'SCALAR_SPAN', 'SCALAR_SPAN_TRACE', 'SPAN_FAST_BYTES', 'MAPS_CURRENT_TF', 'SCALAR_REGION', 'SCALAR_REGION_REUSE', 'INITIAL_CODE_PROTECTION', 'UNROLLED_HASH', 'MAPS_MAINTAINED') + MACROS
    macros = ('PERSISTENT_DIRECT_FRONTIER','PERSISTENT_CROSS_PAIR','PERSISTENT_SUBENTRY','PERSISTENT_UNREGISTERED','MAPS_PARSE_MEMO','LINKED_NATIVE_PROBE','PERSISTENT_ACTIVE_DOMAIN','RSEQ_CURRENT_DATA','PERSISTENT_RETAINED_TWO','PERSISTENT_DISPATCH') + macros
    if capture:
        macros = ('PERSISTENT_DIRECT_FRONTIER_CAPTURE',) + macros
    if differential:
        macros = ('MAPS_DIFFERENTIAL',) + macros
    if retained_counters:
        macros = ('PERSISTENT_RETAINED_TWO_COUNTERS', 'PERSISTENT_GROUP_COUNTERS') + macros
    macros = ('PERSISTENT_DIRECT_CALL','PERSISTENT_CALL_RETURN_HEADS','PERSISTENT_RET_DISPATCH','PERSISTENT_CALL_DISPATCH') + macros
    name='bridge-persistent-direct-call'+('' if mode=='release' else '-'+mode)+'.so'
    need(argv[-2:] == ['-o', str(output / name)] and [x for x in argv if x.endswith(('.c', '.S'))] == units and ([x for x in argv if x.startswith('-DLI2_')] == ['-DLI2_' + n + '=1' for n in macros]) and all((x in argv for x in ('-O2', '-g', '-nostdlib', '-shared', '-fPIC', '-fvisibility=hidden', '-mgeneral-regs-only', '-fno-builtin', '-fno-tree-loop-distribute-patterns', '-fno-tree-vectorize', '-Wall', '-Wextra', '-Werror'))), 'exact28-TU CALL+RET counter no-FP recipe')
    state = record['release_build'] = dict(status='failed', profile='persistent-direct-call-'+mode+'-v1', call_dispatch=True, ret_dispatch=True, return_heads=True, direct_call=True, plan_version=9, recipe=fact(script), archive=fact(archive), argv=argv, persistent_binding=binding, capture=capture, qualification_credit=False)
    state['active_domain'] = dict(version=1, unregistered=True, subentry=True, cross_pair=True, direct_frontier=True, slots=2, same_source_pair=False, source_pairs_max=2, joint_receipts=3, directory_heads=256,
        maintained_rseq=True,differential=differential,native_probe=True,parse_memo=True,immutable_reconstruction='two-whole-certificates-with-frozen-lossless-transcript' if capture else None)
    state['dispatch'] = dict(version=3, heads_min=1, heads_max=128, header_abi=1, shared_boundaries=8, code_pages=17, emitter_slot_bytes=512, emitter_boundaries=64)
    state['direct_frontier'] = dict(version=1,policy_version=5,conditions=16,shared_boundaries=8,
        typed_external_arms=True,unknown_target='original branch-before full drain')
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
        'rseq_current_data.h','rseq_current_data.inc','linked_native_probe.h','linked_native_probe.inc','linked_native_probe_report.inc','maps_parse_memo.inc','persistent_subentry.h','persistent_subentry.inc','persistent_subentry_source.inc','persistent_cross_pair.h','persistent_cross_pair_source.inc','linked_direct_dispatch.h','linked_direct_dispatch.c',
        'linked_call_dispatch.h','linked_call_dispatch.c','maps_call_stack.h','maps_call_stack.inc',
        'persistent_call_window.inc','linked_ret_dispatch.h','linked_ret_dispatch.c',
        'persistent_ret_resume.h','persistent_ret_resume.inc','tf_chain.inc')
    forbidden = {'persistent_plan.c', 'persistent_compact.c', 'persistent_lifetime.h', 'persistent_runtime.h', 'persistent_source.inc', 'persistent_rseq.inc', 'persistent_controller.inc', 'persistent_dynamic_controller.inc', 'persistent_dynamic_plan.h', 'persistent_dynamic_plan.inc', 'persistent_epoch_config.h', 'persistent_dynamic_capture_config.h', 'selected_scalar_span.inc', 'selected_scalar_span_reuse.inc', 'unrolled_hash_nested_fp.h'}
    counter_names = {'persistent_group_counters.h', 'persistent_group_counters.inc'}
    need(names.intersection(counter_names) == (counter_names if retained_counters else set()), 'exact counter bootstrap/header compiler closure only in explicit release diagnostic')
    observation_names = {'persistent_direct_frontier_observe.h','persistent_direct_frontier_observe.inc',
                         'persistent_direct_frontier_observe_memory.h','persistent_direct_frontier_observe_memory.inc'}
    if capture:
        need(all((str((SELECTED / n).resolve()) in state['headers'] for n in observation_names)) and digest(state['headers'].get(observation['header']['path'])) == digest({k: observation['header'][k] for k in ('bytes','sha256')}), 'all four actual observation leaves and exact generated capture header are compiler inputs')
    need(all((str((SELECTED / n).resolve()) in state['headers'] for n in required_group)) and (not names.intersection(forbidden)) and (not any(('observe' in n and (not (capture and n in observation_names)) or n.startswith(('linked_preedge_', 'linked_native_hint')) for n in names))), 'exact group release source closure without an old owner, classifier, capture or wire alias')
    bridge = Path(argv[-1])
    run('persistent-group-release-link', argv, profile='release_build', env=builder.environment)
    state['bridge'] = fact(binary(bridge))
    state['elf'] = bridge_check(bridge)
    _, out, err = run('persistent-group-release-undefined', [builder.tools['nm'], '-u', bridge], profile='inspect', env=builder.environment)
    need(out == err == b'', 'persistent bridge has no unresolved imports')
    _, symbols, err = run('persistent-group-release-symbols', [builder.tools['nm'], '-S', '--defined-only', bridge], profile='inspect', env=builder.environment)
    need(not err, 'complete actual persistent symbol census')
    for name in ACTIVE_PROVIDERS + (('li2_pdo_trace_closed','li2_capture_rle_prepare','li2_capture_rle_write') if capture else ()):
        found = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [name.encode()]]
        need(len(found) == 1 and len(found[0]) == 4 and (found[0][2] in (b't', b'T')) and (int(found[0][1], 16) > 0), 'actual nonempty persistent proof/owner provider ' + name)
    providers = re.findall(r'--undefined=([^,\\\s]+)', ' '.join(argv))
    need(providers == ['li2_selected_observe_hardware', 'li2_selected_complete_native', 'li2_selected_complete_scripted', 'li2_step_session_init', 'li2_step_arm', 'li2_step_begin', 'li2_step_trace', 'li2_step_abort', 'li2_decoder_initialize', 'li2_decoder_decode', 'li2_decoder_scan_page', 'li2_decoder_stats', 'li2_decoder_tf_classify', 'li2_tf_arm', 'li2_tf_begin', 'li2_tf_trace', 'li2_tf_abort', 'li2_tf_unexpected', 'li2_lifecycle_tf_continuation', 'li2_decoder_write_footprint', 'li2_decoder_span_describe', 'li2_span_plan_page', 'li2_span_plan_validate', 'li2_span_map_pc', 'li2_decoder_link_none', 'li2_link_plan_page', 'li2_link_plan_validate', 'li2_decoder_mov_store', 'li2_pg_plan_pages', 'li2_pg_miss_valid', 'li2_pg_plan_pages', 'li2_pg_plan_validate', 'li2_pg_compact_build', 'li2_pg_compact_validate', 'li2_pg_compact_guard', 'li2_pg_compact_recover', 'li2_mg_emit', 'li2_mg_recover', 'li2_jd_describe', 'li2_jd_emit', 'li2_jd_validate', 'li2_jd_recover', 'li2_pg_dispatch_binding', 'li2_pg_compact_dispatch', 'li2_dd_span', 'li2_dd_describe', 'li2_dd_arm', 'li2_dd_emit', 'li2_dd_validate', 'li2_dd_recover', 'li2_pg_compact_direct', 'li2_pg_compact_exit', 'li2_cd_direct_target', 'li2_cd_describe', 'li2_cd_emit', 'li2_cd_validate', 'li2_cd_recover', 'li2_pg_call_binding', 'li2_pg_compact_call', 'li2_rd_describe', 'li2_rd_emit', 'li2_rd_validate', 'li2_rd_recover', 'li2_rd_recover_loaded_miss', 'li2_pg_ret_binding', 'li2_pg_compact_ret', 'li2_pg_compact_recover_ret', 'li2_pg_compact_ret_loaded_miss'],
         'all68 source-owned provider entries in their exact original-plus-RET-plus-E8 order')
    _, local_symbols, err = run('persistent-direct-call-release-providers',
        [builder.tools['nm'], '--defined-only', bridge], profile='inspect', env=builder.environment)
    need(not err, 'complete actual local provider census')
    state['provider_functions'] = provider_functions(bridge.read_bytes(), local_symbols, providers)
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
    subentry_extents(builder, bridge, pin, run, state)
    cross_pair_extents(builder, bridge, symbols, pin, run, state)
    direct_frontier_extents(builder, bridge, pin, run, state)
    call_extents(builder, bridge, symbols, pin, run, state)
    ret_extents(builder, bridge, symbols, pin, run, state)
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
        need(all((fact(observation[key]['path']) == {k: observation[key][k] for k in ('bytes','sha256')} for key in ('script','header'))) and all((fact(path) == value for path,value in state['headers'].items())) and fact(script) == state['recipe'], 'actual capture selectors and complete compiler inputs unchanged through byte oracle')
    state['status'] = 'passed'
    return bridge


def provider_functions(data, nm_text, expected):
    """Join every required local function to the complete ELF and nm census."""
    def take(at, count):
        need(0 <= at <= len(data) and 0 <= count <= len(data)-at, 'bounded whole ELF provider range')
        return data[at:at+count]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0,64))
    need(h[0][:7] == b'\x7fELF\2\1\1' and h[1:4] == (3,62,1) and
         h[8:10] == (64,56) and h[11] == 64 and 0 < h[10] <= 128 and 0 < h[12] <= 4096,
         'exact ELF64 shared bridge and bounded complete section/program tables')
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6]+64*i,64)) for i in range(h[12])]
    loads = [struct.unpack('<IIQQQQQQ', take(h[5]+56*i,56)) for i in range(h[10])]
    tables = [x for x in sections if x[1] == 2]
    need(len(tables) == 1, 'one complete static symbol table including localized providers')
    t = tables[0]
    need(t[9] == 24 and t[5] % 24 == 0 and 0 < t[6] < len(sections), 'whole symbol records/string-table index')
    names_row = sections[t[6]]
    need(names_row[1] == 3, 'actual symbol string table')
    names = take(names_row[4],names_row[5]); table = take(t[4],t[5]); symbols = {}
    for at in range(0,len(table),24):
        name, info, other, section, address, size = struct.unpack_from('<IBBHQQ',table,at)
        need(name < len(names) and b'\0' in names[name:], 'bounded NUL-terminated symbol name')
        name = names[name:names.index(b'\0',name)].decode('ascii')
        if name in expected:
            need(name not in symbols, 'one exact definition of every required provider')
            need(info == 2 and other == 0 and 0 < section < len(sections) and size > 0,
                 'actual LOCAL STT_FUNC definition with nonzero body, not UNDEF/ABS/COMMON or object')
            s = sections[section]
            need(s[1] == 1 and s[2] & 7 == 6 and s[3] <= address and size <= s[3]+s[5]-address,
                 'whole provider body in allocated executable nonwritable PROGBITS')
            executable = [x for x in loads if x[0] == 1 and x[1] == 5 and x[5] <= x[6] and
                          x[3] <= address and size <= x[3]+x[5]-address]
            need(len(executable) == 1, 'whole provider body in one actual file-backed RX LOAD')
            load = executable[0]; offset = s[4]+address-s[3]
            need(offset == load[2]+address-load[3], 'section and executable LOAD agree on actual function bytes')
            symbols[name] = dict(address=address,bytes=size,binding=0,type=2,visibility=0,section=section,
                                 file_offset=offset,sha256=hashlib.sha256(take(offset,size)).hexdigest())
    need(len(expected) == 68 and len(set(expected)) == 67 and set(symbols) == set(expected),
         'all58 original entries plus9 RET entries and one E8 target provider, all67 unique actual functions')
    observed = {}
    for line in nm_text.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]+) ([A-Za-z?]) (\S+)',line)
        need(match is not None, 'complete defined-symbol nm row grammar')
        if match[3] in symbols:
            need(match[3] not in observed and match[2] == 't' and
                 int(match[1],16) == symbols[match[3]]['address'], 'nm actual local text symbol joins ELF function')
            observed[match[3]] = int(match[1],16)
    need(set(observed) == set(symbols), 'complete nm and ELF provider sets agree')
    return symbols




def ret_extents(builder, bridge, symbols, pin, run, state):
    """Observe complete RET recovery/storage, preserving all CALL dimensions."""
    from page_selected import elf
    gdb = pin(shutil.which('gdb', path=ENV['PATH']))
    expressions = ('sizeof(struct li2_rd_descriptor)', 'sizeof(struct li2_rd_record)',
        'sizeof(struct li2_rd_plan)', 'sizeof(struct li2_rd_window)',
        'sizeof(struct li2_rd_binding)', 'sizeof(struct li2_rd_recovered)',
        'sizeof(struct pda_ret_exit)', 'sizeof(struct prr_attempt)', 'sizeof(prr)',
        'sizeof(struct li2_pg_ret_record)',
        '(char*)&pe.domain.completion[0].ret_exit-(char*)&pe.domain.completion[0]')
    expression = ('printf "LI2_RD_EXTENTS ' + ' '.join(['%llu'] * len(expressions)) + '\\n", ' +
        ', '.join('(unsigned long long)(' + value + ')' for value in expressions))
    _, out, err = run('persistent-call-return-heads-extents', [gdb, '-nx', '-nh', '-batch',
        '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
        '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
        '-ex', 'file ' + str(bridge), '-ex', expression], profile='inspect',
        env=dict(builder.environment, MALLOC_ARENA_MAX='1'))
    match = re.fullmatch(b'LI2_RD_EXTENTS ' + b' '.join([rb'([0-9]+)'] * len(expressions)) + b'\n', out)
    need(not err and match is not None, 'one complete actual RET DWARF result')
    sizes = tuple(map(int, match.groups()))
    need(sizes == (144,1600,2328,64,56,176,3040,71616,72256,1584,71032) and
         sizes[6] + sizes[-1] == state['direct_frontier_extents']['exit_offset'],
         'exact complete RET descriptors and by-value loaded-exit before the unchanged direct-exit tail')
    rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [b'prr']]
    need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b', b'B') and
         int(rows[0][0], 16) > 0 and int(rows[0][1], 16) == sizes[8],
         'whole actual saved-target owner BSS symbol equals DWARF')
    address = int(rows[0][0], 16)
    _, _, segments = elf(bridge)
    need(sum(p[0] == 1 and p[1] == 6 and p[3] <= address < address + sizes[8] <= p[3] + p[6]
             for p in segments) == 1, 'whole saved-target owner belongs to protected RW/NX bridge storage')
    state['ret_extents'] = dict(zip(('descriptor','record','plan','window','binding','recovered',
        'exit','attempt','owner','compact_record','exit_offset'), sizes))
    state['ret_extents']['owner_address'] = address
