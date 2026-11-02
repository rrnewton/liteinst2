#!/usr/bin/env python3
"""Separate mixed11/12 release build; old PF builds and all byte guards stay exact."""
import json
from pathlib import Path
import re
import shutil
import struct
from maps_view import (need, fact, SELECTED, UNITS, MACROS, recipe, expand, headers,
                       bridge_check, ENV, hidden_memset, body_check, digest, H)
from linked_epoch_build import FIXED_DOMAIN, fixed_domain_source
from scalar_span_trace_build import fast_bytes
from persistent_epoch_build import FEATURES as OLD_FEATURES, dynamic_original_image
FEATURES = OLD_FEATURES + ('scalar-read',)
from persistent_group_build import DISPATCH_POLICY_INPUTS, PROVIDERS, DISPATCH_PROVIDERS
POLICY_INPUTS = tuple({'build-persistent-resident.sh':'build-persistent-loop.sh',
    'persistent_resident_binding.py':'persistent_loop_binding.py'}.get(n,n)
    for n in DISPATCH_POLICY_INPUTS)+('persistent_retained_two.inc','linked_jmp_domain.h','linked_jmp_domain_emit.inc',
    'persistent_active_domain.h','persistent_active_domain_types.inc','persistent_active_domain.inc',
    'rseq_current_data.h','rseq_current_data.inc','linked_native_probe.h','linked_native_probe.inc','linked_native_probe_report.inc','maps_parse_memo.inc','persistent_subentry.h','persistent_subentry.inc','persistent_subentry_source.inc','persistent_cross_pair.h','persistent_cross_pair_source.inc','linked_direct_dispatch.h','linked_direct_dispatch.c')


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

CAPTURE_INPUTS = ('persistent_loop_observe.h', 'persistent_loop_observe.inc', 'persistent_loop_observe_memory.h', 'persistent_loop_observe_memory.inc', 'persistent_loop_capture_binding.py', 'capture_rle.h', 'capture_rle.c')


from persistent_loop_layout import protected_extents
POLICY_INPUTS += ('persistent_fused_plan.h','persistent_fused_plan.inc','persistent_fused_compact.inc','persistent_fused_runtime.h')
ACTIVE_PROVIDERS += ('li2_pf_plan_pages', 'li2_pf_plan_validate', 'li2_pf_miss_validate', 'li2_pf_compact_build', 'li2_pf_compact_validate', 'li2_pf_compact_guard','li2_pf_compact_direct', 'li2_pf_compact_exit', 'li2_pf_compact_recover')

POLICY_INPUTS += ('decoder/src/scalar_read.rs', 'scalar_read_decode.h', 'loop_envelope.h', 'loop_envelope.c', 'loop_read_bridge.h', 'loop_read_bridge.c', 'persistent_loop_plan.h', 'persistent_loop_plan.inc', 'persistent_loop_compact.inc', 'persistent_loop_runtime.h', 'persistent_loop_owner.inc', 'persistent_loop_negative_hint.h', 'persistent_loop_negative_hint.inc', 'linked_loop_direct.h', 'linked_loop_direct.inc', 'persistent_loop_fused_plan.h', 'persistent_loop_fused_plan.inc', 'persistent_loop_fused_compact.inc', 'build-loop-decoder.sh')
ACTIVE_PROVIDERS += ('li2_decoder_scalar_read_describe', 'li2_decoder_scalar_read_none', 'li2_le_choose', 'li2_le_validate', 'li2_lr_describe', 'li2_lr_none', 'li2_lr_bridge_node', 'li2_lp_plan_pages', 'li2_lp_plan_validate', 'li2_lp_miss_validate', 'li2_lp_compact_build', 'li2_lp_compact_validate', 'li2_lp_compact_guard', 'li2_lp_compact_direct', 'li2_lp_compact_exit', 'li2_lp_compact_recover', 'li2_pg_loop_full_policy', 'li2_pg_loop_compact_policy', 'li2_pg_loop_replay_valid', 'li2_pg_source_negative_decline', 'li2_pg_source_negative_remember', 'li2_ld_emit', 'li2_ld_validate', 'li2_ld_recover', 'li2_lp_placement', 'li2_lp_relocation_reason', 'li2_lp_fallback_relocation_reason', 'li2_lpf_plan_pages', 'li2_lpf_plan_validate', 'li2_lpf_miss_validate', 'li2_lpf_compact_build', 'li2_lpf_compact_validate', 'li2_lpf_compact_guard', 'li2_lpf_compact_direct', 'li2_lpf_compact_exit', 'li2_lpf_compact_recover', 'li2_lpf_graph_history')

def fixed_loop_domain(name, path):
    if name != 'decoder/src/region.rs':
        return fixed_domain_source(name, path)
    raw = path.read_bytes()
    need((len(raw), H(raw)) == (51778, 'eeb0a6185875f8b5d1552fdf58bade31e7dd53465c8eb5921902a96945ddf2df'),
         'whole exact additive scalar-read module source')
    addition = b"    // Separate version-2 read-only additions; old descriptor/NONE APIs stay exact.\n    #[cfg(feature = \"scalar-read\")]\n    mod scalar_read {\n        include!(\"scalar_read.rs\");\n    }\n"
    need(raw.count(addition) == 1, 'one exact scalar-read module inverse')
    prior = raw.replace(addition, b'', 1)
    need((len(prior), H(prior)) == FIXED_DOMAIN[name],
         'whole old131-Code scalar/span/NONE implementation retained')
    return len(raw), H(raw)

def binding_config(builder, archive, image, output, pin, binary, run, *, mode):
    need(mode in ('release','counters','capture','differential'), 'explicit mixed-policy build and separate schema14 capture')
    image = pin(binary(image))
    original = dynamic_original_image(image)
    values = []
    policy_inputs=POLICY_INPUTS
    if mode!='release':policy_inputs+=('build-persistent-loop-'+mode+'.sh',)
    if mode=='counters':policy_inputs+=('persistent_group_counters.h', 'persistent_loop_counters.h', 'persistent_loop_counters.inc', 'persistent_loop_counter_owner.inc')
    if mode in ('capture','differential'):policy_inputs+=CAPTURE_INPUTS
    for name in policy_inputs:
        path = pin(SELECTED / name)
        value = fact(path)
        if name in FIXED_DOMAIN:
            size, sha = fixed_loop_domain(name,path)
            need(digest(value) == digest(dict(bytes=size, sha256=sha)), 'unchanged reviewed scalar/NONE decoder domain')
        if name.endswith('.rs'):
            need(digest(builder.record['dep_info'].get('tools/page-entry/selected/' + name)) == digest(value), 'actual archive compiled each bound decoder source')
        values.append(dict(path=name, **value))
    archive = pin(archive)
    archive_fact = fact(archive)
    policy = digest(dict(sources=values, original=original, mode=mode))
    literal = lambda sha: '{' + ','.join(('0x' + sha[i:i + 2] for i in range(0, 64, 2))) + '}'
    linked = ('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINK_BINDING_VERSION 1\n#define LI2_LINK_ARCHIVE_SHA256 ' + literal(archive_fact['sha256']) + '\n#define LI2_LINK_POLICY_SHA256 ' + literal(policy) + '\n#endif\n').encode()
    persistent = ('#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION ' + '4' + '\n#define LI2_PG_LOOP_BINDING_VERSION 1\n#define LI2_PG_LOOP_POLICY_VERSION 12\n#define LI2_PG_LOOP_FALLBACK_VERSION 11\n#define LI2_PG_LOOP_ENCODING_VERSION 2\n#define LI2_PG_ARCHIVE_SHA256 ' + literal(archive_fact['sha256']) + '\n#define LI2_PG_POLICY_SHA256 ' + literal(policy) + '\n#endif\n').encode()
    expected = {'linked_epoch_config.h': linked, 'persistent_group_config.h': persistent}
    manifest = output / 'persistent_loop_binding.json'
    need(not manifest.exists() and (not any(((output / n).exists() for n in expected))), 'fresh binding outputs')
    _, out, err = run('persistent-group-policy-binding', [builder.tools['python'], '-B', SELECTED / 'persistent_loop_binding.py', SELECTED, archive, image, output, mode], env=builder.environment)
    need(out == err == b'', 'source-owned persistent binder has no diagnostics')
    header_facts = {}
    for name, data in expected.items():
        path = pin(binary(output / name))
        need(path.read_bytes() == data, 'whole independent archive/policy/image header')
        header_facts[name] = dict(path=str(path), **fact(path))
    record = dict(version=1, profile='persistent-loop-'+mode+('-v3' if mode=='counters' else '-v1'), mode=mode, native_probe=True, parse_memo=True, unregistered=True, subentry=True, cross_pair=True, direct_frontier=True, bounded_fused=True, bounded_loop=True, policy_version=12, fallback_policy=11, encoding_domain=dict(version=2, policies=[11,12], near_record=1, far_record=2, miss='source-derived-rel32-or-rip-indirect-u64', literal_bytes=8, literal_boundaries=0, old_pf_api=False), header_version=2, chooser_version=12, decoder_read_version=2, capture_version=14 if mode in ('capture','differential') else None, pf_refusals=dict(version=1,reason=256,shared_reasons=18,abi2=False), archive=archive_fact, policy_sha256=policy, original=original, sources=values, headers={name: dict(bytes=len(data), sha256=H(data)) for name, data in expected.items()})
    manifest = pin(binary(manifest))
    if mode=='counters':
        record['counter_schema']=dict(version=3,bytes=824,base_bytes=752,page=4096,initial_seals=6,final_seals=23)
    need(manifest.read_bytes() == (json.dumps(record, sort_keys=True) + '\n').encode(), 'complete typed persistent binding manifest')
    return dict(**record, header_paths=header_facts, manifest=dict(path=str(manifest), **fact(manifest)))

def build_bridge(builder, products, private, pin, binary, aliases, run, record, image, *, capture=False, retained_counters=False, differential=False):
    need(type(capture) is bool and type(differential) is bool and (not differential or capture),
         'differential validation is an explicit capture mode')
    mode='counters' if retained_counters else 'differential' if differential else 'capture' if capture else 'release'
    need(type(retained_counters) is bool and not (capture and retained_counters),
         'explicit active-domain counters require release without capture')
    need(builder.mov_guard is True and builder.linked_epoch is True and (builder.scalar_span is True) and (builder.extra_decoder_sources == ('region.rs', 'mov_guard.rs', 'scalar_read.rs')) and (builder.decoder_features == FEATURES) and (builder.record.get('decoder_features') == list(FEATURES)) and (builder.environment.get('LI2_DECODER_FEATURES') == 'scalar-read,mov-guard'), 'one explicit persistent decoder feature/source closure')
    archive = pin(products['archive'])
    retained = builder.record['artifacts']['decoder.a']
    need(builder.record['status'] == 'passed' and builder.record['command_completed'] is True and (archive == builder.paths['archive'] == builder.retained / 'decoder.a') and (str(archive) == retained['path']) and (digest(fact(archive)) == digest({k: retained[k] for k in ('bytes', 'sha256')})), 'fresh retained actual persistent archive')
    need(all((type(builder.record['archive_text_exports'].get(n)) is int and builder.record['archive_text_exports'][n] == 1 for n in ('li2_decoder_region_describe', 'li2_decoder_span_describe', 'li2_decoder_link_none', 'li2_decoder_mov_store', 'li2_decoder_tf_classify', 'li2_decoder_write_footprint', 'li2_decoder_scalar_read_describe', 'li2_decoder_scalar_read_none'))), 'every actual descriptor/NONE provider is present exactly once')
    output = private / ('persistent-loop-'+mode)
    output.mkdir()
    binding = binding_config(builder, archive, image, output, pin, binary, run, mode=mode)
    observation = capture_config(builder, image, output, pin, binary, run) if capture else None
    script = pin(SELECTED / ('build-persistent-loop'+('' if mode=='release' else '-'+mode)+'.sh'))
    rows = recipe(script, '"$cc_bin"')
    need(len(rows) == 1, 'one source-owned persistent compiler recipe')
    argv = expand(rows[0], {'$cc_bin': builder.tools['cc'], '$selected_dir': SELECTED, '$parent_dir': SELECTED.parent, '$archive': archive, '$output': output})
    units = [str(SELECTED.parent / x) for x in UNITS] + [str(SELECTED / x) for x in ('unrolled_hash_plan.c', 'region_plan.c', 'linked_plan.c', 'persistent_group_plan.c', 'persistent_group_compact.c', 'linked_mov_guard.c')]
    units.append(str(SELECTED / 'linked_jmp_dispatch.c'))
    units.append(str(SELECTED / 'linked_direct_dispatch.c'))
    units.extend(str(SELECTED / x) for x in ('loop_envelope.c', 'loop_read_bridge.c'))
    if capture:units.append(str(SELECTED/'capture_rle.c'))
    macros = ('PERSISTENT_GROUP', 'PERSISTENT_EPOCH', 'MOV_GUARD', 'LINKED_EPOCH', 'SCALAR_SPAN', 'SCALAR_SPAN_TRACE', 'SPAN_FAST_BYTES', 'MAPS_CURRENT_TF', 'SCALAR_REGION', 'SCALAR_REGION_REUSE', 'INITIAL_CODE_PROTECTION', 'UNROLLED_HASH', 'MAPS_MAINTAINED') + MACROS
    macros = ('PERSISTENT_LOOP_PLAN','PERSISTENT_LOOP_RUNTIME','PERSISTENT_FUSED_PLAN','PERSISTENT_FUSED_RUNTIME','PERSISTENT_DIRECT_FRONTIER','PERSISTENT_CROSS_PAIR','PERSISTENT_SUBENTRY','PERSISTENT_UNREGISTERED','MAPS_PARSE_MEMO','LINKED_NATIVE_PROBE','PERSISTENT_ACTIVE_DOMAIN','RSEQ_CURRENT_DATA','PERSISTENT_RETAINED_TWO','PERSISTENT_DISPATCH') + macros
    if capture:
        macros = ('PERSISTENT_LOOP_CAPTURE','PERSISTENT_DIRECT_FRONTIER_CAPTURE') + macros
    if differential:
        macros = ('MAPS_DIFFERENTIAL',) + macros
    if retained_counters:
        macros = ('PERSISTENT_LOOP_COUNTERS', 'PERSISTENT_RETAINED_TWO_COUNTERS', 'PERSISTENT_GROUP_COUNTERS') + macros
    name='bridge-persistent-loop'+('' if mode=='release' else '-'+mode)+'.so'
    need(argv[-2:] == ['-o', str(output / name)] and [x for x in argv if x.endswith(('.c', '.S'))] == units and ([x for x in argv if x.startswith('-DLI2_')] == ['-DLI2_PG_LOOP_ENCODING_VERSION=2'] + ['-DLI2_' + n + '=1' for n in macros]) and all((x in argv for x in ('-O2', '-g', '-nostdlib', '-shared', '-fPIC', '-fvisibility=hidden', '-mgeneral-regs-only', '-fno-builtin', '-fno-tree-loop-distribute-patterns', '-fno-tree-vectorize', '-Wall', '-Wextra', '-Werror'))), 'exact mixed11/12 no-FP recipe;28 TUs plus one codec TU only for capture')
    state = record['release_build'] = dict(status='failed', profile='persistent-loop-'+mode+('-v3' if mode=='counters' else '-v1'), recipe=fact(script), archive=fact(archive), argv=argv, persistent_binding=binding, capture=capture, qualification_credit=False)
    state['active_domain'] = dict(version=1, unregistered=True, subentry=True, cross_pair=True, direct_frontier=True, slots=2, same_source_pair=False, source_pairs_max=2, joint_receipts=3, directory_heads=256,
        maintained_rseq=True,differential=differential,native_probe=True,parse_memo=True,immutable_reconstruction='one-focal-policy12-lifetime-with-whole-source-choice-state-and-lossless-transcript' if capture else None)
    state['dispatch'] = dict(version=3, heads_min=1, heads_max=128, header_abi=2, shared_boundaries=8, code_pages=17, emitter_slot_bytes=512, emitter_boundaries=64)
    state['pf_refusals'] = dict(version=1,reason=256,shared_reasons=18,abi2=False)
    state['bounded_fused'] = dict(version=1,policy_version=11,heads_max=128,shared_boundaries=8,active_members_max=2,call_ret=False)
    state['bounded_loop'] = dict(version=1, policy_version=12, fallback_policy=11, encoding_domain=dict(version=2, policies=[11,12], near_record=1, far_record=2, miss='source-derived-rel32-or-rip-indirect-u64', literal_bytes=8, literal_boundaries=0, old_pf_api=False), header_version=2, chooser_version=12, decoder_read_version=2, heads_max=128, shared_boundaries=8, source_pages=2, active_members_max=2, call_ret=False, serialized_reconstruction=True, fallback='complete-source-bound-NO_ENVELOPE-only')
    state['direct_frontier'] = dict(version=1,policy_version=12,fallback_policy=11,encoding_domain=dict(version=2, policies=[11,12], near_record=1, far_record=2, miss='source-derived-rel32-or-rip-indirect-u64', literal_bytes=8, literal_boundaries=0, old_pf_api=False),partition='source-bound-loop-envelope-or-direction-fused',all_arms_directory=False,conditions=16,shared_boundaries=8,
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
    required_group = ('persistent_fused_plan.h','persistent_fused_plan.inc','persistent_fused_compact.inc','persistent_fused_runtime.h','persistent_group_plan.h', 'persistent_group_compact.h', 'persistent_group_lifetime.h', 'persistent_group_runtime.h', 'persistent_group_source.inc', 'persistent_group_rseq.inc', 'persistent_group_controller.inc','persistent_retained_two.inc','persistent_active_domain.inc',
        'persistent_active_domain.h','persistent_active_domain_types.inc','linked_jmp_domain.h','linked_jmp_domain_emit.inc',
        'rseq_current_data.h','rseq_current_data.inc','linked_native_probe.h','linked_native_probe.inc','linked_native_probe_report.inc','maps_parse_memo.inc','persistent_subentry.h','persistent_subentry.inc','persistent_subentry_source.inc','persistent_cross_pair.h','persistent_cross_pair_source.inc','linked_direct_dispatch.h','linked_direct_dispatch.c')
    required_group += ('scalar_read_decode.h','loop_envelope.h','loop_envelope.c','loop_read_bridge.h','loop_read_bridge.c','persistent_loop_plan.h','persistent_loop_plan.inc','persistent_loop_compact.inc','persistent_loop_runtime.h','persistent_loop_owner.inc', 'persistent_loop_negative_hint.h', 'persistent_loop_negative_hint.inc', 'linked_loop_direct.h', 'linked_loop_direct.inc', 'persistent_loop_fused_plan.h', 'persistent_loop_fused_plan.inc', 'persistent_loop_fused_compact.inc')
    forbidden = {'persistent_plan.c', 'persistent_compact.c', 'persistent_lifetime.h', 'persistent_runtime.h', 'persistent_source.inc', 'persistent_rseq.inc', 'persistent_controller.inc', 'persistent_dynamic_controller.inc', 'persistent_dynamic_plan.h', 'persistent_dynamic_plan.inc', 'persistent_epoch_config.h', 'persistent_dynamic_capture_config.h', 'selected_scalar_span.inc', 'selected_scalar_span_reuse.inc', 'unrolled_hash_nested_fp.h'}
    counter_names = {'persistent_group_counters.h', 'persistent_loop_counters.h', 'persistent_loop_counters.inc', 'persistent_loop_counter_owner.inc'}
    need('persistent_group_counters.inc' not in names and names.intersection(counter_names) == (counter_names if retained_counters else set()), 'exact ABI3 counter bootstrap/header/event compiler closure only in explicit loop release diagnostic')
    observation_names = {'persistent_loop_observe.h','persistent_loop_observe.inc',
                         'persistent_loop_observe_memory.h','persistent_loop_observe_memory.inc'}
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
    protected_extents(builder, bridge, symbols, pin, run, state)
    if retained_counters:
        for wanted, extent in ((b'pgc_bootstrap', 752), (b'li2_pgc_current', 8)):
            rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == [wanted]]
            need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in (b'b', b'B', b'd', b'D') and
                 int(rows[0][1], 16) == extent, 'actual final-counter storage/type extent')
        counter_extents(builder,bridge,pin,run,state)
        state['counter_schema'] = dict(version=3, bytes=824, base_bytes=752, page=4096, initial_seals=6, final_seals=23)
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


from persistent_loop_capture import capture_config, capture_extents


def counter_extents(builder, bridge, pin, run, state):
    """Independent ABI3 offsets from actual DWARF; no inferior is run."""
    gdb=pin(shutil.which('gdb',path=ENV['PATH']))
    rows=[('base','sizeof(struct li2_pgc_record)',752),
          ('record','sizeof(struct li2_plc_record)',824),
          ('loop','(char*)&((struct li2_plc_record*)0)->loop-(char*)0',752),
          ('counts','sizeof(struct li2_plc_counts)',72)]
    fields=('chooser_attempts','chooser_selected','chooser_no_envelope','publications12','hits12',
            'entries_with12','completed_with12','historical_reconstructions','actual_entries12')
    rows += [(name,'(char*)&((struct li2_plc_record*)0)->loop.'+name+'-(char*)0',752+8*i)
             for i,name in enumerate(fields)]
    expression=('printf "LI2_LOOP_COUNTER_EXTENTS '+' '.join(['%llu']*len(rows))+'\\n", '+
                ', '.join('(unsigned long long)('+expr+')' for _,expr,_ in rows))
    _,out,err=run('persistent-loop-counter-extents',[gdb,'-nx','-nh','-batch',
        '-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1',
        '-ex','file '+str(bridge),'-ex',expression,
        '-ex',"python import gdb; print('LI2_LOOP_COUNTER_ALIGN '+str(gdb.lookup_type('struct li2_plc_record').alignof))"],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    match=re.fullmatch(b'LI2_LOOP_COUNTER_EXTENTS '+b' '.join([rb'([0-9]+)']*len(rows))+b'\nLI2_LOOP_COUNTER_ALIGN 8\n',out)
    need(not err and match is not None and tuple(map(int,match.groups()))==tuple(v for _,_,v in rows),
         'whole actual ABI3 record and all nine offsets retain every old752-byte extent')
    state['loop_counter_extents']=dict(zip((name for name,_,_ in rows),map(int,match.groups())))
