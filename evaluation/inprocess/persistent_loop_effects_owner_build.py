"""Read-only whole build reconstruction from source-derived retained commands.

These helpers do not launch a command or write any file. The prerequisite's
closed_run authenticates every whole argv/environment/bound/capture. Original
builder predicates are retained; only fresh-directory/file creation becomes an
exact existing-object/content join after whole receipt custody is established.
"""
from persistent_loop_effects_build import *
from scalar_span_trace_build import (observe_headers, elf, interpreter, PROGRAM_ENV,
    resolved_libraries, fast_bytes_completed, FAST_BYTES_STDOUT)
import importlib.util
import namespace

def binding_completed(builder, archive, image, output, pin, binary, run, *, mode):
    need(mode in ('release','capture','differential'), 'explicit mixed-policy build and separate schema16 capture')
    image = pin(binary(image))
    original = dynamic_original_image(image)
    values = []
    policy_inputs=POLICY_INPUTS
    if mode!='release':policy_inputs+=('build-persistent-loop-effects-'+mode+'.sh',)
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
    persistent = ('#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION ' + '4' + '\n#define LI2_PG_LOOP_BINDING_VERSION 1\n#define LI2_PG_LOOP_POLICY_VERSION 12\n#define LI2_PG_LOOP_FALLBACK_VERSION 11\n#define LI2_PG_LOOP_ENCODING_VERSION 2\n#define LI2_PG_LOOP_EFFECTS_BINDING_VERSION 1\n#define LI2_PG_LOOP_EFFECTS_POLICY_VERSION 13\n#define LI2_PG_LOOP_EFFECTS_SCALAR_VERSION 3\n#define LI2_PG_LOOP_EFFECTS_MOV_VERSION 2\n#define LI2_PG_ARCHIVE_SHA256 ' + literal(archive_fact['sha256']) + '\n#define LI2_PG_POLICY_SHA256 ' + literal(policy) + '\n#endif\n').encode()
    expected = {'linked_epoch_config.h': linked, 'persistent_group_config.h': persistent}
    manifest = output / 'persistent_loop_effects_binding.json'
    need(manifest.is_file() and all((output/n).is_file() for n in expected), 'complete retained binding outputs')
    _, out, err = run('persistent-group-policy-binding', [builder.tools['python'], '-B', SELECTED / 'persistent_loop_effects_binding.py', SELECTED, archive, image, output, mode], env=builder.environment)
    need(out == err == b'', 'source-owned persistent binder has no diagnostics')
    header_facts = {}
    for name, data in expected.items():
        path = pin(binary(output / name))
        need(path.read_bytes() == data, 'whole independent archive/policy/image header')
        header_facts[name] = dict(path=str(path), **fact(path))
    record = dict(version=1, profile='persistent-loop-effects-'+mode+'-v1', mode=mode, native_probe=True, parse_memo=True, unregistered=True, subentry=True, cross_pair=True, direct_frontier=True, bounded_fused=True, bounded_loop=True, policy_version=12, fallback_policy=11, encoding_domain=dict(version=2, policies=[11,12,13], near_record=1, far_record=2, miss='source-derived-rel32-or-rip-indirect-u64', literal_bytes=8, literal_boundaries=0, old_pf_api=False), header_version=2, chooser_version=12, decoder_read_version=2, effects=dict(binding_version=1,policy_version=13,scalar_version=3,mov_version=2,selection_order=[12,13,11]), capture_version=16 if mode in ('capture','differential') else None, pf_refusals=dict(version=1,reason=256,shared_reasons=18,abi2=False), archive=archive_fact, policy_sha256=policy, original=original, sources=values, headers={name: dict(bytes=len(data), sha256=H(data)) for name, data in expected.items()})
    manifest = pin(binary(manifest))
    if mode=='counters':
        record['counter_schema']=dict(version=3,bytes=824,base_bytes=752,page=4096,initial_seals=6,final_seals=23)
    need(manifest.read_bytes() == (json.dumps(record, sort_keys=True) + '\n').encode(), 'complete typed persistent binding manifest')
    return dict(**record, header_paths=header_facts, manifest=dict(path=str(manifest), **fact(manifest)))

def fast_bytes_reconstruct(builder,output,pin,binary,aliases,run,build):
    fixture=SELECTED/'tests/span_fast_bytes';output=output/'fast-bytes';need(output.is_dir(), 'retained actual byte-oracle directory')
    state=build['fast_bytes']=dict(status='failed')
    script=pin(fixture/'build.sh');unit=pin(fixture/'oracle.c');header=pin(SELECTED/'span_fast_bytes.h')
    observe_headers(script,{'$cc_bin':builder.tools['cc'],'$selected':SELECTED,'$fixture':fixture,'$output':output},
        [],'span-bytes-headers',builder,pin,run,state,aliases)
    rows=state['header_observations'];need(len(rows)==1 and rows[0]['complete'],'one complete actual-header oracle recipe')
    argv=rows[0]['argv'];deps=rows[0]['headers']
    need([x for x in argv if x.endswith(('.c','.S'))]==[str(unit)]and
         [x for x in argv if x.startswith('-D')]==['-DLI2_SCALAR_SPAN_TRACE=1','-DLI2_SPAN_FAST_BYTES=1']and
         str(header)in deps and all(x in argv for x in('-O2','-g','-fno-builtin','-mgeneral-regs-only',
             '-fno-tree-loop-distribute-patterns','-fno-tree-vectorize','-Wall','-Wextra','-Werror'))and
         argv[-2:]==['-o',str(output/'span-fast-bytes')],'exact actual-header oracle compiler recipe')
    _,out,err=run('span-bytes-link',argv,profile='release_build',env=builder.environment)
    need(out==err==b'','complete byte-oracle build without diagnostics')
    executable=binary(output/'span-fast-bytes');state.update(path=str(executable),executable=fact(executable))
    data,head,segments=elf(executable)
    need(head[1]in(2,3)and any(p[0]==1 and p[1]==5 and p[3]<=head[4]<p[3]+p[6]for p in segments)and
         all(not(p[1]&1 and p[1]&2)for p in segments if p[0]in(1,0x6474e551)),
         'actual byte-oracle ELF entry with no writable executable segment or stack')
    interp=pin(interpreter(executable))
    spec=importlib.util.spec_from_file_location('span_bytes_namespace',pin(SELECTED.parent/'namespace.py'))
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    need(pin(namespace.parse(data)['interpreter'])==interp,'exact byte-oracle interpreter alias')
    objects,description=namespace.plan(executable,[Path('/usr/lib64')],bytes.fromhex(H(data)),bytes.fromhex(fact(interp)['sha256']))
    expected={interp:set()}
    for obj in objects:
        path=pin(obj['path']);need(fact(path)['sha256']==H(obj['bytes']),'whole actual oracle dependency')
        expected.setdefault(path,set()).update(obj['names'])
    state['runtime_inputs']=dict(interpreter=fact(interp),dependencies=[dict(names=o['names'],**fact(o['path']))for o in objects])
    state['namespace_plan']=description
    _,out,err=run('span-bytes-native-libraries',[interp,'--list',executable],env=PROGRAM_ENV)
    need(not err,'actual oracle loader listing stderr');resolved_libraries(out,expected,interp,pin)
    row,out,err=run('span-bytes-oracle',[executable],profile='finite',env=PROGRAM_ENV)
    need(out==FAST_BYTES_STDOUT and err==b'','all actual-header byte cases and exact result')
    need(fact(header)=={k:deps[str(header)][k]for k in('bytes','sha256')},'actual header unchanged through oracle')
    state.update(status='passed',command=row['name']);fast_bytes_completed(build,[row],binary)

def bridge_completed(builder, products, private, pin, binary, aliases, run, record, image, *, capture=False, retained_counters=False, differential=False):
    need(type(capture) is bool and type(differential) is bool and (not differential or capture),
         'differential validation is an explicit capture mode')
    mode='counters' if retained_counters else 'differential' if differential else 'capture' if capture else 'release'
    need(type(retained_counters) is bool and not retained_counters and not (capture and retained_counters),
         'explicit active-domain counters require release without capture')
    need(builder.mov_guard is True and builder.linked_epoch is True and (builder.scalar_span is True) and (builder.extra_decoder_sources == ('region.rs', 'mov_guard.rs', 'scalar_read.rs', 'loop_scalar.rs', 'byte_mov_guard.rs')) and (builder.decoder_features == FEATURES) and (builder.record.get('decoder_features') == list(FEATURES)) and (builder.environment.get('LI2_DECODER_FEATURES') == 'loop-effects'), 'one explicit persistent decoder feature/source closure')
    archive = pin(products['archive'])
    retained = builder.record['artifacts']['decoder.a']
    need(builder.record['status'] == 'passed' and builder.record['command_completed'] is True and (archive == builder.paths['archive'] == builder.retained / 'decoder.a') and (str(archive) == retained['path']) and (digest(fact(archive)) == digest({k: retained[k] for k in ('bytes', 'sha256')})), 'fresh retained actual persistent archive')
    need(all((type(builder.record['archive_text_exports'].get(n)) is int and builder.record['archive_text_exports'][n] == 1 for n in ('li2_decoder_region_describe', 'li2_decoder_span_describe', 'li2_decoder_link_none', 'li2_decoder_mov_store', 'li2_decoder_tf_classify', 'li2_decoder_write_footprint', 'li2_decoder_scalar_read_describe', 'li2_decoder_scalar_read_none', 'li2_decoder_loop_scalar_describe', 'li2_decoder_loop_scalar_none', 'li2_decoder_byte_mov_store'))), 'every actual descriptor/NONE provider is present exactly once')
    output = private / ('persistent-loop-effects-'+mode)
    need(output.is_dir(), 'retained actual loop build directory')
    binding = binding_completed(builder, archive, image, output, pin, binary, run, mode=mode)
    observation = capture_config(builder, image, output, pin, binary, run) if capture else None
    script = pin(SELECTED / ('build-persistent-loop-effects'+('' if mode=='release' else '-'+mode)+'.sh'))
    rows = recipe(script, '"$cc_bin"')
    need(len(rows) == 1, 'one source-owned persistent compiler recipe')
    argv = expand(rows[0], {'$cc_bin': builder.tools['cc'], '$selected_dir': SELECTED, '$parent_dir': SELECTED.parent, '$archive': archive, '$output': output})
    units = [str(SELECTED.parent / x) for x in UNITS] + [str(SELECTED / x) for x in ('unrolled_hash_plan.c', 'region_plan.c', 'linked_plan.c', 'persistent_group_plan.c', 'persistent_group_compact.c', 'linked_mov_guard.c')]
    units.append(str(SELECTED / 'linked_jmp_dispatch.c'))
    units.append(str(SELECTED / 'linked_direct_dispatch.c'))
    units.extend(str(SELECTED / x) for x in ('loop_envelope.c', 'loop_read_bridge.c', 'loop_effects_envelope.c', 'loop_effects_bridge.c'))
    if capture:units.append(str(SELECTED/'capture_rle.c'))
    macros = ('PERSISTENT_GROUP', 'PERSISTENT_EPOCH', 'MOV_GUARD', 'LINKED_EPOCH', 'SCALAR_SPAN', 'SCALAR_SPAN_TRACE', 'SPAN_FAST_BYTES', 'MAPS_CURRENT_TF', 'SCALAR_REGION', 'SCALAR_REGION_REUSE', 'INITIAL_CODE_PROTECTION', 'UNROLLED_HASH', 'MAPS_MAINTAINED') + MACROS
    macros = ('PERSISTENT_LOOP_PLAN','PERSISTENT_LOOP_RUNTIME','PERSISTENT_FUSED_PLAN','PERSISTENT_FUSED_RUNTIME','PERSISTENT_DIRECT_FRONTIER','PERSISTENT_CROSS_PAIR','PERSISTENT_SUBENTRY','PERSISTENT_UNREGISTERED','MAPS_PARSE_MEMO','LINKED_NATIVE_PROBE','PERSISTENT_ACTIVE_DOMAIN','RSEQ_CURRENT_DATA','PERSISTENT_RETAINED_TWO','PERSISTENT_DISPATCH') + macros
    if capture:
        macros = ('PERSISTENT_LOOP_EFFECTS_CAPTURE','PERSISTENT_LOOP_CAPTURE','PERSISTENT_DIRECT_FRONTIER_CAPTURE') + macros
    if differential:
        macros = ('MAPS_DIFFERENTIAL',) + macros
    if retained_counters:
        macros = ('PERSISTENT_LOOP_COUNTERS', 'PERSISTENT_RETAINED_TWO_COUNTERS', 'PERSISTENT_GROUP_COUNTERS') + macros
    name='bridge-persistent-loop-effects'+('' if mode=='release' else '-'+mode)+'.so'
    need(argv[-2:] == ['-o', str(output / name)] and [x for x in argv if x.endswith(('.c', '.S'))] == units and ([x for x in argv if x.startswith('-DLI2_')] == ['-DLI2_PERSISTENT_LOOP_EFFECTS=1','-DLI2_LOOP_EFFECTS=1','-DLI2_PG_LOOP_ENCODING_VERSION=2'] + ['-DLI2_' + n + '=1' for n in macros]) and all((x in argv for x in ('-O2', '-g', '-nostdlib', '-shared', '-fPIC', '-fvisibility=hidden', '-mgeneral-regs-only', '-fno-builtin', '-fno-tree-loop-distribute-patterns', '-fno-tree-vectorize', '-Wall', '-Wextra', '-Werror'))), 'exact effects13 no-FP recipe; original ordered TUs plus two effects TUs and optional codec')
    state = record['release_build'] = dict(status='failed', profile='persistent-loop-effects-'+mode+'-v1', recipe=fact(script), archive=fact(archive), argv=argv, persistent_binding=binding, capture=capture, qualification_credit=False)
    state['active_domain'] = dict(version=1, unregistered=True, subentry=True, cross_pair=True, direct_frontier=True, slots=2, same_source_pair=False, source_pairs_max=2, joint_receipts=3, directory_heads=256,
        maintained_rseq=True,differential=differential,native_probe=True,parse_memo=True,immutable_reconstruction='one-focal-policy12-lifetime-with-whole-source-choice-state-and-lossless-transcript' if capture else None)
    state['dispatch'] = dict(version=3, heads_min=1, heads_max=128, header_abi=2, shared_boundaries=8, code_pages=17, emitter_slot_bytes=512, emitter_boundaries=64)
    state['pf_refusals'] = dict(version=1,reason=256,shared_reasons=18,abi2=False)
    state['bounded_fused'] = dict(version=1,policy_version=11,heads_max=128,shared_boundaries=8,active_members_max=2,call_ret=False)
    state['bounded_loop'] = dict(version=1, policy_version=12, fallback_policy=11, encoding_domain=dict(version=2, policies=[11,12,13], near_record=1, far_record=2, miss='source-derived-rel32-or-rip-indirect-u64', literal_bytes=8, literal_boundaries=0, old_pf_api=False), header_version=2, chooser_version=12, decoder_read_version=2, heads_max=128, shared_boundaries=8, source_pages=2, active_members_max=2, call_ret=False, serialized_reconstruction=True, fallback='complete-source-bound-NO_ENVELOPE-only')
    state['direct_frontier'] = dict(version=1,policy_version=12,fallback_policy=11,encoding_domain=dict(version=2, policies=[11,12,13], near_record=1, far_record=2, miss='source-derived-rel32-or-rip-indirect-u64', literal_bytes=8, literal_boundaries=0, old_pf_api=False),partition='source-bound-loop-envelope-or-direction-fused',all_arms_directory=False,conditions=16,shared_boundaries=8,
        typed_external_arms=True,unknown_target='original branch-before full drain')
    state['bounded_loop']['effects']=dict(binding_version=1,policy_version=13,scalar_version=3,mov_version=2,selection_order=[12,13,11])
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
    required_group += tuple(n for n in EFFECTS_INPUTS if n.endswith(('.c','.h','.inc')))
    forbidden = {'persistent_plan.c', 'persistent_compact.c', 'persistent_lifetime.h', 'persistent_runtime.h', 'persistent_source.inc', 'persistent_rseq.inc', 'persistent_controller.inc', 'persistent_dynamic_controller.inc', 'persistent_dynamic_plan.h', 'persistent_dynamic_plan.inc', 'persistent_epoch_config.h', 'persistent_dynamic_capture_config.h', 'selected_scalar_span.inc', 'selected_scalar_span_reuse.inc', 'unrolled_hash_nested_fp.h'}
    counter_names = {'persistent_group_counters.h', 'persistent_loop_counters.h', 'persistent_loop_counters.inc', 'persistent_loop_counter_owner.inc'}
    need('persistent_group_counters.inc' not in names and names.intersection(counter_names) == (counter_names if retained_counters else set()), 'exact ABI3 counter bootstrap/header/event compiler closure only in explicit loop release diagnostic')
    observation_names = {'persistent_loop_effects_observe.h','persistent_loop_effects_observe.inc',
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
    fast_bytes_reconstruct(builder, output, pin, binary, aliases, run, state)
    need(digest(fact(archive)) == digest(binding['archive']) and fact(image) == binding['original']['image'] and all((fact(SELECTED / v['path']) == {k: v[k] for k in ('bytes', 'sha256')} for v in binding['sources'])) and all((fact(v['path']) == {k: v[k] for k in ('bytes', 'sha256')} for v in binding['header_paths'].values())) and (fact(binding['manifest']['path']) == {k: binding['manifest'][k] for k in ('bytes', 'sha256')}), 'archive, original image, full policy and configuration unchanged through build and byte oracle')
    if capture:
        need(all((fact(observation[key]['path']) == {k: observation[key][k] for k in ('bytes','sha256')} for key in ('script','header'))) and all((fact(path) == value for path,value in state['headers'].items())) and fact(script) == state['recipe'], 'actual capture selectors and complete compiler inputs unchanged through byte oracle')
    state['status'] = 'passed'
    return bridge

def inputs_completed(original,bridge,builder,private,pin,binary,run,r,application):
    """Exact no-DT_NEEDED fixture; no claim that its auxv jumper implements --list."""
    interp=pin(interpreter(original));roots=[original.parent]
    expected=application['interpreter']
    need(str(interp)==expected['path']and fact(interp)=={k:expected[k]for k in('bytes','sha256')}and
         namespace.parse(original.read_bytes())==dict(elf_type=2,needed=[],soname=None,interpreter=interp)and
         namespace.parse(interp.read_bytes())==dict(elf_type=3,needed=[],soname=None,interpreter=None),
         'whole exact fresh main/interpreter with two empty DT_NEEDED lists')
    objects,description=namespace.plan(original,roots,bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    need(objects==[],'exact namespace has no dependency objects')
    r['runtime_libraries']={interp.name:dict(path=str(interp),**fact(interp))}
    r['runtime_library_scope']='source_owned_no_needed_fixture; no dynamic-loader list command'
    r['namespace_plan']=description
    images,raws,known=[],[],{};directory=private/'external-inputs';need(directory.is_dir(), 'retained actual source-image directory')
    for role,path in [('original',original),('interpreter',interp)]:
        data=pin(path).read_bytes();identity=dict(bytes=len(data),sha256=H(data));need(fact(path)==identity,'complete independently retained ELF')
        if identity['sha256']in known:
            i=known[identity['sha256']];need(raws[i]==data,'duplicate content equality');images[i]['roles'].append(role);continue
        p=directory/(str(len(images))+'.elf')
        need(p.read_bytes()==data, 'whole retained source image equals authenticated original')
        need(fact(binary(p))==identity,'whole retained input copy');known[identity['sha256']]=len(images)
        images.append(dict(identity,roles=[role]));raws.append(data)
    need(len(images)==2,'distinct complete original and source-owned interpreter images')
    r['external_inputs']=images;carrier=private/'carrier'
    _,out,err=run('carrier',[builder.tools['python'],'-B',pin(SELECTED.parent/'carrier.py'),'make',original,bridge,carrier],profile='program')
    need(not err,'carrier construction stderr');binary(carrier);identity=json.loads(out)
    need(all(identity[k+'_sha256']==fact(p)['sha256']for k,p in(('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier)))and interpreter(carrier)==bridge,'whole actual carrier source identities')
    r['subject_artifacts']={k:fact(p)for k,p in(('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier))}
    return interp,roots,objects,description,images,raws,carrier
