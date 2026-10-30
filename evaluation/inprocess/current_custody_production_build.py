"""Production19-TU unrolled bridge with maintained-view custody; no capture."""
import shutil
from pathlib import Path
from maps_view import (need,fact,SELECTED,UNITS,MACROS,recipe,expand,headers,bridge_check,
    ENV,hidden_memset,body_check)
from unrolled_hash_build import capture_config
import maps_current_extents as extents


def observe_storage(builder,bridge,pin,binary,run,state):
    headers=state['headers']
    need(all(str((SELECTED/name).resolve())in headers for name in
        ('maps_current_ticket.h','maps_current_ticket.inc','fetch_current_view.h',
         'fetch_current_view.inc','fetch_current_custody.h','fetch_current_custody.inc')),
         'all current-custody source seams observed by actual compiler')
    need(not any(str((SELECTED/name).resolve())in headers for name in
         ('current_tf_observe.h','current_tf_observe.inc','current_tf_observe_lifecycle.inc')),
         'production bridge has no current fixture capture')
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(SELECTED/'tests/current_custody/extents.py')
    _,out,err=run('current-storage-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off',
        '-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err,'file-only complete actual storage layout without diagnostics')
    layout=extents.decode(out);proof=extents.check(bridge,layout,headers);controls=extents.controls(bridge,layout,headers)
    need(proof['symbols']==9 and proof['compiled_only']==1 and len(controls['refusals'])==44,
         'all nine actual complete bridge extents and44 supplied refusals')
    state.update(storage=proof,storage_controls=controls,storage_observation=layout)


def build_bridge(builder,products,private,pin,binary,aliases,run,r,extra,capture_image=None):
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},'fresh Build.prepare owns this exact archive')
    need(extra in (('MAPS_CURRENT_TF',),('MAPS_CURRENT_TF','MAPS_DIFFERENTIAL')),
         'one explicit current or every-hit differential current production profile')
    need(capture_image is None,'no fixture or capture configuration in production current profile')
    output=private/'release';output.mkdir();config=capture_config(capture_image,output,pin,binary)if capture_image is not None else None
    bridge_recipe=pin(SELECTED/'build-unrolled-hash.sh');rows=recipe(bridge_recipe,'"$cc_bin"')
    need(len(rows)==1,'one explicit bounded unrolled release link recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,
        '$parent_dir':SELECTED.parent,'$archive':archive,'$output':output})
    argv[1:1]=['-DLI2_'+x+'=1'for x in extra];units=[str(SELECTED.parent/x)for x in UNITS]+[str(SELECTED/'unrolled_hash_plan.c')]
    need(argv[-2:]==['-o',str(output/'bridge-unrolled-hash.so')]and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in extra+('UNROLLED_HASH','MAPS_MAINTAINED')+MACROS]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact19-TU unrolled release recipe and explicitly selected diagnostic macros')
    state=r['release_build']=dict(status='failed',recipe=fact(bridge_recipe),archive=fact(archive),argv=argv,capture_config=config)
    headers('release-bridge-headers',argv,units,archive,builder,pin,aliases,run,state)
    need(all(str((SELECTED/name).resolve())in state['headers']for name in
         ('maps_phase.inc','maps_view.inc','selected_unrolled_hash.inc','unrolled_hash.h',
          'unrolled_source.inc','unrolled_source.h','rseq_unrolled.inc')),
         'compiler observes all maintained-view and actual unrolled owner seams')
    need((str((SELECTED/'unrolled_hash_observe.inc').resolve())in state['headers'])==(config is not None),
         'compiler observes capture adapter only in capture profile')
    if config is not None:need(state['headers'].get(config['path'])==config['header'],'actual compiler observes exact ELF-derived capture header')
    bridge=Path(argv[-1]);run('release-bridge-link',argv,profile='release_build',env=builder.environment)
    state['bridge']=fact(binary(bridge));state['elf']=bridge_check(bridge)
    _,out,err=run('release-bridge-undefined',[builder.tools['nm'],'-u',bridge],profile='inspect',env=builder.environment)
    need(out==err==b'','actual effect bridge has no unresolved imports')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('release-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual objdump identity')
    _,symbols,err=run('release-bridge-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset symbol inspection')
    _,assembly,err=run('release-bridge-memset',[objdump,'-d','-w','-M','att','--disassemble=memset',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset disassembly');state['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
    observe_storage(builder,bridge,pin,binary,run,state)
    state['status']='passed';return bridge
