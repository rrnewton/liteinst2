"""Test-only link, using the exact current committed archive and C recipe."""
import json,shlex
from pathlib import Path
from page_selected import fact,need
import page_selected_oneshot_build as production
import recipes

def link(builder,products,private,pin,binary,aliases,run,receipt):
    output=private/'failure-build';output.mkdir()
    plan=recipes.commands(builder.tools['cc'],products['archive'],output)
    pin(recipes.RECIPE)
    state=receipt['oneshot_build']=dict(status='failed',recipe=fact(recipes.RECIPE),
        argv=plan['link'],owner_argv=plan['owner'],archive=fact(products['archive']),
        translation_units=len(plan['product_sources'])+1,headers={})
    # All 16 actual product TUs plus the test TU are observed using their own
    # frontend arguments. Only the owner has four symbol-name definitions.
    need(len(plan['dependencies'])==17,'closed actual translation-unit cohort')
    for i,argv in enumerate(plan['dependencies']):
        _,out,err=run('failure-headers-'+str(i),argv,profile='metadata',env=builder.environment)
        prefix='li2_'+str(i)+':'
        rules=out.decode().replace('\\\n',' ').splitlines()
        need(not err and len(rules)==1 and rules[0].startswith(prefix+' '),'one complete actual include rule')
        seen={}
        for token in shlex.split(rules[0][len(prefix):]):
            p=pin(Path(token).absolute());seen[str(p)]=fact(p)
        need(str(Path(argv[-1]).resolve())in seen,'actual source in include closure')
        state['headers'][str(i)]=dict(argv=argv,files=seen)
    _,out,err=run('oneshot-archive-exports',[builder.tools['nm'],'-g','--defined-only',products['archive']],
                  profile='inspect',env=builder.environment)
    need(not err,'actual unchanged Rust contract archive')
    for name in production.EXPORTS:
        rows=[r.split()for r in out.splitlines()if r.split()[-1:]==[name.encode()]]
        need(len(rows)==1 and rows[0][-2:]==[b'T',name.encode()],'one actual Rust contract '+name)
    state['archive_exports']=list(production.EXPORTS)
    try:
        run('failure-owner-compile',plan['owner'],profile='build',env=builder.environment)
        binary(plan['outputs'][0])
        run('failure-bridge-link',plan['link'],profile='build',env=builder.environment)
    finally:
        state['output_prefix']={}
        for value in plan['outputs']:
            try:
                path=Path(value)
                if path.exists()or path.is_symlink():state['output_prefix'][path.name]=fact(binary(path))
            except BaseException as exc:receipt['final_errors'].append('partial failure bridge: '+type(exc).__name__+': '+str(exc))
    result=binary(plan['outputs'][1]);need(result.stat().st_mode&0o111,'actual executable derivative')
    state['status']='passed';return result

def layout(bridge,private,tools,pin,run,environment):
    env=dict(environment,XDG_CACHE_HOME=str(private/'gdb-cache'))
    (private/'gdb-cache').mkdir()
    _,out,err=run('failure-gdb-version',[tools['gdb'],'--version'],env=env)
    need(not err and out.startswith(b'GNU gdb'),'actual GDB metadata; no stderr exemption')
    _,out,err=run('failure-dwarf',[tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off',
        '-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),
        '-x',pin(recipes.HERE/'layout.py')],env=env)
    need(not err,'actual file-only DWARF output')
    return json.loads(out)
