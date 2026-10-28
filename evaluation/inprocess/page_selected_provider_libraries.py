"""Closed actual provider DT_NEEDED graph joined to the retained loader listing."""
import importlib.util
import os
import re
from pathlib import Path
from page_selected import fact,need


def libraries(root,executable,interpreter,output,link_inputs,pin):
    # Reuse the existing bounded ELF parser, including its rejection of search,
    # audit and filter policies. No approximate ld.so search is performed here.
    path=pin(Path(root)/'tools/page-entry/namespace.py')
    spec=importlib.util.spec_from_file_location('provider_link_namespace',path)
    namespace=importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace)
    main=namespace.parse(Path(executable).read_bytes())
    interpreter=pin(interpreter);loader=namespace.parse(interpreter.read_bytes())
    need(main['elf_type']==2 and main['interpreter']is not None and
         pin(main['interpreter'])==interpreter,'actual provider PT_INTERP identity')
    need(loader['elf_type']==3 and loader['interpreter']is None and
         loader['soname']is not None,'actual unchained provider interpreter SONAME')
    runtime_names={'libc.so.6','libgcc_s.so.1'}
    need(loader['soname']not in runtime_names,'distinct interpreter SONAME')
    allowed=runtime_names|{loader['soname']}
    rows={};infos={};vdso=0
    for line in output.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):vdso+=1;continue
        match=re.fullmatch(r'\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'closed actual provider loader dependency row')
        name=match[1];alias=match[2];target=pin(alias)
        if name is None or name.startswith('/'):
            need(target==interpreter and(name is None or pin(name)==interpreter),'actual provider interpreter aliases')
            name=loader['soname']
        need(name in allowed and name not in rows,'unique known provider loader object')
        info=namespace.parse(target.read_bytes())
        need(info['elf_type']==3 and info['soname']==name,'actual dependency SONAME/type')
        if name==loader['soname']:need(target==interpreter,'actual needed interpreter identity')
        else:
            selected=link_inputs.get(name)
            need(selected is not None and pin(selected['path'])==target and
                 fact(target)=={k:selected[k]for k in ('bytes','sha256')},'compiler-selected runtime dependency '+name)
        if info['interpreter']is not None:
            need(pin(info['interpreter'])==interpreter,'dependency descriptive PT_INTERP identity')
        need(str(target)not in {r['path']for r in rows.values()},'distinct provider object paths')
        rows[name]=dict(alias=alias,path=str(target),needed=info['needed'],**fact(target));infos[name]=info
    need(vdso==1 and loader['soname']in rows and 'libc.so.6'in rows,'complete actual libc/interpreter listing')
    need(infos[loader['soname']]==loader,'listed interpreter metadata identity')
    # Every DT_NEEDED edge must resolve once, and every listed object must be
    # reachable from the executable or its actual interpreter. Extra objects,
    # missing transitive edges and unsupported SONAMEs cannot be normalized away.
    pending=list(main['needed'])+list(loader['needed']);seen={loader['soname']};at=0
    while at<len(pending):
        name=pending[at];at+=1
        need(name in allowed and name in rows,'every actual provider DT_NEEDED edge resolves')
        if name in seen:continue
        seen.add(name);pending.extend(infos[name]['needed'])
    need(seen==set(rows),'exact reachable provider loader object set')
    return dict(executable=dict(**fact(executable),needed=main['needed']),
                interpreter_soname=loader['soname'],objects=rows,vdso_rows=vdso)
