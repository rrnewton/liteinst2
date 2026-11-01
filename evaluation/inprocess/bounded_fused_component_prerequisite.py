"""Whole standalone PF component custody joined to the finite owner's fresh archive."""
import os,re,shlex
from pathlib import Path
from page_selected import need,fact,ENV
from persistent_dynamic import digest
from direct_frontier_program import decode
from bounded_fusion_component import run as component
ROOT=Path(__file__).resolve().parents[2]
SELECTED=ROOT/'tools/page-entry/selected'


def fused_component_prerequisite(path,expected_sha256,r,pin,binary,archive):
    """Retain supplied-archive limits; require equality to the actual fresh owner archive."""
    path=pin(path)
    need(path.name=='receipt.json'and path.parent.parent==ROOT/'target/evaluation/inprocess'and
         re.fullmatch('[0-9a-f]{64}',expected_sha256)is not None and
         fact(path)['sha256']==expected_sha256,'explicit complete private PF component receipt')
    a=decode(path.read_bytes());directory=path.parent
    need(a['schema']==1 and a['profile']=='experimental-bounded-fused-component-v1'and
         a['status']=='components_passed'and a['source']==r['source']and a['revision']==r['revision']and
         a['cpu']==r['cpu']and a['hardware']==r['hardware']and a['bounds']==component.BOUNDS and
         a['source_unchanged']is True and a['inputs_unchanged']is True and a['cleanup_complete']is True and
         a['error']is None and a['final_errors']==[]and a['archive_builds']==0 and
         a['archive_source_provenance_verified']is False and a['generated_execution']==a['native_execution']==0 and
         a['owner_credit']is a['qualification_credit']is a['performance_credit']is False,
         'whole same-source same-CPU component; supplied archive gives no independent build or execution credit')
    for name,value in a['inputs'].items():
        p=pin(name);need(component.fact(p)==value,'whole actual PF component input and mode')
    for name,value in a['artifacts'].items():
        p=binary(name);need(p.is_relative_to(directory)and component.fact(p)==value,'whole private PF component artifact')
    for name,value in a['aliases'].items():need(str(pin(name))==value,'whole PF component alias closure')
    for name,value in a['loader_presence'].items():need(Path(name).exists()==value,'PF component loader configuration presence')
    need(component.fact(pin(component.__file__))==a['inputs'][str(Path(component.__file__).resolve())],
         'exact current source-owned PF component validator')
    need({k:a['archive'][k]for k in('bytes','sha256')}==fact(archive),
         'complete supplied component archive equals this actual fresh native41/PB/owner archive')
    schedule=['tool-'+n+'-dependencies'for n in('cc','nm','python','git')]
    for n in('cc1','collect2','as','ld'):schedule+=['resolve-'+n,'tool-'+n+'-dependencies']
    schedule+=['version-'+n for n in('cc','as','ld','nm','python','git')]
    schedule+=['link-'+n for n in component.LINK_NAMES]
    schedule+=['compiler-specs','archive-exports','bounded_fusion_plan-headers',
               'bounded_fusion_plan-build','bounded_fusion_plan-dependencies','bounded_fusion_plan-component']
    rows=a['commands'];need([x['name']for x in rows]==schedule and len(set(schedule))==len(schedule)==44,
         'entire original fixed44-command standalone PF component schedule')
    observed={}
    for row in rows:
        kind='component'if row['name']=='bounded_fusion_plan-component'else'build'
        need(row['expected_exit']==row['exit']==0 and row['bounds']==component.BOUNDS[kind]and
             row['capture_limit']==16<<20 and row['environment']==ENV and row['reaped']is True and
             row['timed_out']is False and row['error']is None and row['cleanup_errors']==[]and
             all(x['closed']is True for x in row['descriptors'])and set(row['captures'])=={'stdout','stderr'},
             'each original bounded component child succeeded and completely reaped')
        captures={}
        for key,value in row['captures'].items():
            p=pin(directory/value['file'])
            need(p.is_relative_to(directory)and fact(p)=={k:value[k]for k in('bytes','sha256')},
                 'whole actual component capture')
            captures[key]=p.read_bytes()
        record=pin(directory/(row['name']+'.json'))
        need(decode(record.read_bytes())==row,'whole retained original component command row')
        observed[row['name']]=captures
    need(set(a['components'])=={'bounded_fusion_plan'},'single complete PF component population')
    case=a['components']['bounded_fusion_plan'];declared=component.CASES['bounded_fusion_plan']
    fixture=SELECTED/'tests/bounded_fusion_plan';recipe=pin(fixture/'build.sh')
    need(case['status']=='passed'and case['recipe']==component.fact(recipe)and
         fact(recipe)['sha256']==declared['recipe_sha256']and
         case['diagnostic_only_additions']==['-save-temps=obj','-Wl,--trace'],
         'actual immutable component recipe and exact diagnostic additions')
    units=[str(SELECTED/x)for x in declared['units']]
    output=directory/'bounded_fusion_plan/component';argv=case['original_argv']
    archive_names=[x for x in argv if x.endswith('.a')]
    need(len(archive_names)==1 and archive_names[0]in a['inputs']and
         component.fact(pin(archive_names[0]))==a['archive'],'one whole prebound supplied archive path')
    source=recipe.read_text().replace('\\\n',' ')
    lines=[x.strip()for x in source.splitlines()if x.strip().startswith('"$cc_bin" ')]
    need(len(lines)==1,'one source-owned complete component compiler recipe')
    expanded=[]
    for word in shlex.split(lines[0]):
        for key,value in {'$cc_bin':a['tools']['cc'],'$fixture':fixture,'$selected':SELECTED,
                          '$archive':archive_names[0],
                          '$output':output}.items():
            need(value is not None,'retained actual component archive path');word=word.replace(key,str(value))
        need('$'not in word and '`'not in word,'closed exact compiler word');expanded.append(word)
    need(argv==expanded and [x for x in argv if x.endswith(('.c','.S'))]==units and
         len({Path(x).stem for x in units})==len(units)==9,
         'exact original ordered compiler recipe and nine distinct real translation-unit stems')
    commands={x['name']:x for x in rows}
    flags=[x for x in argv[1:-2]if x not in units and not x.endswith('.a')and not x.startswith(('-Wl,','-l'))]
    need(commands['bounded_fusion_plan-headers']['argv']==[a['tools']['cc'],*flags,'-M','-MT','call_component',*units]and
         commands['bounded_fusion_plan-build']['argv']==argv[:-2]+case['diagnostic_only_additions']+argv[-2:]and
         commands['bounded_fusion_plan-component']['argv']==[str(output)],
         'actual preprocessing/build/finite invocation join to the exact recipe')
    captures=observed['bounded_fusion_plan-headers'];rules=captures['stdout'].decode().replace('\\\n',' ').splitlines()
    need(not captures['stderr']and len(rules)==9 and all(x.startswith('call_component: ')for x in rules),
         'all nine actual compiler-M rules')
    headers={str(pin(x))for line in rules for x in shlex.split(line.split(':',1)[1])}
    need(headers==set(case['headers'])and
         {str(pin(x))for x in units}|{str(pin(SELECTED/x))for x in declared['headers']}<=headers,
         'complete actual headers including both unchanged model C bodies and separate wrappers')
    trace=observed['bounded_fusion_plan-build'];need(not trace['stderr'],'strict original compiler warnings remain fatal')
    linked={str(Path(x).resolve(strict=True))for x in trace['stdout'].decode().splitlines()}
    need(linked==set(case['link_inputs'])and len(linked)>9 and
         all(str((output.parent/('component-'+Path(p).stem+'.o')).resolve())in linked for p in units),
         'complete actual link trace contains every distinct generated object')
    for p in units:
        for suffix in('.i','.s','.o','.su'):
            name=output.parent/('component-'+Path(p).stem+suffix)
            need(component.fact(binary(name))==a['artifacts'][str(name)],'whole real preprocessed/assembly/object/stack-use artifact')
    need(component.fact(binary(output))==case['binary']and component.elf(output)==case['elf'],
         'actual component executable and complete ELF identity')
    for name,value in case['runtime_objects'].items():need(component.elf(pin(name))==value,'actual full component loader object identity')
    for name,objects in a['tool_runtime'].items():
        for object_path,value in objects.items():need(component.elf(pin(object_path))==value,'whole actual compiler/tool runtime object identity')
    final=observed['bounded_fusion_plan-component']
    need(component.component_result(final['stdout'],final['stderr'])==case['result'],
         'original independent literal14/10/14/60 and full typed-model result gate')
    return dict(file=str(path.relative_to(ROOT)),**fact(path),status=a['status'],profile=a['profile'],
        archive=fact(archive),commands=len(rows),commands_sha256=digest(rows),result=case['result'],
        supplied_archive_provenance=False,fresh_owner_archive_bytes_joined=True,
        emitted_execution=0,owner_credit=False,qualification_credit=False,performance_credit=False)
