#!/usr/bin/env python3
"""Publish the closed FAILED958 cohort without rerunning or reclassifying it."""
import argparse,ast,csv,hashlib,io,json,platform,subprocess
from pathlib import Path
from types import SimpleNamespace
import scalar_case_strings

REVISION='95883d7fedaa26c29c640648bb21aedb9136eee3'
STEM='20261030T105622.249164Z-scalar-region-reuse-owner-95883d7fedaa'
RECEIPT_SHA='50ffc4809f789ca1cc846f3208d2c013b773cd4e647ac30cd8ad09eea1351a46'
OWNER_SHA='28b5813ff33dd4065ca8955d22409c54d51bc8467bd043fe83d8d7c68d56d519'
MAPPING_SHA='548034aea0fdb6fae8c419f857876516329084a8946121734e955c3d63246581'
ROOT=Path(__file__).resolve().parents[2];HERE=ROOT/'evaluation/inprocess'
H=lambda b:hashlib.sha256(b).hexdigest()


def need(condition,message):
    if not condition:raise ValueError(message)


def fact(path):
    data=Path(path).read_bytes();return dict(bytes=len(data),sha256=H(data))


def git(*args):
    return subprocess.run(['git','-C',str(ROOT),*args],capture_output=True,check=True,timeout=10).stdout


def pure_functions(tree,names,namespace):
    nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name in names]
    need({node.name for node in nodes}==set(names),'all exact original pure functions')
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),
                 'authenticated-original-projection','exec'),namespace)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision',required=True)
    parser.add_argument('--receipt-sha256',required=True)
    supplied=parser.parse_args()
    need(supplied.expect_revision==REVISION and supplied.receipt_sha256==RECEIPT_SHA,'only the exact closed FAILED958 cohort')
    private=ROOT/'target/evaluation/inprocess'/STEM;path=private/'receipt.json'
    need(fact(path)==dict(bytes=10323476,sha256=RECEIPT_SHA),'unchanged whole closed private receipt')
    r=json.loads(path.read_bytes())
    need(r['expected_revision']==REVISION and r['status']=='failed'and r['error']=="KeyError: 'uho_owners'"and
         r['totals']['planned']==r['totals']['launched']==43 and r['totals']['qualified']==r['totals']['native']==13 and
         r['totals']['gated']==r['totals']['owner_controls']==r['totals']['qualified_pairs']==0 and
         r['source_unchanged']is True and r['cleanup_complete']is True and r['final_errors']==[],
         'retain exact failed population and closure without reader replay')
    original=git('show',REVISION+':evaluation/inprocess/scalar_region_owner.py')
    mapping=git('show',REVISION+':evaluation/inprocess/scalar_region_mapping_controls.py')
    need(H(original)==OWNER_SHA and H(mapping)==MAPPING_SHA,'exact original projection source bytes')
    ns=dict(ast=ast,csv=csv,hashlib=hashlib,io=io,json=json,platform=platform,Path=Path,
            ROOT=ROOT,HERE=HERE,H=H,need=need,fact=fact,private=private,r=r,
            pins=r['inputs'],artifacts=r['artifacts'],stem=STEM)
    tree=ast.parse(original)
    pure_functions(tree,('digest','expand_cases','case_projection'),ns)
    pure_functions(ast.parse(mapping),('public_summary',),ns)
    ns['mapping_controls']=SimpleNamespace(public_summary=ns['public_summary'])
    ns['args']=SimpleNamespace(expect_revision=REVISION,
        decoder_receipt=Path('evaluation/inprocess/results')/r['prerequisites']['decoder']['file'],
        component_receipt=Path('evaluation/inprocess/results')/r['prerequisites']['component']['file'])
    function=next(node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name=='main')
    final=next(node for node in function.body if isinstance(node,ast.Try)and node.finalbody).finalbody
    first=next(i for i,node in enumerate(final)if isinstance(node,ast.Assign)and
               isinstance(node.targets[0],ast.Name)and node.targets[0].id=='hw')
    last=next(i for i,node in enumerate(final)if isinstance(node,ast.Expr)and isinstance(node.value,ast.Call)and
              isinstance(node.value.func,ast.Name)and node.value.func.id=='need'and
              node.value.args[1].value=='compact public numerical result without private paths/host names')
    exec(compile(ast.fix_missing_locations(ast.Module(body=final[first:last],type_ignores=[])),
                 'authenticated-original-projection-only','exec'),ns)
    original_public=ns['encoded'];raw=ns['raw'];public=ns['public']
    need(len(original_public.encode())==38700 and len(raw)==2203,'original exact oversized JSON and unchanged CSV')
    denied=(str(ROOT),str(Path.home()),platform.node(),'/home/')
    need(not any(value and len(value)>1 and(value in original_public or value in raw.decode())for value in denied),
         'uncompressed public projection has no private paths or host names')
    exporter=Path(__file__).resolve();encoder=Path(scalar_case_strings.__file__).resolve()
    revision=git('rev-parse','HEAD').decode().strip()
    for source in(exporter,encoder):
        need(git('show',revision+':'+str(source.relative_to(ROOT)))==source.read_bytes(),'exact committed recovery implementation')
    public['publication_recovery']=dict(original_publication='failed_size_bound',original_json_bytes=38700,
        original_json_sha256=H(original_public.encode()),source_revision=revision,
        exporter=fact(exporter),encoder=fact(encoder),qualification_replayed=False,
        reproduce=['python3','-B','evaluation/inprocess/recover_scalar_reuse_958.py',
                   '--expect-revision',REVISION,'--receipt-sha256',RECEIPT_SHA])
    compact=scalar_case_strings.project(public)
    canonical=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
    encoded=canonical(compact)+'\n'
    need(canonical(scalar_case_strings.restore(json.loads(encoded)))==canonical(public),
         'complete canonical typed public inverse, all rows and failed outcomes retained')
    need(len(encoded.encode())<=32<<10 and len(raw)<=8192 and
         not any(value and len(value)>1 and(value in encoded or value in raw.decode())for value in denied),
         'original numerical publication bounds and privacy remain mandatory')
    need(fact(path)==dict(bytes=10323476,sha256=RECEIPT_SHA),'closed private receipt still byte-identical')
    output=HERE/'results'/(STEM+'.json');csv_output=HERE/'results'/(STEM+'.csv')
    need(not output.exists()and not csv_output.exists(),'no existing result overwritten')
    with csv_output.open('xb')as f:f.write(raw)
    with output.open('x')as f:f.write(encoded)
    print(json.dumps(dict(status='failed',qualified=13,qualification_replayed=False,
                          result=str(output.relative_to(ROOT)),json_bytes=len(encoded.encode()))))


if __name__=='__main__':main()
