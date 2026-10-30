"""Explicit certificate/reuse release comparison; same fixed82 process owner.

No CURRENT_TF composition. All five old qualifications plus the complete
certificate43/transaction8 receipt are mandatory on the exact revision/CPU.
"""
from pathlib import Path
from page_selected import need,fact
from page_cost_compare import digest
import scalar_reuse_performance as reuse
import scalar_region_owner as qualification
import scalar_reuse_certificate_profile as profile
import scalar_region_mapping_controls as mapping

ROOT,HERE=reuse.ROOT,reuse.HERE
LANES=('unrolled','certificate-reuse','differential','native','dynamorio')
ORDER=tuple((kind,repeat,'certificate-reuse'if lane=='scalar-reuse'else lane)
            for kind,repeat,lane in reuse.ORDER)
NAMES=tuple(f'{kind}-{repeat}-{lane}'for kind,repeat,lane in ORDER)
REQUIRED=reuse.REQUIRED|{
    'evaluation/inprocess/scalar_reuse_certificate_performance.py',
    'evaluation/inprocess/scalar_reuse_certificate_performance_reports.py',
    'evaluation/inprocess/scalar_reuse_certificate_profile.py',
    'evaluation/inprocess/scalar_reuse_certificate_reports.py',
    'evaluation/inprocess/scalar_reuse_certificate_mapping.py',
    'evaluation/inprocess/scalar_region_reuse_certificate_build.py',
    'tools/page-entry/selected/build-scalar-region-reuse-certificate.sh',
    'tools/page-entry/selected/region_reuse_certificate.h',
    'tools/page-entry/selected/selected_scalar_reuse_certificate.inc',
    'tools/page-entry/selected/rseq_region_live.h',
    'tools/page-entry/selected/rseq_region_live.inc',
    'tools/page-entry/selected/scalar_reuse_certificate_observe.h',
    'tools/page-entry/selected/scalar_reuse_certificate_observe.inc',
    *('tools/page-entry/selected/tests/scalar_region_reuse_certificate_owner/'+name
      for name in('read.py','certificate.py','wire.py','layout.py')),
    *('tools/page-entry/selected/tests/reuse_certificate/'+name
      for name in('oracle.c','build.sh','check.py'))}


def arguments(a):
    reuse.arguments(a)
    need(a.certificate_owner_receipt is not None,'complete certificate owner qualification is required')
    path=a.certificate_owner_receipt.resolve(strict=True).relative_to(ROOT)
    need(path.parent==Path('evaluation/inprocess/results')and path.suffix=='.json',
         'certificate qualification public receipt inside evaluation results')
    a.certificate_owner_receipt=path


def reproduce(a):
    return ['--reuse-certificate',*reuse.reproduce(a)[1:],
            '--certificate-owner-receipt',str(a.certificate_owner_receipt)]


def named(value,key,count):
    names=value[key]
    need(type(names)is list and all(type(name)is str for name in names)and
         len(names)==len(set(names))==count and type(value['native_operations'])is int and
         value['native_operations']==0,'exact actual supplied refusal names and no native work')


def prerequisites(a,r,pin,binary):
    reuse.prerequisites(a,r,pin,binary)
    public,actual=reuse.closed(a.certificate_owner_receipt,r,pin,binary)
    need(public['profile']==actual['profile']=='scalar-region-reuse-certificate-owner-v1'and
         public['status']==actual['status']=='passed'and actual['reuse']is True and actual['certificate']is True,
         'distinct complete actual certificate/reuse owner qualification')
    expected=dict(planned=43,launched=43,qualified=43,native=13,gated=13,owner_controls=17,qualified_pairs=13,
        completed_applications=14,required_read_faults=6,required_reference_faults=6,required_owner_refusals=17,
        application_reader_refusals=348,terminal_reader_refusals=1964,owner_reader_refusals=4102,
        boundary_metadata_commands=38,certificate_owner_reader_refusals=998,
        certificate_terminal_reader_refusals=450,certificate_mapping_reader_refusals=160)
    need(digest(actual['totals'])==digest(expected)and
         digest(actual['bounds'])==digest(dict(qualification.BOUNDS,certificate_component=profile.COMPONENT_BOUNDS))and
         actual['build']['decoder_features']==['scalar-region'],
         'all43 exact cases, all old/additive controls and unchanged owner/component bounds')
    profile.complete(actual)
    need(digest(actual['prerequisites']['decoder'])==digest(r['prerequisites']['region_decoder'])and
         digest(actual['prerequisites']['component'])==digest(r['prerequisites']['region_component']),
         'certificate owner used these same actual decoder8 and scalar-component11 receipts')
    cases=actual['cases'];commands={c['name']:c for c in actual['commands']}
    need([(c['lane'],c['mode'],c['control'])for c in cases]==list(qualification.REUSE_ORDER)and
         all(c['launched']is True and type(c['exit'])is int and
             c['exit']==c['expected_exit']==(125 if c['control']or 5<=c['mode']<=10 else 0)and
             c['status']==('qualified_native_reference'if c['lane']=='native'else
                 'qualified_required_owner_refusal'if c['control']else
                 'qualified_required_read_failure'if 5<=c['mode']<=10 else 'qualified_application')for c in cases),
         'all unchanged43 actual subjects with the required completion or refusal outcome')
    need(digest(actual['required_owner_reader_controls'])==digest({str(m)+':'+str(c):n
         for (m,c),n in sorted(qualification.REUSE_CONTROL_COUNTS.items())})and
         digest(actual['required_certificate_reader_controls'])==digest({str(m)+':'+str(c):n
         for (m,c),n in sorted(profile.CERTIFICATE_CONTROL_COUNTS.items())}),
         'exact old4102 and additional998 control tables')
    fields=('label','lane','mode','control','expected_exit','status','launched','exit','whole_process_ns','timed_out',
            'captures','pair','owner_summary','control_reference','boundary_observation','error_type')
    rows=[]
    for c in cases:
        row={k:c[k]for k in fields if k in c};owner=c.get('owner_reader_controls',{});terminal=c.get('terminal_controls',{})
        row.update(terminal_control_count=len(terminal.get('refusals',[])),terminal_controls_sha256=digest(terminal),
            application_control_count=c.get('application_controls',{}).get('supplied_refusals',0),
            owner_control_count=len(owner.get('refusals',[])),owner_controls_sha256=digest(owner))
        rows.append(row)
        if c['lane']!='gated':continue
        key=(c['mode'],c['control']);command=commands[c['label']]
        named(owner,'refusals',qualification.REUSE_CONTROL_COUNTS[key])
        named(owner,'certificate_refusals',profile.CERTIFICATE_CONTROL_COUNTS[key])
        named(terminal,'refusals',67 if c['exit']==0 else 65)
        named(terminal,'certificate_refusals',15)
        need(owner['original_sha256']==command['captures']['record']['sha256']and
             terminal['original_stderr_sha256']==command['captures']['stderr']['sha256'],
             'all actual old/new owner and terminal controls bind the exact captured subject')
    need(digest(qualification.expand_cases(public))==digest(rows),
         'every original public case field/type/presence equals the actual certificate row')
    need(sum(row['application_control_count']for row in rows)==348,
         'all original application supplied controls retained independently')
    state=actual['mapping_controls']
    need(state['planned']==8 and state['status']=='passed'and len(state['cases'])==8 and
         [c['name']for c in state['cases']]==[c[0]for c in mapping.CASES]and
         digest(public['mapping_controls'])==digest(mapping.public_summary(state)),
         'all eight original mapping outcomes and complete exact public projection')
    for c,spec in zip(state['cases'],mapping.CASES,strict=True):
        need(c['status']=='qualified_mapping_refusal'and c['launched']is True and c['exit']==125 and
             c['failure_code']==spec[-1]and c['reader_refusals']==19 and c['completed_applications']==0 and
             c['generated_owner_credit']is False and c['boundary_observation']['exit']==0,
             'actual v3 mapping refusal retains old19 controls and metadata child without execution credit')
        named(c['certificate_controls'],'certificate_refusals',20)
        need(c['certificate_controls']['original_sha256']==commands['subject-mapping-'+c['name']]['captures']['record']['sha256'],
             'additional mapping mutations bind the actual whole v3 capture')
    guard=actual['mapping_guard_summary'];seed=actual['seed_prerequisite']
    need(digest(guard)==digest(public['mapping_guard_oracle'])and guard['status']=='passed_predicate_only'and
         guard['exit']==0 and digest(guard['result'])==digest(dict(version=1,predicate_only=1,cases=754,
         allowed=273,refused=481,live_rseq=0,live_owner=0))and seed['status']=='passed'and
         seed['launched']is True and seed['exit']==0 and seed['bounds']==[5,512<<20,16<<20,15],
         'all754 predicate cases and independent actual same-CPU seed remain mandatory')
    component=actual['certificate_component']
    need(digest(public['certificate_component'])==digest(profile.component_summary(component))and
         type(component['planned'])is int and component['planned']==8 and
         digest(component['bounds'])==digest(profile.COMPONENT_BOUNDS)and
         component['build']['status']=='passed'and component['supplied_boundary']is True and
         component['native_owner_credit']is False and component['performance_credit']is False,
         'complete separately counted transaction component, without owner or performance credit')
    for mode,c in enumerate(component['cases']):
        command=commands['certificate-component-mode-'+str(mode)]
        need(type(c['mode'])is int and c['mode']==mode and c['launched']is True and
             c['status']==('qualified_transaction'if mode<3 else 'qualified_required_transaction_failure')and
             c['expected_exit']==c['exit']==command['exit']==profile.COMPONENT_EXITS[mode]and
             command['profile']=='certificate_component'and command['bounds']==profile.COMPONENT_BOUNDS and
             digest(c['reader_controls'])==digest(dict(refusals=32,native_operations=0))and
             c['result']['mode']==mode and c['result']['component_only']==1 and c['result']['supplied_boundary']==1,
             'all eight actual scoped transactions and256 exact supplied refusals')
    built=actual['release_build'];binding=built['certificate_binding']
    need(built['status']=='passed'and 'capture_config'in built and
         '-DLI2_SCALAR_REGION_REUSE_CERTIFICATE=1'in built['argv']and
         '-DLI2_SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE=1'in built['argv']and
         '-DLI2_MAPS_CURRENT_TF=1'not in built['argv']and
         digest({k:component['build']['binding'][k]for k in('version','archive','policy','policy_inputs','header')})==
             digest({k:binding[k]for k in('version','archive','policy','policy_inputs','header')})and
         actual['nested_emission']['status']=='passed'and actual['owner_layout']['bridge']==built['bridge'],
         'actual certificate capture ELF, whole nested shim and one production archive/policy binding')
    r['prerequisites']['certificate_owner']=dict(file=a.certificate_owner_receipt.name,**fact(pin(a.certificate_owner_receipt)),
        private_receipt=public['private_receipt'],profile=actual['profile'],status='passed',totals=expected,
        transaction_component=profile.component_summary(component),commands=len(actual['commands']),
        commands_sha256=digest(actual['commands']),mapping_refusals=8,mapping_reader_refusals=152,
        certificate_mapping_refusals=160,predicate_cases=754,
        binding={k:binding[k]for k in('version','archive','policy','header')},
        policy_inputs_sha256=digest(binding['policy_inputs']))


def cohort(builder,products,private,pin,binary,aliases,run,r,a,builders):
    return reuse.cohort(builder,products,private,pin,binary,aliases,run,r,a,builders,certificate=True)


def publish(path,r,private):
    return reuse.publish(path,r,private,certificate=True)
