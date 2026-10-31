"""Pure receipt-join checks; only the caller's final closure grants eligibility."""
import copy
import hashlib
import json
from page_selected import need

PROFILE='linked-preedge-full-v2'
BINDING=('version','archive','policy_sha256','header')
CUT_TOTALS=dict(planned=3,launched=3,qualified=3,native_fault_reference=1,gated_data_fault=1,
    gated_revoke_failure=1,qualified_pairs=1,application_reader_refusals=82,
    terminal_reader_refusals=106,owner_reader_refusals=109,pair_reader_refusals=6)
FULL_TOTALS=dict(planned=26,hardware_planned=25,metadata_qualified=1,launched=26,qualified=26,
    native=7,gated=7,owner_controls=4,qualified_pairs=7,completed_applications=10,
    required_read_faults=2,required_reference_faults=2,required_owner_refusals=4,
    application_reader_refusals=234,terminal_reader_refusals=5464,owner_reader_refusals=477,
    required_refault_refusals=4,pair_reader_refusals=4,refault_reader_refusals=187,
    actual_refault_witnesses=1,required_hint_rejections=3,hint_owner_reader_refusals=366,
    hint_terminal_reader_refusals=738,actual_hint_witnesses=1,
    preedge_owner_reader_refusals=199,preedge_terminal_reader_refusals=54)
CONTROL_NAMES=('missing_cut_receipt','wrong_cut_profile','failed_cut_cohort','stale_source',
    'wrong_cpu','wrong_hardware','different_archive','different_policy','different_binding_header',
    'substituted_private_receipt','helper_cannot_grant_eligibility')
CONTROL_COUNT=11


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def project(actual):
    """Compact actual metadata, read only after the unchanged strict prerequisite."""
    value={k:actual[k]for k in('profile','status','source','expected_revision','cpu','hardware','totals')}
    value['archive']={k:actual['build']['artifacts']['decoder.a'][k]for k in('bytes','sha256')}
    value['binding']={k:actual['release_build']['linked_binding'][k]for k in BINDING}
    return value


def cut_join(r,primitive,cut,actual,public_fact,private_fact):
    """Additional joins only; never a substitute for the strict cut3 reader."""
    need(type(cut)is dict and type(actual)is dict and cut and actual,'required actual cut-failure receipt')
    need(cut['profile']==actual['profile']=='linked-preedge-cut-failure-v2','exact cut-failure profile')
    need(cut['status']==actual['status']=='passed'and
         digest(cut['totals'])==digest(actual['totals'])==digest(CUT_TOTALS),'all three cut failures qualified')
    need(digest(actual['source'])==digest(r['source'])and
         actual['expected_revision']==r['expected_revision']==r['source']['revision'],
         'cut-failure exact current source')
    need(type(actual['cpu'])is int and type(r['cpu'])is int and actual['cpu']==r['cpu'],
         'cut-failure same reserved CPU')
    need(digest(actual['hardware'])==digest(r['hardware']),'cut-failure same actual hardware')
    need(digest(cut['archive'])==digest(actual['archive'])==digest(primitive['archive'])and
         all(digest(v['binding']['archive'])==digest(cut['archive'])for v in(cut,actual,primitive)),
         'cut-failure same actual decoder archive')
    need(all(type(v['binding']['version'])is int and v['binding']['version']==1 for v in(cut,actual,primitive))and
         len({v['binding']['policy_sha256']for v in(cut,actual,primitive)})==1,
         'cut-failure same immutable policy')
    need(digest(cut['binding']['header'])==digest(actual['binding']['header'])==digest(primitive['binding']['header']),
         'cut-failure same actual binding header')
    need(digest({k:cut[k]for k in('bytes','sha256')})==digest(public_fact)and
         digest(cut['private_receipt'])==digest(private_fact),'cut-failure exact retained receipt digests')
    need(cut['whole_profile_qualified']is False and primitive['whole_profile_qualified']is False,
         'individual prerequisite helpers cannot grant full-profile eligibility')


def metadata_digest(r,primitive,cut,actual,public_fact,private_fact):
    expected={k:r[k]for k in('source','expected_revision','cpu','hardware')}
    return digest([expected,primitive,cut,actual,public_fact,private_fact])


def controls(r,primitive,cut,actual,public_fact,private_fact):
    """Scoped supplied metadata refusals; no reader replay or native operations."""
    cut_join(r,primitive,cut,actual,public_fact,private_fact)
    trials=[]
    def add(name,error,change):
        c,a=copy.deepcopy(cut),copy.deepcopy(actual);change(c,a);trials.append((name,error,c,a))
    trials.append(('missing_cut_receipt','required actual cut-failure receipt',None,actual))
    add('wrong_cut_profile','exact cut-failure profile',lambda c,a:(c.update(profile='linked-preedge-finite-v2'),a.update(profile='linked-preedge-finite-v2')))
    add('failed_cut_cohort','all three cut failures qualified',lambda c,a:(c.update(status='failed'),a.update(status='failed')))
    def stale(c,a):a['source']['revision']='0'*40 if a['source']['revision']!='0'*40 else '1'*40
    add('stale_source','cut-failure exact current source',stale)
    add('wrong_cpu','cut-failure same reserved CPU',lambda c,a:a.update(cpu=a['cpu']+1))
    def hardware(c,a):a['hardware']['probe_cpu']+=1
    add('wrong_hardware','cut-failure same actual hardware',hardware)
    def archive(c,a):
        value=dict(c['archive'],bytes=c['archive']['bytes']+1)
        for row in(c,a):row['archive']=value;row['binding']['archive']=value
    add('different_archive','cut-failure same actual decoder archive',archive)
    def policy(c,a):
        value='0'*64 if c['binding']['policy_sha256']!='0'*64 else '1'*64
        for row in(c,a):row['binding']['policy_sha256']=value
    add('different_policy','cut-failure same immutable policy',policy)
    def header(c,a):
        value=dict(c['binding']['header'],bytes=c['binding']['header']['bytes']+1)
        for row in(c,a):row['binding']['header']=value
    add('different_binding_header','cut-failure same actual binding header',header)
    add('substituted_private_receipt','cut-failure exact retained receipt digests',lambda c,a:c['private_receipt'].update(bytes=c['private_receipt']['bytes']+1))
    add('helper_cannot_grant_eligibility','individual prerequisite helpers cannot grant full-profile eligibility',lambda c,a:c.update(whole_profile_qualified=True))
    refused=[]
    for name,error,c,a in trials:
        need(digest([c,a])!=digest([cut,actual]),'actual eligibility metadata mutation')
        try:cut_join(r,primitive,c,a,public_fact,private_fact)
        except ValueError as exc:need(str(exc)==error,'exact eligibility metadata refusal '+name);refused.append(name)
        else:raise ValueError('accepted supplied eligibility metadata '+name)
    need(tuple(refused)==CONTROL_NAMES and len(refused)==CONTROL_COUNT,'complete separate eligibility metadata controls')
    return dict(refusals=refused,native_operations=0,original_metadata_sha256=metadata_digest(r,primitive,cut,actual,public_fact,private_fact))


def complete(r,primitive,cut,actual,public_fact,private_fact):
    """Called only after the complete existing finalizer; returns no ready flag."""
    cut_join(r,primitive,cut,actual,public_fact,private_fact)
    need(r['profile']==PROFILE and r['status']=='passed'and r['error']is None and r['final_errors']==[]and
         r['source_unchanged']is True and r['cleanup_complete']is True and
         digest(r['source_after'])==digest(r['source'])and
         all(digest(r[a])==digest(r[b])for a,b in(('inputs_before','inputs_after'),
             ('artifacts_before','artifacts_after'),('aliases_before','aliases_after'))),
         'full-profile final source artifact and process closure')
    need(digest(r['totals'])==digest(FULL_TOTALS)and r['cohort_complete']is True and
         r['reuse_cohort']['cohort_complete']is True and r['linked_metadata']['status']=='passed'and
         r['seed_prerequisite']['status']=='passed','all original26 and old plus typed controls qualified')
    need(primitive['profile']=='linked-preedge-finite-v2'and primitive['status']=='passed'and
         primitive['totals']['planned']==primitive['totals']['qualified']==9,
         'full-profile actual primitive9 prerequisite')
    for state in(r,r['reuse_cohort']):
        release=state['release_build'];binding={k:release['linked_binding'][k]for k in BINDING}
        need(release['status']==state['application_build']['status']=='passed'and
             digest(release['archive'])==digest(primitive['archive'])and
             digest(binding)==digest(primitive['binding'])==digest(cut['binding']),
             'full-profile both actual capture builds join all prerequisite authority')
    value=r['eligibility_controls']
    need(type(value['refusals'])is list and tuple(value['refusals'])==CONTROL_NAMES and
         type(value['native_operations'])is int and value['native_operations']==0 and
         value['original_metadata_sha256']==metadata_digest(r,primitive,cut,actual,public_fact,private_fact),
         'full-profile exact separate metadata refusal ledger')
