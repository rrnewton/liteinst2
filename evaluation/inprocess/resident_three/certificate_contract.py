"""Exact source-owned SBC variants over the unchanged installed NX/D3 contract."""
import json
from pathlib import Path
from page_selected import need

PROFILES = {'differential': (True, 0), 'release': (False, 0), 'stale': (True, 1), 'mirror': (True, 2), 'fd': (True, 3)}
EXTRA = ['sealed_byte_certificate.h','sealed_byte_certificate.inc','sealed_byte_certificate_observe.h',
         'sealed_byte_certificate_observe.inc','resident_three_flags_binding.py']
ADAPTERS = ('certificate_run.py','certificate_build.py','certificate_audit.py','certificate_semantics.py',
            'certificate_contract.py','certificate_identity.py','certificate_reports.py','certificate_baseline.py','certificate_owner.py')

def header_text(profile):
    need(profile in PROFILES, 'one exact fixed certificate header')
    differential,control=PROFILES[profile]
    return ('#ifndef LI2_SBC_EXPERIMENT_PROFILE_H\n#define LI2_SBC_EXPERIMENT_PROFILE_H\n'
            '#define LI2_SEALED_BYTE_CERTIFICATE 1\n#define LI2_SEALED_BYTE_CERTIFICATE_OBSERVE 1\n'+
            ('#define LI2_SEALED_BYTE_CERTIFICATE_DIFFERENTIAL 1\n' if differential else '')+
            '#define LI2_SEALED_BYTE_CERTIFICATE_CONTROL '+str(control)+'\n#endif\n')


def contract(here, profile, pin):
    need(profile in PROFILES, 'one fixed SBC variant, no implicit fallback')
    value=json.loads(pin(Path(here)/'CONTRACT.json').read_bytes())
    need(len(value['macros'])==50 and value['macros'][0]=='-DLI2_TF_NX_PAGE_BOUNDARY=1' and
         len(value['policy'])==102 and len(value['translation_units'])==28 and len(value['providers'])==99,
         'whole reviewed NX/D3 base counts and explicit feature order')
    value['policy']=[{'build-resident-three-flags.sh':'build-resident-three-certificate.sh',
                     'resident_three_flags_binding.py':'resident_three_certificate_binding.py'}.get(n,n)
                     for n in value['policy']] + EXTRA + ['certificate_profiles/'+profile+'.h']
    need(len(value['policy'])==len(set(value['policy']))==108,'all exact certificate policy members')
    for key in ('commands','compile_commands'):
        value[key].insert(value[key].index('dwarf')+1,'certificate-dwarf')
    value['profile']=profile
    value['differential'],value['control']=PROFILES[profile]
    value['header']='certificate_profiles/'+profile+'.h'
    return value
