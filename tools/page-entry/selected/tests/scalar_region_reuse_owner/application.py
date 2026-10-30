"""Only the three additional reuse controls; original application reader is unchanged."""
from pathlib import Path
import importlib.util
p=Path(__file__).resolve().parent.parent/'scalar_region_app'/'read.py'
s=importlib.util.spec_from_file_location('scalar_reuse_original_application',p)
old=importlib.util.module_from_spec(s);s.loader.exec_module(old)
need,MASK,FP,TF,RF=old.need,old.MASK,old.FP,old.TF,old.RF


def control_prefix(data,control,exit_status,layout,pid,cpu,seed_reference):
    need(type(control)is int and 15<=control<=17 and type(exit_status)is int and exit_status==125,
         'three distinct required completed-generation reuse refusals')
    return old._prefix(data,0,False,layout,pid,cpu,seed_reference)


def control_reference(native,gated,owner,control):
    """Actual native mode0 joins; all three additional outcomes remain refused125."""
    need(type(control)is int and 15<=control<=17 and owner['control']==control and
         native['header'][4:6]==(0,1) and gated['header'][4:6]==(0,0),
         'same actual mode0 hardware reference and required refusal')
    need(native['header'][8:19]==gated['header'][8:19] and native['hardware']==gated['hardware'] and
         all(native[k]==gated[k] for k in ('seed','source','stack','data')),
         'all actual control/reference input and hardware bytes')
    need(native['machine'][0]==gated['machine'][0]==MASK and native['machine'][3:]==gated['machine'][3:] and
         len(native['observations'])==1 and gated['suffix']is None,
         'actual control launch and no application completion')
    reference=native['observations'][0]['frames']
    def compare(actual,expected,observed_tls=True):
        need(type(actual['greg'])is tuple and len(actual['greg'])==23 and type(actual['fp'])is bytes and
             len(actual['fp'])==FP and actual['fp_bytes']==expected['header'][9] and actual['mask']==MASK,
             'complete typed actual control frame')
        want=list(expected['greg']);want[17]=(want[17]&~TF)|RF
        want[19],want[20],want[22]=21,14,want[16]
        need(actual['greg']==tuple(want) and actual['fp']==expected['fp'],
             'whole actual control GPR/flags/AF/FP joins original hardware reference')
        need((actual['fs'],actual['gs'])==(gated['machine'][1:3] if observed_tls else (0,0)),
             'actual observed TLS or source-exact pre-TLS empty fields')
    entries=owner['entries'];need(len(entries)==(0 if control==6 else 1),'all real focal control prefixes')
    if control==6:compare(owner['supplied_before'],reference[0],False)
    else:
        entry=entries[0];compare(entry['before'],reference[0])
        need(entry['source_page']==entry['terminal_source_page']==native['source'],'complete actual control source')
        for memory in (entry['before_memory'],entry['after_memory']):
            need(memory['data']==native['data'] and memory['stack']==native['stack'] and
                 memory['stack_observed']==bytes([1])*224,'complete actual control data/224stack observations')
        if control in (3,7):compare(entry['after'] if control==3 else entry['unexpected'],reference[1])
    return dict(native_entry_joins=1,native_endpoint_joins=int(control in (3,7)),
                completed_applications=0,required_owner_refusals=1)
