"""Complete original callback record plus independently authenticated format trailer."""
import importlib.util
from pathlib import Path
def need(ok,why):
    if not ok:raise ValueError(why)
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def check(raw,layout,ref,boundary,profile):
    here=Path(__file__).resolve().parent
    old=load('b2_original_reader',here/'callback/read.py')
    fmt=load('b2_format',here/'xstate.py')
    need(set(layout)=={'b2_record','b2_row','b2_snapshot','layout','b2_format_record','b2_format_sample'},
         'exact original and additional actual DWARF layouts')
    n=layout['b2_record']['bytes'];need(n==1258752 and len(raw)==n+fmt.FORMAT_BYTES,
         'complete original record and complete separate format object')
    facts=fmt.trailer(raw[n:],{k:layout[k]for k in('b2_format_record','b2_format_sample')},profile)
    original_layout={k:layout[k]for k in('b2_record','b2_row','b2_snapshot','layout')}
    result=old.check(raw[:n],original_layout,ref,fmt.Boundary(boundary,facts))
    result.update(format=dict(pre_post_samples=2,extent=facts['extent'],mask=facts['mask'],
        signal_trailer_bytes=4,format_bytes=fmt.FORMAT_BYTES,raw_envelopes_preserved=True,
        architectural_bytes_excluded=0,general_host_guarantee=False))
    return result
