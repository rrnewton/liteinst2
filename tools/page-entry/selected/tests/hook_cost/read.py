"""Unchanged complete correctness reader, plus a separate timing record."""
import importlib.util
from pathlib import Path
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def need(ok,why):
    if not ok:raise ValueError(why)
def check(raw,layout,ref,boundary,profile,mode=0):
    here=Path(__file__).parent;timing=load('hc_timing_reader',here/'timing.py')
    old_keys={'b2_record','b2_row','b2_snapshot','layout','b2_format_record','b2_format_sample'}
    need(set(layout)==old_keys|{'hc_record','hc_row'},'complete original plus actual timing layout')
    if mode==0:
        need(len(raw)==1258752+3536+timing.BYTES,'whole unchanged correctness prefix and timing record')
        result=load('hc_original_full_reader',here/'original_read.py').check(raw[:-timing.BYTES],{k:layout[k]for k in old_keys},ref,boundary,profile)
        part=raw[-timing.BYTES:]
    else:
        need(mode==1 and len(raw)==timing.BYTES+3536,'whole timing record and unchanged format trailer')
        load('hc_actual_format',here/'xstate.py').trailer(raw[timing.BYTES:],{k:layout[k]for k in('b2_format_record','b2_format_sample')},profile)
        part=raw[:timing.BYTES];result={}
    observed=timing.check(part,{k:layout[k]for k in('hc_record','hc_row')},ref,profile,mode)
    if mode:return observed
    result['timing_observation']=observed;result['timing_is_performance_sample']=False;return result
