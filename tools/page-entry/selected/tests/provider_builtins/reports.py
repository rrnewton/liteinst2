"""Exact old report schemas plus separate configured builtin-prefix schema."""
import importlib.util
from pathlib import Path
from page_selected import need
import page_selected_rseq_compare as rseq

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
old=load('builtin_old_oneshot_reports',HERE.parent/'oneshot_integrated/reports.py')
completion=load('builtin_completion',HERE/'completion.py')
PROVIDER_KEYS=set('version status failure_code initialized attempts busy cpuid_completed rdrand_completed rdseed_completed rdpid_completed random_entered random_returned random_committed random_error cpuid_entered cpuid_returned cpuid_committed'.split())
BUILTIN_KEYS=set('version status failure_code first_error busy attempts rdtsc_completed rdtscp_completed syscall_replaced syscall_forwarded_returned clock_entered clock_returned clock_committed syscall_prepared syscall_entered syscall_returned syscall_pre_dispatch_guards_complete native_dispatch_entered raw_entered raw_returned replacement_selected dispatch_returned syscall_committed exit_selected'.split())

def reports(stderr,configured=True):
    need(type(stderr)is bytes and stderr.endswith(b'\n')and type(configured)is bool,'actual complete report input')
    lines=stderr[:-1].split(b'\n');provider=builtins=None
    if configured:
        need(len(lines)in(8,9)and lines[2].startswith(b'LI2_PROVIDER ')and lines[3].startswith(b'LI2_PROVIDER_BUILTINS ')and
             all(0<len(s)+1<=4096 for s in lines),'actual exact two configured report rows')
        provider=rseq.decode(lines[2][len(b'LI2_PROVIDER '):]);builtins=rseq.decode(lines[3][len(b'LI2_PROVIDER_BUILTINS '):])
        for row,keys,extra in((provider,PROVIDER_KEYS,{'scope','policy'}),(builtins,BUILTIN_KEYS,{'policy'})):
            need(type(row)is dict and set(row)==keys|extra and row['version']==1 and row['policy']=='deterministic-builtins-v1'and
                 all(type(row[k])is int and 0<=row[k]<1<<64 for k in keys),'closed typed configured report fields')
        need(provider['scope']=='configured_cpuid_random_id','actual shared immutable policy scope')
        lines=lines[:2]+lines[4:]
    parsed=old.reports(b'\n'.join(lines)+b'\n')
    if configured:
        need(all(row[k]==parsed['loader'][k]for row in(provider,builtins)for k in('status','failure_code')),'one actual terminal outcome across reports')
    return dict(parsed,provider=provider,builtins=builtins)


def check(parsed,pid,comparison,negative=0):
    configured=comparison['configured'];loader,native=parsed['loader'],parsed['native'];o=parsed['oneshot']
    need(type(pid)is int and pid>0 and comparison['negative']==negative,'actual process and finite case')
    if configured:
        expected=comparison['terminal_report'];need({k:parsed['builtins'][k]for k in BUILTIN_KEYS}==expected,
            'every actual builtin report field bound to complete raw observation')
        p=parsed['provider'];need(p['initialized']==1 and p['version']==1 and
            all(p[k]==0 for k in PROVIDER_KEYS-{'version','status','failure_code','initialized'}),
            'uninvoked random/CPUID provider remains unchanged in builtin fixture')
    else:need(parsed['provider']is None and parsed['builtins']is None,'explicit native policy has no configured report')
    need(loader['source_syscalls']==loader['syscalls']==comparison['syscall_attempts']and
         loader['forwarded']==comparison['native_syscalls_returned']+int(not negative)and
         loader['rdtsc']==comparison['clock_completed'][0]and loader['rdtscp']==comparison['clock_completed'][1]and
         loader['cpuid']==loader['rdrand']==loader['rdseed']==loader['rdpid']==0,'actual native/replacement/class counters stay distinct')
    need(o['owners']==o['published']==o['restored']==o['effect_started']==comparison['published'] and
         o['completed']==o['effect_returned']==comparison['completed']and
         o['active_phase']==(7 if comparison['published']>comparison['completed']else 0),
         'actual all-source restoration and honest incomplete/nonreturning owner prefix')
    need(parsed['rseq']['owner'][1:4]==[0,0,0]and loader['rseq']==0,'explicit unregistered fixture; no registration credit or fake unregister')
    if negative:
        need(loader['status']==125 and loader['failure_code']==comparison['terminal_report']['failure_code']and
             comparison['failed_operations']==1 and comparison['nonreturning_exit']==0,'qualified failed operation remains failed')
        return
    need(native['status']==native['failure_code']==native['epoch_error']==native['close_error']==native['close_busy']==0 and
         native['close_complete']==1 and 0<native['admissions']==native['closed']==loader['admissions']and
         loader['sync_core']==native['admissions']+native['closed']and native['first_admission_ns']>0,
         'complete genuine native admission/revocation; original guard unchanged')
    replaced=comparison['syscall_replacements']
    need(replaced==(4 if configured else 0),'exact four independently observed tagged replacements or explicit native control')
    completion.completed(loader,parsed['repeat'],parsed['run'],parsed['chain'],parsed['rseq'],pid,replaced)
    need(o['owners']==o['published']==o['restored']==o['effect_started']==8 and o['completed']==o['effect_returned']==7 and
         o['syscall_patches']==6 and o['rdtsc_patches']==2 and o['active_phase']==7,
         'eight actual restored publications, seven returned, genuine nonreturning exit')
    need(native['main_admissions']==16 and native['main_refaults']==0 and loader['source_syscalls']==10 and
         sum(comparison['clock_completed'])==6,'all actual main seed/capture native entries and complete fixed effects')
