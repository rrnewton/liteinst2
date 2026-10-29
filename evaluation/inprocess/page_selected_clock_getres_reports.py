"""Real default-rseq clock query refusal prefix; successful closures unchanged."""
from page_selected import need
from page_selected_repeat_lease_app_reports import reports
from page_selected_run_reuse_ls_reports import extensions
from page_selected_run_reuse_app_reports import gate
from page_selected_effect_ls_reports import trace_closed_counts
from page_selected_rseq_compare import observed_data
from page_late_dso_reports import check as completed,supplied_controls as completed_controls
U=(1<<64)-1

def refused(stderr,row,stdout,mode):
    need(mode in range(5,9)and row['exit']==125 and row['reaped']is True and not row['timed_out']and
         not row['error']and not row['cleanup_errors']and stdout==b'','actual pre-issue refusal process')
    p=reports(stderr);extensions(p);gate(p,row['pid'],125,row['stdout_provenance_before'],0)
    l,e,r=(p[k]for k in('loader','effect','rseq'))
    error,detail=(1208,1)if mode==8 else(1205,0)
    need((l['status'],l['failure_code'],l['detail_abs'],l['detail_negative'],l['last_syscall'])==(125,error,detail,0,229),
         'actual clock query guard failure, never an unsupported-call pass')
    owner=r['owner'];address=owner[9];word=address+8
    need(owner[:7]==[1,1,1,3,error,detail,0]and owner[7:9]==[row['pid']]*2 and
         0<address<=U-32 and address%32==0 and owner[10:]==[address&~4095,32,0x53053053,1],
         'actual held singleton registration identity and exact first error')
    need(r['counts'][:4]==[1,1,0,0]and r['transaction']==[1,1,1,0,0,0,1,0]and
         r['args'][:4]==[address,32,0,0x53053053]and r['tls'][:6]==[1,1,0,0,0,0]and r['tls'][6]>0 and
         r['identity'][0]==1 and r['identity'][1]>0 and r['identity'][2]>0,
         'completed real registration, zero word and retained mapping identity')
    need(observed_data(r['before'],owner,row['pid'])==observed_data(r['after'],owner,row['pid'])==r['identity'] and
         r['before'][:7]==r['after'][:7] and r['after'][26:]==[0,1] and r['after'][23]>r['before'][23] and
         r['after'][25]>r['before'][25] and r['after'][24]==r['before'][24],
         'unchanged full real registration query comparator and actual post-kernel invalidation')
    first=(word,word-15,word+7,U-15)[mode-5]
    need(r['last'][3:]==([0,0]if mode==8 else[first,first+16]),'exact optional16-byte span or before-range overflow')
    need(l['source_syscalls']==l['syscalls']==l['forwarded']+1,'one refused source syscall was never forwarded')
    expected=dict(first_error=0,stage=2,busy=1,finished=0,kind=7,action=1,phase=2,error=0,
        native_entered=0,native_returned=0,raw_entered=0,raw_returned=0,committed=0,
        callback_entered=0,callback_returned=0,exit_entered=0,post_guards_complete=0,
        post_callback_entered=0,post_callback_returned=0,random_backend_returned=0,
        random_backend_status=0,fp_after_initialized=0)
    need(all(type(e.get(k))is int and e[k]==v for k,v in expected.items()),'all actual pre-issue markers remain zero')
    need(e['sequence']==e['attempts']==e['completed']+1 and e['completed']==e['commits']==e['native_completed']and
         e['scripted_completed']==0 and sum(e['classes'])==e['completed']and e['classes'][6]==l['forwarded']and
         512<=e['fp_bytes']==e['fp_before_initialized']<=65536,'all earlier effects complete; actual refused frame has no result')
    return dict(case=mode,exit=125,error=error,detail=detail,write_bytes=16,overflow=mode==8,
        native_entered=0,raw_entered=0,raw_returned=0,registered=True,trace_run=trace_closed_counts(p['trace_run']))


def refusal_controls(stderr,row,stdout,mode):
    import json
    refused(stderr,row,stdout,mode)
    parts=[line.partition(b' ')for line in stderr.splitlines()]
    changes=(('LI2_SELECTED_EFFECT','native_entered',1),('LI2_SELECTED_EFFECT','raw_entered',1),
             ('LI2_SELECTED_EFFECT','raw_returned',1),('LI2_SELECTED_EFFECT','fp_after_initialized',1),
             ('LI2_RSEQ','last',None),('LI2_RSEQ','transaction',None))
    for name,key,value in changes:
        lines=[]
        for tag,sep,payload in parts:
            obj=json.loads(payload)
            if tag.decode()==name:
                if key=='last':obj[key][3]^=1
                elif key=='transaction':obj[key][2]=0
                else:obj[key]=value
            lines.append(tag+sep+json.dumps(obj,separators=(',',':')).encode())
        try:refused(b'\n'.join(lines)+b'\n',row,stdout,mode)
        except ValueError:pass
        else:raise ValueError('copied refusal marker accepted '+name+'.'+key)
    return len(changes)
