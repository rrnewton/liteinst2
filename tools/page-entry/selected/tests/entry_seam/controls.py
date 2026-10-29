"""Supplied violating bytes only; these never count as additional native events."""

def refusals(data,layout,mode,pid,cpu,image,boundary,xstate,reader):
    root=layout['types']['eso_record']['fields'];cases=[]
    def pos(field,sub=None,kind=None,offset=0):
        at=root[field]['offset']
        if sub is not None:at+=layout['types'][kind]['fields'][sub]['offset']
        return at+offset
    def flip(label,at):
        reader.need(type(at)is int and 0<=at<len(data),'mutation inside retained full record')
        cases.append((label,at))
    flip('source identity',pos('source_file_offset'))
    flip('literal source page',pos('pages',offset=image['entry_file_offset']%4096))
    flip('full saved GPR',pos('saved','gpr','eso_saved'))
    flip('saved inactive FP payload',pos('saved','fp','eso_saved',offset=400))
    flip('independent live ZMM seed',pos('seed_fp',offset=160))
    flip('complete original stack',pos('stacks',offset=(2<<20)))
    flip('same session PID',pos('session','pid','li2_step_session'))
    flip('terminal outcome',pos('status'))
    flip('clock prefix',pos('timing','clock_complete','entry_timing'))
    flip('complete source generation',pos('page','generation','li2_lifecycle_page_view'))
    if mode==1:
        flip('invented first NX',pos('nx','complete','eso_frame'))
        flip('invented restore return',pos('saved',offset=layout['types']['eso_saved']['bytes']))
    else:
        fp=pos('nx','fp','eso_frame')
        flip('exact signal xfeatures',fp+479)
        flip('whole original signal UC',pos('nx','uc','eso_frame',offset=layout['offsets']['greg']))
        flip('independent MOV result',pos('trace','uc','eso_frame',offset=layout['offsets']['greg']+8*8))
        flip('real release',pos('released','held','li2_fetch_progress'))
        flip('whole owner after FP',pos('owner','after','li2_step_owner',offset=layout['types']['li2_step_frame']['fields']['fp']['offset']+400))
        flip('original owner request',pos('owner','request','li2_step_owner',offset=0))
        flip('pre-helper actual base',pos('fs_endpoint'))
        if mode==0:
            flip('post-helper raw UC',pos('returned','uc','eso_frame',offset=layout['offsets']['greg']))
            flip('post-helper FP',pos('returned','fp','eso_frame',offset=400))
            flip('post-helper whole stack',pos('stacks',offset=5*(2<<20)))
            flip('post-helper actual base',pos('fs_returned'))
        else:
            flip('invented helper return',pos('returned','complete','eso_frame'))
    if mode==3:flip('genuine interruption PID',pos('nested','info','eso_frame',offset=layout['offsets']['siginfo_pid']))
    cases.append(('truncated complete record',None));cases.append(('unparsed suffix',-1))
    for label,at in cases:
        if at is None:changed=data[:-1]
        elif at==-1:changed=data+b'\0'
        else:
            value=bytearray(data);value[at]^=1;changed=bytes(value);del value
        try:reader.check(changed,layout,mode,pid,cpu,image,boundary,xstate)
        except ValueError:pass
        else:raise ValueError('violating supplied record accepted: '+label)
    return dict(kind='supplied_record_mutations',refused=len(cases),names=[x[0]for x in cases],native_events=0)
