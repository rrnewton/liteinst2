#!/usr/bin/env python3
"""Original twenty-two programs plus ten actual canonical REP STOSQ programs."""
import json
import struct
import sys
sys.dont_write_bytecode=True
import page_selected_generic as base
import page_selected_embedded as embedded
import page_selected_repeat_compare as repeat

NAMES=['repeat_'+str(n)+'_df'+str(d) for n in (0,1,3) for d in (0,1)]+[
    'repeat_cross','repeat_next_page','repeat_reuse','repeat_write_fault']


def check(spec,row,owner,command,stdout,native,before,after,decoded,original,observe,run):
    result=repeat.check(spec,row,owner,command,stdout,native,original.read_bytes())
    base.need(before['cpu']==after['cpu'] and before['aux']==after['aux'] and before['cpuid0']==after['cpuid0'] and
              before['tsc']<after['tsc'],'closed actual pinned hardware bracket')
    rows={item['name']:item for item in spec['rows']}
    last=[rows[n] for n in spec['executed'] if rows[n]['route']=='generic'][-1]
    code=bytes.fromhex(last['bytes'])
    base.need(row['tf_pc']==last['pc'] and row['tf_length']==len(code) and
              (row['tf_bytes_lo'],row['tf_bytes_hi'])==struct.unpack('<QQ',code.ljust(16,b'\0')) and
              decoded['pc']==last['pc'] and decoded['length']==len(code) and decoded['decode_status']==0 and
              decoded['kind']==0 and decoded['code']==row['tf_code'],'actual retained completed generic request')
    item=[rows[n] for n in spec['executed'] if rows[n]['route']=='repeat'][-1]
    _,out,err=run('decode-last-repeat-'+spec['name'],[observe,'decode',str(item['pc']),item['bytes']])
    base.need(not err,'native REP decoder observer stderr')
    d=json.loads(out)
    base.need(d['pc']==item['pc'] and d['next_pc']==item['pc']+3 and d['abi']==1 and d['decode_status']==0 and
              d['length']==3 and d['kind']==0 and d['code']==346 and d['step_disposition']==8,
              'independent canonical REP decode and unchanged old classifier refusal')
    return result


def publish(path,receipt,private,aliases):
    embedded.publish(path,receipt,private,aliases,repeat=True)


if __name__=='__main__':
    raise SystemExit(base.main(embedded=True,repeat=True))
