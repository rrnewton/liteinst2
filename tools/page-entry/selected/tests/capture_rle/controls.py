#!/usr/bin/env python3
"""Pure codec controls and one actual C-encoder output; no owner/native claim."""
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
from read import decode,encode_for_control,LIMIT,MAGIC,END

def need(value,message):
    if not value:raise ValueError(message)

def wrap(payload,n):
    body=64+len(payload)
    return struct.pack('<8Q',MAGIC,1,17,n,len(payload),64,64,0)+payload+struct.pack('<8Q',END,1,body,body,1,body,0,0)

def main():
    need(not sys.flags.optimize and len(sys.argv)==2,'assertions and exact C vector input')
    data=Path(sys.argv[1]).read_bytes()
    need(len(data)==794,'exact complete actual C canonical vector extent')
    original=bytes(i%251 if i%31<9 else 0x90 for i in range(1024))
    raw,receipt=decode(data,raw_bytes=1024,schema_version=17)
    need(type(raw)is memoryview and raw.readonly and raw.c_contiguous and
         raw.format=='B'and raw.ndim==1 and raw.nbytes==1024 and type(raw.obj)is bytearray,
         'one owned raw allocation exposed only as a read-only byte view')
    need(raw==original and receipt['body_write_calls']==1 and receipt['body_last_write']==receipt['body_bytes'],
         'whole independently expected actual C encoder vector and real write receipt')
    roundtrips=0
    for n in (1,7,8,9,127,128,129,65535,65536,65537):
        for raw in (bytes(n),bytes(i%256 for i in range(n)),bytes((i//8)%2 for i in range(n)),bytes(0x90 if i%9 else 0x42 for i in range(n))):
            encoded=encode_for_control(raw,schema_version=17)
            decoded,_=decode(encoded,raw_bytes=n,schema_version=17)
            need(type(decoded)is memoryview and decoded.readonly and decoded.nbytes==n and
                 decoded==raw,'whole independent roundtrip');roundtrips+=1
    refused=[]
    def reject(name,value,n=1024,message=None):
        try:decode(value,raw_bytes=n,schema_version=17)
        except ValueError as error:
            need(message is None or str(error)==message,'exact causal transport refusal');refused.append(name)
        else:raise ValueError('accepted '+name)
    for i in range(8):
        mutant=bytearray(data);struct.pack_into('<Q',mutant,8*i,struct.unpack_from('<Q',mutant,8*i)[0]^1)
        reject('header_'+str(i),bytes(mutant))
    for i in range(8):
        mutant=bytearray(data);at=len(data)-64+8*i;struct.pack_into('<Q',mutant,at,struct.unpack_from('<Q',mutant,at)[0]^1)
        reject('footer_'+str(i),bytes(mutant))
    for i in range(len(data)):reject('truncate_'+str(i),data[:i])
    reject('trailing',data+b'\0')
    reject('zero_packet',wrap(struct.pack('<BI',0,0),8),8)
    reject('unknown_tag',wrap(struct.pack('<BI',2,8)+b'a',8),8)
    reject('missing_header',wrap(b'\0',8),8)
    reject('short_literal',wrap(struct.pack('<BI',0,8)+b'a',8),8)
    reject('missing_run_value',wrap(struct.pack('<BI',1,8),8),8)
    reject('short_run',wrap(struct.pack('<BI',1,7)+b'a',7),7)
    reject('expansion',wrap(struct.pack('<BI',1,0xffffffff)+b'a',8),8)
    reject('missing_raw',wrap(struct.pack('<BI',1,8)+b'a',9),9)
    reject('literal_limit',wrap(struct.pack('<BI',0,65537)+bytes(i%251 for i in range(65537)),65537),65537)
    reject('split_run',wrap((struct.pack('<BI',1,8)+b'a')*2,16),16,'whole canonical packet encoding')
    reject('run_as_literal',wrap(struct.pack('<BI',0,16)+b'a'*16,16),16,'whole canonical packet encoding')
    reject('split_literal',wrap(struct.pack('<BI',0,2)+b'ab'+struct.pack('<BI',0,2)+b'cd',4),4,'whole canonical packet encoding')
    reject('strict_cap',b'\0'*LIMIT)
    # Semantic controls use decoded bytes and a synthetic canonical transport;
    # they must reach their original exact field error, never a codec error.
    semantic=[]
    for at in (0,len(original)-1):
        changed=bytearray(original);changed[at]^=1
        decoded,_=decode(encode_for_control(bytes(changed),schema_version=17),raw_bytes=len(original),schema_version=17)
        try:need(decoded==original,'whole example owner byte equality')
        except ValueError as error:need(str(error)=='whole example owner byte equality','exact semantic reachability');semantic.append(at)
        else:raise ValueError('accepted changed raw byte')
    need(roundtrips==40 and len(semantic)==2 and len(refused)==len(set(refused))==len(data)+30,'complete distinct codec controls')
    print(json.dumps(dict(scope='capture_codec_reader_only',roundtrips=roundtrips,transport_refusals=len(refused),
        truncations=len(data),semantic_reachability=2,cross_language_vectors=1,native_qualification=False),sort_keys=True))

if __name__=='__main__':main()
