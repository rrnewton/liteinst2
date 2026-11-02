"""Independent lossless transport reader; no raw-owner or native qualification.

raw_bytes/schema_version MUST come from the separately authenticated complete
C schema and actual DWARF, never from the incoming header. No field is omitted
or normalized. The returned receipt concerns real encoded body writes only.
The raw return is a read-only memoryview over one owned bytearray, not a second
whole-raw bytes copy. Callers must preserve that owner and use bounded views.
"""
import re
import struct

LIMIT=4<<20
HEADER=FOOTER=64
MAGIC=0x314838454c52324c
END=0x314638454c52324c
VERSION=1
LITERAL=65536
RUN=8
# A fixed one-byte class searches the existing buffer; no raw-sized temporary
# or repetition/backtracking stack is needed. Hex escapes cover all 256 bytes.
_DIFFERENT=tuple(re.compile(rb'[^\x%02x]'%value)for value in range(256))

def need(value,message):
    if not value:raise ValueError(message)

def _run(raw,at):
    end=at+1
    if type(at)is int and (type(raw)is bytes or type(raw)is bytearray or
        (type(raw)is memoryview and raw.ndim==1 and raw.itemsize==1 and
         raw.format=='B'and raw.c_contiguous)):
        size=len(raw)
        if 0<=at<size:
            if end==size or raw[end]!=raw[at]:return 1
            match=_DIFFERENT[raw[at]].search(raw,end,size)
            return (size if match is None else match.start())-at
    # Preserve scalar behavior for other sequences, views and unusual offsets.
    while end<len(raw)and raw[end]==raw[at]:end+=1
    return end-at

def _packets(raw):
    at=0
    while at<len(raw):
        start=at;n=_run(raw,at)
        if n>=RUN:
            yield struct.pack('<BI',1,n),bytes((raw[at],));at+=n
        else:
            at+=n
            while at<len(raw)and at-start<LITERAL:
                n=_run(raw,at)
                if n>=RUN:break
                at+=min(n,LITERAL-(at-start))
            yield struct.pack('<BI',0,at-start),raw[start:at]

def decode(data,*,raw_bytes,schema_version):
    need(type(raw_bytes)is int and 0<raw_bytes<1<<32 and
         type(schema_version)is int and 0<schema_version<1<<64,'independent exact raw schema bound')
    need(type(data)is bytes and HEADER+FOOTER<=len(data)<LIMIT,'complete strict4MiB transport bound')
    h=struct.unpack_from('<8Q',data)
    need(h[:4]==(MAGIC,VERSION,schema_version,raw_bytes)and
         h[5:]==(HEADER,FOOTER,0),'exact distinct lossless transport header')
    size=h[4];body=HEADER+size
    need(size>0 and body+FOOTER==len(data),'exact encoded payload and no trailing bytes')
    footer=struct.unpack_from('<8Q',data,body)
    need(footer[:4]==(END,VERSION,body,body)and 1<=footer[4]<=64 and
         0<footer[5]<=body and footer[6:]==(0,0),'actual complete encoded-body write footer')
    need((footer[4]==1 and footer[5]==body)or
         (footer[4]>1 and footer[4]-1<=body-footer[5]),'actual positive body partial-write geometry')
    # Header equality above precedes this one exact bounded allocation.
    out=bytearray(raw_bytes);at=HEADER;used=0
    while at<body:
        need(body-at>=5,'complete packet header')
        tag,n=struct.unpack_from('<BI',data,at);at+=5
        need(n>0 and n<=raw_bytes-used,'bounded nonempty packet expansion')
        if tag==0:
            need(n<=LITERAL and n<=body-at,'complete bounded literal packet')
            out[used:used+n]=data[at:at+n];at+=n
        else:
            need(tag==1 and n>=RUN and at<body,'complete canonical run packet')
            block=data[at:at+1]*min(n,LITERAL);at+=1
            filled=0
            while filled<n:
                k=min(len(block),n-filled);out[used+filled:used+filled+k]=block[:k];filled+=k
        used+=n
    need(at==body and used==raw_bytes,'whole exact raw expansion')
    # Streaming canonical comparison has only bounded literal temporaries. It
    # rejects alternate partitions, never substitutes an equivalent encoding.
    at=HEADER
    for prefix,payload in _packets(out):
        for part in (prefix,payload):
            need(len(part)<=body-at and data[at:at+len(part)]==part,'whole canonical packet encoding')
            at+=len(part)
    need(at==body,'complete canonical payload')
    return memoryview(out).toreadonly(),dict(schema_version=schema_version,raw_bytes=raw_bytes,
        payload_bytes=size,body_bytes=body,stream_bytes=len(data),
        body_write_calls=footer[4],body_last_write=footer[5],status=footer[6],code=footer[7])

def encode_for_control(raw,*,schema_version):
    """Synthetic reader-control transport only: never evidence of real writes.

    Mutate the whole decoded raw object, then use this to reach its original
    semantic predicate. New transport refusals are counted separately.
    """
    need(type(raw)is bytes and 0<len(raw)<1<<32 and
         type(schema_version)is int and 0<schema_version<1<<64,'synthetic exact raw control input')
    payload=bytearray()
    for prefix,part in _packets(raw):
        need(HEADER+len(payload)+len(prefix)+len(part)+FOOTER<LIMIT,'synthetic strict4MiB transport bound')
        payload+=prefix;payload+=part
    h=struct.pack('<8Q',MAGIC,VERSION,schema_version,len(raw),len(payload),HEADER,FOOTER,0)
    n=len(h)+len(payload)
    return h+bytes(payload)+struct.pack('<8Q',END,VERSION,n,n,1,n,0,0)
