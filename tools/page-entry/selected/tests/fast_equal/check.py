"""Pure strict reader for actual 4800-byte primitive records; no execution."""
import struct
LENGTHS=list(range(34))+[48,63,64,65,72,127,128,129,184,255,256,257,511,512,513,575,576,577,
    1023,1024,1025,2443,2444,2445,4095,4096,4097,8191,8192,8193,16383,16384,16385,
    32767,32768,32769,65535,65536]
def need(v,m):
    if not v:raise ValueError(m)
def mismatch_positions(n):
    if n<=33:return list(range(n))
    return sorted({p for p in (0,1,7,8,9,n//2,n//8*8-1,n//8*8,n-1)if p<n})
def expected_row(n):
    equal=243;unequal=4*81*len(mismatch_positions(n));extent=(n+8+4095)&~4095
    return [n,81,equal,unequal,(equal+unequal)*n,2*extent*81,7,18]
def parse(data,fast,measured):
    need(type(data)is bytes and len(data)==4800,'whole fixed record')
    need(type(fast)is bool and type(measured)is bool,'exact requested lanes')
    h=list(struct.unpack_from('<16Q',data))
    maps=148 if measured else 146
    expected=[0x314551464932494c,1,4800,int(fast),0,0,72,16,28,int(measured),
              8192 if measured else 0,8 if measured else 0,2444 if measured else 0,maps,maps,maps]
    need(h==expected,'complete actual coverage/cleanup/flags result; failed prefixes do not pass')
    for i,n in enumerate(LENGTHS):
        need(list(struct.unpack_from('<8Q',data,128+64*i))==expected_row(n),'full length/geometry/result/memory row '+str(i))
    times=list(struct.unpack_from('<8Q',data,4736))
    need(all(x>0 for x in times)if measured else times==[0]*8,'positive measured intervals or exact functional zero storage')
    return dict(lengths=72,placements=72*81,equal_calls=72*243,
                unequal_calls=sum(expected_row(n)[3]for n in LENGTHS),
                zero_length_guard_null_calls=16,overlap_calls=28,
                verified_image_bytes=sum(expected_row(n)[5]for n in LENGTHS),
                fast=fast,measured=measured,nanoseconds=times,
                scope='Actual immutable-range helper only; no owner/application speedup credit')
