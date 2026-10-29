"""Exact old Code2791 promotions; no invented actual-before frame."""
import hashlib,struct
from page_selected import need
INDICES=(0,1,2,3,4,5,6,7,11,12)
ENCODINGS=('62b2764026c9', '62b2764026f9', '62b2764026c0', '62b2764026c2', '62b27e4026c1', '62b26e4026c1', '62f2764026c1', '62b2764826c1', '62b2764126c1', '62b2764726c1')
FAMILIES=('vptestnmb','vpcmpb','vptestmb','vpxorq128','bzhi','vptestnmb_family')
def promotions(data,family):
    need(type(data)is bytes and len(data)==3232 and family in FAMILIES,'complete fixed promotion trailer/profile')
    indices=INDICES+(101,)if family in('vptestmb','vptestnmb_family')else INDICES
    encodings=ENCODINGS+(ENCODINGS[8],)if len(indices)==11 else ENCODINGS
    need(struct.unpack_from('<8Q',data)==(0x31504d4e5456324c,1,3232,len(indices),len(indices),0,0,0),
         'every fixed old row attempted and completed separately')
    for i,(index,hexadecimal)in enumerate(zip(indices,encodings,strict=True)):
        at=64+288*i;b=bytes.fromhex(hexadecimal)
        need(struct.unpack_from('<5Q',data,at)==(index,1,0,0,1),'exact old row and successful typed/query observations')
        need(data[at+40:at+56]==b+bytes(10),'exact retained encoding and zero unused source capacity')
        need(struct.unpack_from('<2Q6I',data,at+56)==(0x1000,0x1006,1,1,2791,6,1,6),
             'mandatory exact Code2791 positive fallthrough SIMD classification')
        need(struct.unpack_from('<18Q',data,at+96)==tuple(0x1234000+16*j for j in range(16))+(0,0),
             'exact declared supplied GPR/FS/GS tuple')
        need(struct.unpack_from('<4Q4I',data,at+240)==(0x1000,0x1006,0,0,1,1,2791,6),
             'mandatory exact Code2791 NONE footprint')
    need(not any(data[64+288*len(indices):]),'whole unused row remains zero')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),typed_promotions=len(indices),
                supplied_none_queries=len(indices),scope='Supplied exact old-byte controls; native pairs are separately required.')
