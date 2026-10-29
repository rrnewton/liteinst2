"""Exact Code1720 register transitions; supplied control tuples only."""
import hashlib,struct
from page_selected import need
ENCODINGS=('62f1754074c7', '62b1754074c0', '62b1754074c9', '62b17d4074c8', '62b1754174c8')
FAMILIES=('vpcmpeqb_memory', 'vpcmpeqb_memory_family', 'vmovdqu128', 'vmovdqu128_family', 'vmovdqu128_store', 'strrchr_short')
def promotions(data,family):
    need(type(data)is bytes and len(data)==1216 and family in FAMILIES,'complete fixed register-promotion trailer/profile')
    indices=(0,1,2,3)if family=='strrchr_short'else(42,)
    values=ENCODINGS[1:]if family=='strrchr_short'else ENCODINGS[:1]
    need(struct.unpack_from('<8Q',data)==(0x315052455056324c,1,1216,len(indices),len(indices),0,0,0),
         'every exact old row attempted and completed')
    for i,(index,h)in enumerate(zip(indices,values,strict=True)):
        at=64+288*i
        need(struct.unpack_from('<5Q',data,at)==(index,1,0,0,1),'exact source index and successful typed/query result')
        need(data[at+40:at+56]==bytes.fromhex(h)+bytes(10),'complete exact old encoding and zero tail')
        need(struct.unpack_from('<2Q6I',data,at+56)==(0x1000,0x1006,1,1,1720,6,1,6),'exact Code1720 fallthrough SIMD authority')
        need(struct.unpack_from('<18Q',data,at+96)==tuple(0x1234000+16*j for j in range(16))+(0,0),'complete literal supplied register tuple')
        need(struct.unpack_from('<4Q4I',data,at+240)==(0x1000,0x1006,0,0,1,1,1720,6),'complete Code1720 NONE footprint')
    need(not any(data[64+288*len(indices):]),'whole unused row capacity zero')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),typed_promotions=len(indices),supplied_none_queries=len(indices),scope='Supplied old-byte controls; native state belongs to separate mandatory family pairs.')
