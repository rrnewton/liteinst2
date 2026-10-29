"""Exact Code3676 register transitions; supplied control tuples only."""
import hashlib,struct
from page_selected import need
ENCODINGS=('c4e2c0f3d6','c4e2c8f3d7')
FAMILIES=('strrchr_short',)
def promotions(data,family):
    need(type(data)is bytes and len(data)==640 and family in FAMILIES,'complete fixed register-promotion trailer/profile')
    indices=(15,16)
    values=ENCODINGS
    need(struct.unpack_from('<8Q',data)==(0x3150524d4950324c,1,640,len(indices),len(indices),0,0,0),
         'every exact old row attempted and completed')
    for i,(index,h)in enumerate(zip(indices,values,strict=True)):
        at=64+288*i
        need(struct.unpack_from('<5Q',data,at)==(index,1,0,0,1),'exact source index and successful typed/query result')
        need(data[at+40:at+56]==bytes.fromhex(h)+bytes(11),'complete exact old encoding and zero tail')
        need(struct.unpack_from('<2Q6I',data,at+56)==(0x1000,0x1005,1,1,3676,5,1,1),'exact Code3676 fallthrough INTEGER authority')
        need(struct.unpack_from('<18Q',data,at+96)==tuple(0x1234000+16*j for j in range(16))+(0,0),'complete literal supplied register tuple')
        need(struct.unpack_from('<4Q4I',data,at+240)==(0x1000,0x1005,0,0,1,1,3676,5),'complete Code3676 NONE footprint')
    need(not any(data[64+288*len(indices):]),'whole unused row capacity zero')
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),typed_promotions=len(indices),supplied_none_queries=len(indices),scope='Supplied old-byte controls; native state belongs to separate mandatory family pairs.')
