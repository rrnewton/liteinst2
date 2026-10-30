"""Bounded actual metadata observations, separate from semantic reconstruction."""
import struct

REQUEST=0x315152534c49324c
RESPONSE=0x315352534c49324c
CAPACITY=65


def need(ok,why):
    if not ok:raise ValueError(why)


def requests(reader):
    """Extract bytes only; this is not an owner/plan acceptance predicate."""
    b=reader.data[:-64];owner=reader.field(b,'sro_wire','owner');queries=set()
    plans=[(reader.field(slot,'sr_slot','plan'),False) for slot in reader.items(owner,'scalar_owner','slots','sr_slot')
        if reader.integer(slot,'sr_slot','installed')]
    plans.append((reader.field(owner,'scalar_owner','scratch'),True))
    need(len(plans)<=CAPACITY,'bounded boundary observation input count')
    for p,scratch in plans:
        if not any(p):continue
        if reader.integer(p,'li2_region_plan','stop_reason')==1:
            page,pc=reader.values(p,'li2_region_plan','page boundary_pc')
        elif scratch and not reader.integer(p,'li2_region_plan','ready') and not reader.integer(p,'li2_region_plan','stop_reason'):
            page,entry,selected=reader.values(p,'li2_region_plan','page entry source_bytes');pc=entry+selected
            if pc==page+4096:continue # Planner stops before making a decoder call.
        else:continue
        need(page%4096==0 and page<=pc<page+4096,'bounded captured boundary source window')
        available=min(15,page+4096-pc);source=reader.field(p,'li2_region_plan','source')
        window=source[pc-page:pc-page+available]+bytes(16-available)
        queries.add(struct.pack('<QII16s',pc,available,0,window))
    rows=sorted(queries)
    return struct.pack('<4Q',REQUEST,1,len(rows),32)+b''.join(rows)


def observe(request,response):
    """Authenticate every returned row against the complete immutable request."""
    need(type(request)is bytes and len(request)>=32 and type(response)is bytes and len(response)>=128,
        'complete actual boundary metadata request/response')
    magic,version,n,width=struct.unpack_from('<4Q',request)
    need((magic,version,width)==(REQUEST,1,32) and n<=CAPACITY and len(request)==32+32*n,
        'exact fixed boundary request extent')
    need(struct.unpack_from('<4Q',response)==(RESPONSE,1,n,344) and len(response)==128+344*n,
        'exact complete boundary response extent')
    before,after=response[32:80],response[80:128]
    abi,phase,fatal,reserved,arena,high,alloc,free=struct.unpack('<4I4Q',before)
    need((abi,phase,fatal,reserved,arena)==(1,2,0,0,16*1024*1024) and 0<high<=arena and alloc>0 and before==after,
        'complete actual post-seal allocator tuple unchanged')
    result={}
    for i in range(n):
        q=request[32+32*i:64+32*i];at=128+344*i
        need(response[at:at+32]==q and response[at+32:at+40]==bytes(8),
            'actual successful decoder result and exact input row')
        pc,available,zero,window=struct.unpack('<QII16s',q)
        need(1<=available<=15 and zero==0 and window[available:]==bytes(16-available),
            'exact actual bounded decoder source')
        key=(pc,available,window)
        need(key not in result,'one actual observation per exact source window')
        row=response[at+40:at+344]
        need(row[0:8]==struct.pack('<Q',pc) and row[44:48]==struct.pack('<I',available) and row[56:72]==window,
            'whole decoder observation belongs to exact requested PC/window')
        result[key]=row
    return result
