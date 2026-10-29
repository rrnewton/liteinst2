"""Replay the trusted pre-exec FD construction; no filesystem queries here."""
import os,stat,struct
from page_selected import need


def check(actual,route,layout):
    need(type(actual)is dict and actual['route']==route and actual['status']=='passed'and actual['error']is None and
         actual['cleanup_errors']==[],'complete actual parent FD preparation and cleanup')
    identity=actual['identity'];keys={'device','inode','mode','flags','size','offset'}
    need(set(identity)==keys and all(type(identity[k])is int and identity[k]>=0 for k in keys-{'offset'})and
         (identity['offset']is None or type(identity['offset'])is int and identity['offset']==0),
         'typed complete actual capture FD identity/initial position')
    need(actual['major']==os.major(identity['device'])and actual['minor']==os.minor(identity['device'])and
         type(actual['mount_id'])is int and (actual['mount_id']==0 if route=='memfd'else actual['mount_id']>0),
         'actual retained memfd zero or ordinary positive mount-ID/device components')
    calls=actual['calls'];need(type(calls)is list and all(type(x)is dict and 'error'not in x for x in calls),'complete actual FD construction calls')
    opened=[];closed=[];alive=set()
    for row in calls:
        name=row['name']
        if name in('open','open_path','open_directory','memfd'):
            fd=row['fd'];need(type(fd)is int and fd>3 and fd not in alive,'actual owned capture FD');opened.append(fd);alive.add(fd)
        elif name=='pipe':
            for fd in(row['read_fd'],row['write_fd']):
                need(type(fd)is int and fd>3 and fd not in alive,'two actual owned pipe FDs');opened.append(fd);alive.add(fd)
        elif name=='same_ofd_dup':
            fd=row['result_fd'];need(row['source_fd']in alive and row['command']==1030 and type(fd)is int and fd>=16 and fd not in alive,
                 'actual F_DUPFD_CLOEXEC from owned source');opened.append(fd);alive.add(fd)
        elif name=='close':
            need(row['fd']in alive and row['result']==0,'actual each owned descriptor closes once');closed.append(row['fd']);alive.remove(row['fd'])
        elif name in('query','get_subvol_info'):
            need(type(row['fd'])is int and row['fd']in alive,'actual query observes an owned live descriptor')
        elif name=='dup2':
            need(type(row['source_fd'])is int and row['source_fd']in alive and type(row['result_fd'])is int and
                 row['result_fd']==1,'actual live owned descriptor installed as inherited FD1')
        else:need(False,'no unbound launch operation')
    need(len(opened)==len(closed)and not alive,'complete actual parent descriptor closure')
    # O_PATH deliberately closes then reopens, and the kernel may reuse its FD.
    # Its per-call lifetime is checked separately rather than inferred from a
    # numeric descriptor having never appeared earlier.
    expected={'normal':['open','query','query','dup2','close'],
              'subvolume':['open','query','query','get_subvol_info','dup2','close'],
              'dup':['open','query','query','same_ofd_dup','dup2','close','close'],
              'opath':['open','close','open_path','query','query','dup2','close'],
              'directory':['open_directory','query','query','dup2','close'],
              'pipe':['pipe','query','query','dup2','close','close'],
              'memfd':['memfd','query','query','dup2','close']}[route]
    need([x['name']for x in calls]==expected,'exact finite parent open/query/dup/close route')
    query=[x for x in calls if x['name']=='query'];need([x['number']for x in query]==[138,332]and
        [x['bytes']for x in query]==[120,256]and all(x['result']==x['errno']==0 for x in query),
        'actual successful full statfs/statx queries')
    origin=[x for x in calls if x['name']in('open','open_path','open_directory','pipe','memfd')][-1]
    need(origin['identity']==identity and query[0]['fd']==origin.get('fd',origin.get('write_fd')),
         'actual opened object identity owns both complete raw queries')
    fs=bytes.fromhex(query[0]['raw']);sx=bytes.fromhex(query[1]['raw']);need(len(fs)==120 and len(sx)==256,'complete retained raw query buffers')
    fields=layout['types']['statx']['fields']
    def val(key):
        f=fields[key];return int.from_bytes(sx[f['offset']:f['offset']+f['bytes']],'little')
    need(val('stx_mask')&0x1103==0x1103 and not val('stx_mask')&0x4000 and
         (val('stx_ino'),val('stx_mode'),val('stx_dev_major'),val('stx_dev_minor'),val('stx_mnt_id'))==
         (identity['inode'],identity['mode'],actual['major'],actual['minor'],actual['mount_id'])and
         int.from_bytes(fs[:8],'little')==actual['filesystem_type'],'complete actual FD stat/statx/statfs joins')
    regular=route in('normal','subvolume','dup','opath','memfd')
    need(stat.S_ISREG(identity['mode'])if regular else stat.S_ISDIR(identity['mode'])if route=='directory'else stat.S_ISFIFO(identity['mode']),
         'actual finite capture object type')
    need(bool(identity['flags']&os.O_PATH)==(route=='opath'),'actual normal-open/O_PATH distinction')
    if regular:need(identity['size']==0 and identity['offset']==(None if route=='opath'else 0),'actual empty regular capture before exec')
    if route in('normal','subvolume','dup','opath','directory'):need(actual['filesystem_type']==0x9123683e,'actual tested capture filesystem is btrfs')
    if route=='memfd':need(actual['filesystem_type']==0x01021994,'actual memfd shmem is the wrong-filesystem control')
    dup=next(x for x in calls if x['name']=='dup2');need(dup['result_fd']==1 and dup['identity']==identity,'actual inherited FD1 identity')
    need(all(x['fd']==query[0]['fd']for x in query),'both raw queries observe the same original object')
    if route=='dup':
        d=next(x for x in calls if x['name']=='same_ofd_dup');need(d['source_fd']==query[0]['fd']and d['result_fd']==dup['source_fd']and d['identity']==identity,
             'actual same-OFD duplication precedes inherited FD1')
    else:need(dup['source_fd']==query[0]['fd'],'the queried original object is inherited as FD1')
    if route=='subvolume':
        row=next(x for x in calls if x['name']=='get_subvol_info');raw=bytes.fromhex(row['raw'])
        need(row['fd']==query[0]['fd']and row['command']==layout['subvolume_command']==0x81f8943c and
             type(row['result'])is int and row['result']in(0,1)and row['bytes']==len(raw)==504 and row['before']==row['after']==identity and
             raw==bytes.fromhex(actual['subvolume']['raw'])and struct.unpack_from('<Q',raw)[0]==actual['subvolume']['treeid']>=256 and
             any(raw[296:312])and not any(raw[440:]),'actual same-FD complete GET_SUBVOL_INFO proves non-top-level subvolume')
    else:need(actual['subvolume']is None,'no subvolume inference from pathname/device')
    return actual
