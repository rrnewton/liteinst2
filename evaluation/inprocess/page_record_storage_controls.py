#!/usr/bin/env python3
"""Storage-only checks using two authenticated, already-qualified c14 XOR records.
Never runs a native subject or record reader; required exit125 remains failed_memory_read.
"""
import argparse,copy,errno,gzip,hashlib,importlib.util,json,os,sys,tempfile
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
RECEIPT_SHA='45e27943431739a6eff8eec28218bb65794e177aaa530afe67f8055a6108a0a6'
PUBLIC_SHA='fc2a10e3587d30275e6d00f0fcaf80586117380889556698a5853f4ee3578469'
HELPER_SHA='b054ad33b0d4fb81a093ee26971e4fae386fef4ba853aa41eb5908ce763c3c4c'
NAMES=('group0','indexed-cross-read-fault')
CASES=('completed_roundtrip','required125_roundtrip','damaged_crc','truncated_archive','raw_reappearance',
       'unaccepted_record','wrong_command','wrong_exit','failed_read_relabel','compression_failure','journal_fsync_failure','fd3_reusable_after_archive')
def fact(data):return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
def fd3_available():
    fd=os.open(os.devnull,os.O_RDONLY|os.O_CLOEXEC)
    try:assert fd==3,'actual fixed fd3 must be reusable'
    finally:os.close(fd)
def rejected(call,kind):
    try:call()
    except kind as exc:
        assert type(exc)is kind,(type(exc),kind)
        return str(exc)
    raise AssertionError('expected exact storage rejection '+kind.__name__)
def original(path,want):
    assert not(path.exists()and Path(str(path)+'.gz').exists()),'one original storage representation'
    opener=path.open if path.exists()else Path(str(path)+'.gz').open
    with opener('rb')as raw:
        source=raw if path.exists()else gzip.GzipFile(fileobj=raw,mode='rb')
        try:
            data=bytearray()
            while True:
                block=source.read(1<<20)
                if not block:break
                data.extend(block);assert len(data)<=want['bytes'],'bounded retained source'
        finally:
            if source is not raw:source.close()
    assert fact(data)==want,'exact closed original record bytes'
    return bytes(data)
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for key in ('helper','receipt','public','output'):ap.add_argument('--'+key,required=True,type=Path)
    args=ap.parse_args();assert not sys.flags.optimize
    helper=args.helper.resolve(strict=True);receipt=args.receipt.resolve(strict=True);public=args.public.resolve(strict=True)
    helper_bytes=helper.read_bytes();receipt_bytes=receipt.read_bytes();public_bytes=public.read_bytes()
    assert fact(helper_bytes)['sha256']==HELPER_SHA and fact(receipt_bytes)['sha256']==RECEIPT_SHA and fact(public_bytes)['sha256']==PUBLIC_SHA
    r=json.loads(receipt_bytes);p=json.loads(public_bytes)
    assert p['private_receipt']==fact(receipt_bytes) and p['status']==r['status']=='passed'
    assert r['source']['revision']=='c14f3078a1b59c637f3cf5fe29e0849ca11f3abf' and r['source_unchanged']and r['cleanup_complete']and not r['error']and not r['final_errors']
    records={}
    for name,exitcode in zip(NAMES,(0,125)):
        matches=[c for c in r['cases']if c['name']==name];commands=[c for c in r['commands']if c['name']==name]
        assert len(matches)==len(commands)==1
        case,command=matches[0],commands[0];cap=command['captures']['record'];want={k:cap[k]for k in('bytes','sha256')}
        assert case['status']=='accepted_observation'and case['record']==want and case['actual_exit']==command['exit']==command['expected_exit']==exitcode
        assert case['outcome']['operation']==('completed'if exitcode==0 else'failed_memory_read')
        assert command['profile']=='native'and command['bounds']==[5,512<<20,16<<20,15]and command['reaped']and not command['timed_out']and not command['error']and not command['cleanup_errors']
        assert cap['file']==name+'.record' and all(d['closed']for d in command['descriptors'])
        path=receipt.parent/cap['file'];mode=r['binaries_before'][str(path)]['mode']
        records[name]=(command,case,original(path,want),mode)
    spec=importlib.util.spec_from_file_location('reviewed_record_storage',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    result=dict(schema=1,status='failed',scope='Evidence-storage component only, using two closed authenticated c14 records; no subject or native reader runs, no new operation or performance credit.',
        inputs=dict(helper=fact(helper_bytes),private_receipt=fact(receipt_bytes),public_receipt=fact(public_bytes)),
        original_records={n:dict(exit=records[n][0]['exit'],operation=records[n][1]['outcome']['operation'],**fact(records[n][2]))for n in NAMES},cases=[],native_subjects=0,reader_replays=0)
    try:
        for label in CASES:
            name=NAMES[1]if label in('required125_roundtrip','failed_read_relabel')else NAMES[0]
            command,accepted,data,mode=records[name];command=copy.deepcopy(command);accepted=copy.deepcopy(accepted)
            with tempfile.TemporaryDirectory(prefix='storage-',dir=out)as directory:
                private=Path(directory);raw=private/command['captures']['record']['file'];raw.write_bytes(data);raw.chmod(mode)
                fd3_available()
                want=fact(data);local={};store=module.RecordStorage(private,local);row=dict(name=label,status='failed')
                if label in('completed_roundtrip','required125_roundtrip','damaged_crc','truncated_archive','raw_reappearance','fd3_reusable_after_archive'):
                    store.archive(raw,command,accepted);assert not raw.exists()and store.contains(raw)
                    assert store.original(raw)==dict(want,mode=mode)
                    gz=Path(str(raw)+'.gz');assert gzip.decompress(gz.read_bytes())==data
                    assert [json.loads(x)['event']for x in store.path.read_text().splitlines()]==['begin','verified_before_raw_unlink','raw_storage_replaced']
                    if label in('damaged_crc','truncated_archive'):
                        saved=gz.read_bytes();broken=bytearray(saved)
                        if label=='damaged_crc':broken[-8]^=1
                        else:del broken[-8:]
                        gz.write_bytes(broken)
                        rejected(lambda:store.original(raw),ValueError)
                        # Supplied storage-fact rebinding tests decompression itself; original raw fact stays fixed.
                        entry=store.entries[str(raw)];entry['compressed']=module.fact(gz);entry['compressed_stat']=module.stable(gz)
                        kind=gzip.BadGzipFile if label=='damaged_crc'else EOFError
                        rejected(lambda:store.original(raw),kind)
                        gz.write_bytes(saved);entry['compressed']=module.fact(gz);entry['compressed_stat']=module.stable(gz)
                        store.finish()
                    elif label=='raw_reappearance':
                        raw.write_bytes(data);rejected(lambda:store.original(raw),ValueError)
                        rejected(store.finish,ValueError);fd3_available()
                    elif label=='fd3_reusable_after_archive':
                        fd3_available();assert store.original(raw)==dict(want,mode=mode)
                        store.finish();fd3_available()
                    else:store.finish()
                elif label=='journal_fsync_failure':
                    opened=[];path_open=Path.open
                    def observe_open(path,*args,**kwargs):
                        stream=path_open(path,*args,**kwargs)
                        if path==store.path:opened.append(stream)
                        return stream
                    with patch.object(Path,'open',new=observe_open),patch.object(module.os,'fsync',side_effect=OSError(errno.EIO,'supplied journal fsync failure')):
                        rejected(lambda:store.archive(raw,command,accepted),OSError)
                    assert len(opened)==1 and opened[0].closed and raw.read_bytes()==data and not store.entries
                    assert local['record_storage']['records'][0]['status']=='started'and not Path(str(raw)+'.gz').exists()
                    fd3_available();rejected(store.finish,ValueError);fd3_available()
                elif label=='compression_failure':
                    original_gzip=module.gzip.GzipFile
                    class BrokenGzip(original_gzip):
                        def write(self,block):
                            super().write(block[:4096]);raise OSError(errno.ENOSPC,'supplied compression failure')
                    with patch.object(module.gzip,'GzipFile',BrokenGzip):rejected(lambda:store.archive(raw,command,accepted),OSError)
                    assert raw.read_bytes()==data and not store.contains(raw)and local['record_storage']['records'][0]['status']=='started'
                    assert [json.loads(x)['event']for x in store.path.read_text().splitlines()]==['begin']
                    rejected(store.finish,ValueError);fd3_available();assert raw.read_bytes()==data
                else:
                    if label=='unaccepted_record':accepted['status']='failed'
                    elif label=='wrong_command':command['name']='other-command'
                    elif label=='wrong_exit':command['exit']=command['expected_exit']=accepted['actual_exit']=1
                    elif label=='failed_read_relabel':accepted['outcome']['operation']='completed'
                    else:raise AssertionError(label)
                    rejected(lambda:store.archive(raw,command,accepted),ValueError)
                    assert raw.read_bytes()==data and not Path(str(raw)+'.gz').exists()and not store.path.exists()
                    assert local['record_storage']['records']==[]and not store.entries
                    store.finish()
                row.update(status='passed',raw_bytes=want['bytes'],actual_source_exit=records[name][0]['exit']);result['cases'].append(row)
        assert [x['name']for x in result['cases']]==list(CASES)and len(result['cases'])==12
        assert helper.read_bytes()==helper_bytes and receipt.read_bytes()==receipt_bytes and public.read_bytes()==public_bytes
        result['status']='passed'
    finally:
        (out/'result.json').write_text(json.dumps(result,sort_keys=True,separators=(',',':'))+'\n')
    print(json.dumps(dict(status=result['status'],storage_cases=len(result['cases']),native_subjects=0,reader_replays=0),sort_keys=True))
if __name__=='__main__':main()
