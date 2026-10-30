import ctypes,json
from pathlib import Path
libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
mask=ctypes.c_ulonglong(0x55aa55aa55aa55aa);ctypes.set_errno(0)
result=libc.syscall(ctypes.c_long(158),ctypes.c_long(0x5005),ctypes.byref(mask))
record=dict(operation='ARCH_SHSTK_STATUS',operation_value=0x5005,result=result,errno=ctypes.get_errno(),sentinel_before='55aa55aa55aa55aa',mask_after=format(mask.value,'016x'),status={line.split(':')[0]:line.split(':',1)[1].strip() for line in Path('/proc/self/status').read_text().splitlines() if line.startswith(('x86_Thread_features','SigBlk:','SigIgn:','Seccomp:'))},native_dispatches=0,exec_dispatches=0)
Path('ignored/a3/shstk-status-diagnostic-v1/result.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))
