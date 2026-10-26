#!/usr/bin/env python3
"""Additive pure negative controls; no trace, mapping, budget or CPU execution."""
import copy
import json
import sys
if sys.flags.optimize:
    raise SystemExit("optimized Python disables negative calibrations")
from mapping_identity import backing_identity, require_mapping_identity

BASE = dict(record=dict(fd='3',stat_dev='48',stat_ino='77',stat_size='4096',sha256='a'*64), fdinfo='pos:\t0\nflags:\t02100000\nmnt_id:\t123\nino:\t77\n', mountinfo='123 12 0:42 /sub /fixture rw - btrfs /dev/mock rw\n',fd_path='/fixture/image',expected_path='/fixture/image',stat_dev=48,stat_ino=77,stat_size=4096,digest='a'*64)
def checked(case, vma=(0,42,77)):
    require_mapping_identity(backing_identity(**case),*vma)
def calibrate():
    checked(copy.deepcopy(BASE))
    same=copy.deepcopy(BASE);same['record']['stat_dev']='42';same['stat_dev']=42
    same['mountinfo']=same['mountinfo'].replace('btrfs','ext4');checked(same)
    cases=[]
    def changed(name,key,value):
        case=copy.deepcopy(BASE);case[key]=value;cases.append((name,case,(0,42,77)))
    changed('wrong_mount_id','mountinfo',BASE['mountinfo'].replace('123 12','124 12'))
    changed('wrong_mount_device','mountinfo',BASE['mountinfo'].replace('0:42','0:43'))
    changed('wrong_fd_inode','fdinfo',BASE['fdinfo'].replace('ino:\t77','ino:\t78'))
    changed('wrong_stat_device','stat_dev',49)
    changed('wrong_stat_inode','stat_ino',78)
    changed('wrong_file_size','stat_size',4095)
    changed('wrong_digest','digest','b'*64)
    changed('wrong_fd_path','fd_path','/fixture/other')
    changed('wrong_mountpoint','mountinfo',BASE['mountinfo'].replace('/fixture','/elsewhere'))
    changed('missing_mount','mountinfo','')
    changed('duplicate_mount','mountinfo',BASE['mountinfo']*2)
    changed('malformed_mount','mountinfo',BASE['mountinfo'].replace(' - ',' '))
    changed('duplicate_fd_mount_id','fdinfo',BASE['fdinfo']+'mnt_id:\t123\n')
    changed('missing_fd_mount_id','fdinfo',BASE['fdinfo'].replace('mnt_id:\t123\n',''))
    changed('malformed_fd_field','fdinfo',BASE['fdinfo']+'malformed\n')
    cases.append(('wrong_vma_device',copy.deepcopy(BASE),(0,43,77)))
    cases.append(('wrong_vma_inode',copy.deepcopy(BASE),(0,42,78)))
    assert len(cases)==17
    for name,case,vma in cases:
        try:checked(case,vma)
        except (AssertionError,ValueError):pass
        else:raise AssertionError('required identity refusal accepted: '+name)
    return dict(positive=2,negative=17,names=[name for name,_,_ in cases],trace_inventory_changed=False)
if __name__=='__main__':print(json.dumps(calibrate(),sort_keys=True))
