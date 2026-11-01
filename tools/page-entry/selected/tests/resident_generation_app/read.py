"""Two complete old application records, each checked by the unchanged reader.

The owner adapter must separately prove both real generated activations. These
application records alone do not grant content, source, entry or RX authority.
"""
from pathlib import Path
import importlib.util

path=Path(__file__).resolve().parents[1]/'resident_three_app/read.py'
spec=importlib.util.spec_from_file_location('resident_generation_original_application',path)
original=importlib.util.module_from_spec(spec)
spec.loader.exec_module(original)
elf=original.elf

RECORD=original.PREFIX+original.SUFFIX

def read(data,native,exit_status,image,pid,cpu,seed_reference):
    original.need(type(data) is bytes and len(data)==2*RECORD,
                  'exact two complete application records')
    results=[]
    for ordinal in range(2):
        record=data[ordinal*RECORD:(ordinal+1)*RECORD]
        results.append(original.read(record,native,exit_status,image,pid,cpu,seed_reference))
    return dict(version=1,scope='two_actual_four_cycle_applications',
                complete=True,applications=results,records=2,owner_credit=False)

def controls(data,native,exit_status,image,pid,cpu,seed_reference):
    original.need(native is True,'two complete native-only supplied-control populations')
    read(data,native,exit_status,image,pid,cpu,seed_reference)
    rows=[]
    for ordinal in range(2):
        record=data[ordinal*RECORD:(ordinal+1)*RECORD]
        result=original.controls(record,native,exit_status,image,pid,cpu,seed_reference)
        rows.append(dict(ordinal=ordinal,result=result))
    return dict(version=1,complete=True,records=2,controls=rows)
