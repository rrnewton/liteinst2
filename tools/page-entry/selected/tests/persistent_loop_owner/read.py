"""Strict schema14 one-lifetime owner reader and executable supplied controls.

No native execution, subprocess, production decoder or fixture model is run by
this module. Actual application/ELF/DWARF/seed inputs must first be authenticated
by their separate providers. This focal result never supplies lifecycle credit.
"""
import hashlib,importlib.util
from pathlib import Path

def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
positive=load('loop_positive_reader',HERE/'positive.py')
fault=load('loop_fault_reader',HERE/'fault.py')
pairs=load('loop_actual_pairs',HERE/'pair.py')
controls_module=load('loop_actual_controls',HERE/'controls.py')
wire=positive.state.wire;prior=positive.state.base.prior
need=positive.need
RAW_BYTES,SCHEMA_VERSION=4864896,14


def read(data,layout,image,app,pid,cpu,exit_status):
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,
         'actual process and singleton reserved CPU')
    need(type(app)is dict and app['lane']==1 and type(app['mode'])is int and 0<=app['mode']<7,
         'independently authenticated paired-v2 maintained case')
    failed=app['mode']>=5
    decode=fault.old_fault.decode_failure if failed else prior.codec.decode
    raw,transport=decode(data,raw_bytes=RAW_BYTES,schema_version=SCHEMA_VERSION)
    r=wire.Reader(raw,layout);r.transport=transport
    result=(fault.Check if failed else positive.Check)(r,image,app,pid,cpu).finish(exit_status)
    result.update(transport=transport,encoded_sha256=hashlib.sha256(data).hexdigest(),
                  raw_sha256=hashlib.sha256(raw).hexdigest(),schema_version=14)
    return result


def controls(data,layout,image,app,pid,cpu,exit_status):
    return controls_module.controls(read,data,layout,image,app,pid,cpu,exit_status)


def pf_refusal_controls(data,layout,image,app,pid,cpu,exit_status):
    read(data,layout,image,app,pid,cpu,exit_status)
    failed=app['mode']>=5
    decode=fault.old_fault.decode_failure if failed else prior.codec.decode
    raw,_=decode(data,raw_bytes=RAW_BYTES,schema_version=SCHEMA_VERSION)
    encode=(lambda b:fault.old_fault.encode_failed_control(b,schema_version=SCHEMA_VERSION))if failed else(
        lambda b:prior.codec.encode_for_control(b,schema_version=SCHEMA_VERSION))
    return prior.pf_controls(data,raw,layout,(image,app,pid,cpu,exit_status),read,encode,
                             epochs=1,cancellation=False)


def terminal(parsed,owner):return prior.terminal(parsed,owner)
def subentry_terminal(parsed,owner):return prior.subentry_terminal(parsed,owner)
def pf_terminal(parsed,owner):return prior.pf_terminal(parsed,owner)
def loop_terminal(parsed,owner):
    expected=owner['loop_terminal']
    need(type(parsed)is dict and list(parsed)==list(expected)and all(type(v)is int for v in parsed.values())and
         parsed==expected,'whole distinct protected loop15-cell terminal row')
    return dict(version=1,fields=15,protected_loop_row=1)

pair=pairs.pair
pair_controls=pairs.controls
