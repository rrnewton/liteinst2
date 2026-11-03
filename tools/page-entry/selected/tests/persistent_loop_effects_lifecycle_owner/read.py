"""Strict schema17 five-offer companion reader and separate actual-state pair.

Only a complete independently decoded native history is accepted. A single
orientation does not establish reversal coverage or authorize a program run.
"""
import hashlib,importlib.util
from pathlib import Path
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
HERE=Path(__file__).resolve().parent
envelope=load('lifecycle_envelope',HERE/'envelope.py')
pairs=load('lifecycle_pairs',HERE/'pair.py')
control_module=load('lifecycle_controls',HERE/'controls.py')
base=envelope.base;wire=base.wire;prior=base.focal.base.prior
need=base.need
RAW_BYTES,SCHEMA_VERSION=16744832,17
OWNER_COUNTS=(723,723)
PAIR_COUNT,PF_COUNT=1069,36
EFFECTS_COUNT=control_module.EFFECTS_COUNT

def read(data,layout,image,app,native,pid,cpu,exit_status):
    need(type(pid)is int and 0<pid<1<<31 and type(cpu)is int and cpu>=0,
         'actual companion process and singleton reserved CPU')
    need(type(exit_status)is int and exit_status==0 and type(app)is dict and
         app['lane']==1 and type(app['mode'])is int and app['mode']in(0,1)and
         type(app['placement'])is int and app['placement']in(0,1),
         'one actual successful maintained companion at an explicit orientation and placement')
    raw,transport=prior.codec.decode(data,raw_bytes=RAW_BYTES,schema_version=SCHEMA_VERSION)
    r=wire.Reader(raw,layout);r.transport=transport
    result=envelope.Check(r,image,app,native,pid,cpu).finish(exit_status)
    result.update(transport=transport,encoded_sha256=hashlib.sha256(data).hexdigest(),
                  raw_sha256=hashlib.sha256(raw).hexdigest(),schema_version=SCHEMA_VERSION)
    return result

def controls(data,layout,image,app,native,pid,cpu,exit_status):
    return control_module.controls(read,data,layout,image,app,native,pid,cpu,exit_status)

def pf_refusal_controls(data,layout,image,app,native,pid,cpu,exit_status):
    return control_module.pf_controls(read,data,layout,image,app,native,pid,cpu,exit_status)

def terminal(parsed,owner):return prior.terminal(parsed,owner)
def subentry_terminal(parsed,owner):return prior.subentry_terminal(parsed,owner)
def pf_terminal(parsed,owner):return prior.pf_terminal(parsed,owner)
def loop_terminal(parsed,owner):
    expected=owner['loop_terminal']
    need(type(parsed)is dict and list(parsed)==list(expected)and
         all(type(v)is int for v in parsed.values())and parsed==expected,
         'whole distinct protected loop15-cell terminal row')
    return dict(version=1,fields=15,protected_loop_row=1)

pair=pairs.pair
pair_controls=pairs.controls


def effects_terminal(parsed,owner):
    expected=owner['effects_terminal']
    need(type(parsed)is dict and list(parsed)==list(expected)and
         all(type(v)is int for v in parsed.values())and parsed==expected,
         'whole distinct18-cell effects terminal row')
    return dict(version=1,fields=18,protected_effects_row=1)

def effects_controls(data,layout,image,app,native,pid,cpu,exit_status):
    return control_module.effects_controls(read,data,layout,image,app,native,pid,cpu,exit_status)


EXPECTED_COUNT=envelope.cancellation.epochs.member_expected.CONTROL_COUNT

def expected_controls(data,layout,image,app,native,pid,cpu,exit_status):
    return envelope.cancellation.epochs.member_expected.controls(read,prior.codec,RAW_BYTES,SCHEMA_VERSION,
        data,layout,image,app,native,pid,cpu,exit_status)
