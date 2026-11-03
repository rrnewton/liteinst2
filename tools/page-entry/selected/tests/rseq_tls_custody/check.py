#!/usr/bin/env python3
"""Strict small component output; no native/full-runtime claim."""
import json

PROFILES=('projected','verified','fresh')
MODES=('plain','page_tail_13','outside_scope','wrong_output','partial_private',
       'trailing_argument','stale_epoch','same_protection_effect','kernel_error','wrong_selector')

def check(stdout,stderr,exit_code,profile,mode):
    if profile not in PROFILES or type(mode) is not int or mode not in range(10):
        raise ValueError('fixed component profile/mode')
    expected=dict(version=1,mode=mode,current=int(profile!='fresh'),
        differential=int(profile=='verified'),component_only=1,supplied_boundary=1,
        tls_calls=2,predicate_refusals=22 if mode==0 else 0,
        guard=1210 if mode==8 else 0,commit=-1 if mode==8 else (0 if mode<2 else 302),
        required_refusal=int(mode>=2),cleanup=[1,2,int(mode<2)])
    encoded=(json.dumps(expected,separators=(',',':'))+'\n').encode()
    if stdout!=encoded or stderr!=b'' or type(exit_code) is not int or exit_code!=(0 if mode<2 else 125):
        raise ValueError('whole literal TLS/custody result and actual exit')
    return expected
