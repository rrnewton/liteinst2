"""Exact ABI6 wrapper over the unchanged bounded subprocess custody body."""
from loop_ro_reason_process import _program_invoke, _namespace_join
from loop_ro_retired_counter import final_counter_prefix

def program_invoke(row,directory,cpu,record=False,step=False):
    return _program_invoke(row,directory,cpu,record,step,version=6,logical_bytes=2016,
                           carrier_name="loop_ro_retired_carrier.py",reader=final_counter_prefix)


def namespace_join(state,ns,binary,r,namespace,counter):
    return _namespace_join(state,ns,binary,r,namespace,counter,version=6,logical_bytes=2016,
        environment_prefix="LI2_LOOP_RO_RETIRED",identity_name="loop_ro_retired_counter")
