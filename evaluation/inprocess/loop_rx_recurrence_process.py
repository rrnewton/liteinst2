"""Exact ABI7 recurrence wrapper; target failure and prefix remain distinct."""
from loop_ro_reason_process import _program_invoke, _namespace_join
from loop_rx_recurrence import final_counter_prefix


def program_invoke(row,directory,cpu,record=False,step=False):
    return _program_invoke(row,directory,cpu,record,step,version=7,logical_bytes=12382208,
        carrier_name="loop_rx_recurrence_carrier.py",reader=final_counter_prefix,storage_bytes=12582912)


def namespace_join(state,ns,binary,r,namespace,counter):
    return _namespace_join(state,ns,binary,r,namespace,counter,version=7,logical_bytes=12382208,
        environment_prefix="LI2_LOOP_RX_RECURRENCE",identity_name="loop_rx_recurrence_counter",storage_bytes=12582912)
