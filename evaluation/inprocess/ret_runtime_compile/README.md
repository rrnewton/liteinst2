# Compile-only RET predecessor

This command compiles the two reviewed RET runtime profiles and inspects their complete ELF/provider/dependency closure. It runs no bridge, generated code, subject, or byte oracle. The owner collector still performs two new complete builds and their mandatory byte oracles. The fixed 21 compiler/inspection commands retain 30 CPU seconds / 60 wall seconds, 512 MiB address space and 16 MiB output each. Both profiles retain 28 translation units and 67 required entries covering 66 distinct local functions.

Run after a fresh public archive and CALL owner result from the same clean revision, CPU 3 and hardware, under the same external reservation:

```sh
python3 -B evaluation/inprocess/ret_runtime_compile/run.py --expect-revision "$(git rev-parse HEAD)" --archive-receipt PATH --archive-receipt-sha256 SHA256 --call-owner-receipt PATH --call-owner-receipt-sha256 SHA256 --output target/evaluation/inprocess/ret-compile-fresh
```

The whole archive/build/tool/source closure is checked in place. The original image binding comes from the authenticated fresh CALL application ELF; it is not executed here. This portable input binding replaces the private diagnostic's fixed historical archive/image paths. The public runner retains the whole compile/provider logic, explicit zero-subject status and no owner, qualification or performance credit. The original failed owner and compile attempts remain historical failures. [The fixed reproducer](../reproduce_ret_owner.py) supplies all arguments and enforces stage order.
