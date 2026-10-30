The scalar-span component passed all 59 cases at `e376443d5c35ab2d63fd05e3f4eb3b4b9ac9e93e`. The separate finite TRACE-owner experiment failed: all nine subjects launched, four native references passed, and all five gated subjects were killed without producing application output or an owner record. The component result does not qualify the runtime TRACE transfer.

Both receipts retain the exact tested source and artifact identities, complete command records, unchanged input/source closure, and completed process/descriptor cleanup with no final closure errors. They used one reserved CPU each: CPU 273 for the component and CPU 3 for the TRACE experiment, on an AMD EPYC 9D85 158-Core Processor, Linux 7.1.3, microcode `0xb101066`, without root privileges.

| Closed cohort | Actual result | Retained scope |
| --- | --- | --- |
| Scalar-span component | 59/59 qualified; 87 commands | One metadata case and 58 native/generated hardware comparisons |
| Finite TRACE owner | Failed; 4/9 qualified; 59 commands | Four native references; zero qualified owner pairs |

The component metadata case covered 131 exact instruction forms and 1,283 accepted descriptor observations, including 1,283 no-write footprint checks, 26 refusals, 49 plan controls and 53 retained old-domain accepts. The 58 hardware cases comprise 56 completed paths and two required read faults that exited 125. All 3,022 supplied-record refusal controls passed. Direct retained-record checks confirmed the original/generated source and relocated image, full GPR/flags including AF, all 65,536 FP bytes, memory, exact fault PCs/addresses, and whole post-seal allocator-state equality. Hardware and metadata subjects retained their original limits: 5 CPU seconds, 15 wall seconds, 512 MiB address space and 16 MiB output/file size.

The TRACE experiment's three successful native paths exited 0; its native read-fault reference exited the required 125. Their twelve actual signal frames retained full native state. Each gated subject exited −9 (`SIGKILL`) after 30.221451796–30.241292888 wall seconds, under the original 30-CPU-second, 60-wall-second, 512-MiB address-space and 16-MiB output/file limits. None triggered the wall-timeout flag. This is consistent with CPU-limit termination; these receipts do not retain measured user/system CPU totals or establish the cause or location of noncompletion.

All five gated stdout, stderr and owner-record captures were empty. Consequently, none of the required four native/owner comparisons, 112 application refusal controls, 164 owner-record controls or 756 terminal controls qualified. The failed required generated read fault and nested refusal remain failures. The separate seed prerequisite and 12 namespace checks passed without owner or application-completion credit. Diagnosis is pending; no bound was raised and no failed subject was omitted or relabelled.

Receipt links: [component JSON](20261030T153413.090976Z-scalar-span-component-e376443d5c35.json), [component CSV](20261030T153413.090976Z-scalar-span-component-e376443d5c35.csv), [failed TRACE JSON](20261030T153625.131280Z-scalar-span-trace-e376443d5c35.json), [failed TRACE CSV](20261030T153625.131280Z-scalar-span-trace-e376443d5c35.csv).

The receipts' portable reproduction commands, each requiring one reserved CPU, are:

```sh
python3 evaluation/inprocess/scalar_span_component.py --expect-revision e376443d5c35ab2d63fd05e3f4eb3b4b9ac9e93e
python3 -B evaluation/inprocess/scalar_span_trace.py --expect-revision e376443d5c35ab2d63fd05e3f4eb3b4b9ac9e93e
```

These are finite component and failed owner observations. They provide no whole-program, full 43-case owner, performance or repository-check qualification; broader transfer failure, stale/repeat, rollback, permission, retirement and late-fault controls remain required.
