# Finite loop qualification checkpoint

At revision `758180bc2f63dd817d92b65fa59ed06437ebea65`, native41, bounded-block, fused components, fused native/faults and the 28 new native references passed their finite collectors. The sequence then failed compiling the loop-plan component because its bridge lacked the decoder declaration. Four component cases completed; the failed sequence remains failed.

Revision `ddfc41a7a34f7f63a625c4ee6d13946624df3adc` adds that header. All five component cases then passed under the original bounds, using the retained scalar-read archive. This supplied-archive check does not establish native execution or same-revision archive build provenance.

These JSON/CSV files contain literal recorded outcomes, exact revisions, hardware, bounds, capture hashes and reproduction commands. Durations are validation cost. No translated-loop, lifecycle, whole-program, original392/522 or performance-target credit is granted here.

Reproduce a complete fresh sequence with `evaluation/inprocess/reproduce_tunables.py` on one externally reserved CPU and a local DynamoRIO11.91 SDK. Its existing child collectors retain all original gates. Copy the driver outside the checkout when reproducing an older revision. `project_tunables_result.py` only projects closed receipts and hashes their captures; it does not replay validation. Its initial private version rejected a legitimate `link-crt1.o` command label before producing output. The published version recognizes exactly the20 linker labels emitted by both original component collectors.

For earlier fault diagnosis, `evaluation/inprocess/diagnose_loop_owner.py` accepts fresh same-revision native28 and five-component receipts, builds both owner lanes and runs all56 focal subjects under their original bounds and comparisons. It explicitly omits the older native41/PB/PF prerequisite evaluation and emits a distinct diagnostic profile rejected by the production provider. Its results cannot replace the full chain. This diagnostic was source-reviewed but had not run at this checkpoint.
