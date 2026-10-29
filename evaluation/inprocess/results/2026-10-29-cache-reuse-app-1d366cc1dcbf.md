# Cache reuse with full application state (claims 1, 2 and 4)

At revision `1d366cc1dcbff9a018bcec16227cdac243345b04`, the unchanged main PIE and dynamically linked DSO completed both Native and Scripted 18-operation state lanes. Each passed 36 complete native signal-frame comparisons with zero architectural bytes excluded, plus all 27 supplied report-refusal controls. Each exercised 1,024 generated runs, 346 generations, 282 retirements, 678 hits and 2,267 copied instructions in the fixed 64-page cache; neither had a capacity miss.

The complete application experiment **failed**. Native stress was killed by signal 9 after 30.201536467 seconds under its original 30-second CPU limit. Its record and stderr were empty; 10,384 stdout bytes do not establish completed stress iterations. Scripted stress was not executed. No capacity-stress, performance, full-B2 or all-seven-instruction qualification is claimed.

The new application reader supports exact existing STOSD and STOSQ semantics. It binds all three emitted source bytes to the original ELF, accepted module bias and independently sampled source allocation; it does not equate allocation with object identity. The earlier `9dab22bf4619fb87f8a1ffd438be8c36d043e065` attempt remains failed at the old STOSQ-only report predicate. Its state-Native process and native pair had succeeded before that rejection. The separate unchanged STOSD oracle at that revision passed six full-state native pairs, an actual store fault and all 53 supplied refusals.

Four required checks plus recorder and serial passed at `1d366cc1`: recorder 350; workspace 3,260 passed, zero failed, 36 ignored; serial 1,039 passed. Source and configuration remained unchanged. The runtime is unchanged from the preceding generated-cache-reuse milestone.

Receipts retain exact revisions, hardware, commands, bounds, raw numerical summaries and capture hashes:

- [Application attempt before reader correction](20261029T143847.678511Z-page-selected-run-reuse-app-9dab22bf4619.json)
- [Independent STOSD oracle](20261029T144241.671359Z-page-selected-repeat-dword-oracle-9dab22bf4619.json)
- [Corrected reader: state success and stress failure](20261029T144727.710473Z-page-selected-run-reuse-app-1d366cc1dcbf.json)
- [Required checks, recorder and serial](20261029T144925.680087Z-checks-1d366cc1dcbf.json)

Reproduce each receipt using its tracked evaluator and `reproduce` argument vector at its exact source revision. Native evaluators require one reserved CPU; required checks used four. The application evaluator builds release artifacts and retains both state lanes before either fixed 9,216-operation stress lane. All original resource and capture limits remain in force.
