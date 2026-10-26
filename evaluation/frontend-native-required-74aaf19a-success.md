The four required workspace gates passed at commit `74aaf19a382461aa24c715cab5e17beeaa045e0a`: format, Clippy, workspace tests and workspace check. The test log contains **1,041 outer passes, zero failures and four unchanged ignores across 62 groups**. Five nested passes are counted separately; two other child launch markers receive no extra credit. [Commands, cases and source hashes](results/frontend-native-required-74aaf19a-20261025/summary.json) retain every named result and original bound.

The only change from the [failed parent attempt](frontend-native-required-7e464a42-failure.md) gives the unchanged ELF fixture an explicitly aligned static owner and adds an alignment/whole-byte assertion. All fourteen old parser test bodies remain exact. The 89 model tests, 26 oracle calibrations and ten compile-fail doc subjects passed. This workspace log contains doc subjects/results, not full compiler diagnostic bodies. The prior attempt remains failed with fourteen parser failures and its final check unrun.

Reproduce from the exact clean tested commit with the existing [required-gates.py](required-gates.py), original Cargo.lock and a new output directory strictly below `REPO/ignored`:

```sh
"${PYTHON}" -B "${REPO}/evaluation/required-gates.py" --repo "${REPO}" --output "${RAW}"
```

`PYTHON` is a whole executable path, `REPO` the exact clean checkout and `RAW` a whole fresh required-output directory. Select `RUSTUP_TOOLCHAIN=1.97.1-x86_64-unknown-linux-gnu`, leave `NATIVE_INTERVAL_DSO` absent, and record fresh tool, configuration and environment observations. The runner retains four jobs/test threads, offline Cargo, no incremental build and its 180/180/360/180-second command bounds; the recorded parent bound is 1,000 seconds. The public override map is not the complete inherited private environment.

Hardware was recorded as an **AMD EPYC Zen 5 dev host** before launch; timing is operational evidence. The runner uses its existing process-group cleanup, with no ECHILD, CPU/file-limit, cgroup or complete tool/runtime-closure claim. This result covers the required workspace commands only. At closure of this required capture, the separate four-mode native campaign had not run; later evidence is recorded separately. Full A5 and claims 1–4 are not established by this packet.
