# Bounded perf.data syntax inspection

`decode_perf.py` inspects the closed little-endian regular-file `PERFILE2` profile offline. It runs neither perf nor an application. Authenticate the CLI and its local `perf_data.py` / `perf_records.py` sources before invocation. Matching a format does not establish the installed writer's identity or capture provenance.

Supply a mandatory expected SHA-256 from independently retained input authority:

```sh
python3 -B tools/rapid-profiler/tree-work/decode_perf.py \
  --data "$PERF_DATA" --sha256 "$EXPECTED_DATA_SHA256"
```

To join the recorded CMDLINE, add both options:

```sh
python3 -B tools/rapid-profiler/tree-work/decode_perf.py \
  --data "$PERF_DATA" --sha256 "$EXPECTED_DATA_SHA256" \
  --command-json "$COMMAND_JSON" --command-sha256 "$EXPECTED_COMMAND_SHA256"
```

Hashes are exactly 64 lowercase hexadecimal digits over the original file bytes. Command JSON must be a nonempty UTF-8 list of strings representing the exact externally authenticated argv stored in perf's CMDLINE, including perf's executable. Supply the complete perf argv, including any wrapped command. Empty arguments, newlines and filesystem-encodable characters remain distinct; NUL is refused. The command hash joins the original JSON bytes. Neither hash alone proves that a process executed those arguments. Omitting command authority preserves an explicit unresolved condition.

Each input must be a regular file; final-component symlinks refuse. Reads check bounded size and before/after descriptor metadata. Ancestor-path custody, source authentication, process resource limits and output custody remain the enclosing owner's responsibility.

| JSON status | Exit | Meaning |
| --- | ---: | --- |
| `DECODED_UNQUALIFIED` | 0 | Supported syntax/profile decoded; adverse or unresolved observations may remain. |
| `REFUSED` | 2 | Input or supported-profile mismatch, authority mismatch or wrapper failure; not necessarily malformed file syntax. |
| `UNSUPPORTED` | 3 | Unsupported format or semantic extension, with error offset and retained prefix counts. |

The CLI emits one complete ASCII JSON summary: hashes, counts, type inventory, decoded-prefix period sum, error offset, and adverse/unresolved fields. The Python API also retains private input bytes, decoded records and feature contents in memory; filenames, argv and private data are excluded from the CLI summary. Unknown records are not skipped or retried.

Bounds are 16 MiB per data file, 100,000 records, 8..65,535 bytes per record, 64 KiB command JSON and encoded argv including NUL charges, and 4 MiB complete summary. The attribute profile requires one event, fixed period 4096 and user-only counting flags. Generic hardware instructions require their exact UAPI encoding. Raw/dynamic PMU words are retained with event meaning unresolved: the `instructions:uDS` label or a PMU name is not semantic authority. Loss, throttle, zero values and unequal enabled/running remain visible. No status qualifies APP identity, mappings, terminal accounting, event meaning, accuracy, performance or full A5.

The pinned upstream Linux v7.3-rc2 regular BUILD_ID writer (`tools/perf/util/build-id.c`, `write_buildid`) zeroes type to 0, requires SIZE with a declared host/guest kernel/user mode, and writes a 36-byte prefix plus minimal eight-byte-aligned NUL filename allocation. Unused ID bytes and padding must be zero; filename allocation stays below 4096 bytes. Synthesized/pipe type 67 uses another layout and is refused here. Canonical syntax still leaves external image and installed-writer identity unestablished.

Run fabricated decoder and CLI controls from the repository root, with temporary files inside the workspace:

```sh
mkdir -p target/evaluation/perf-decode-tmp
TMPDIR="$PWD/target/evaluation/perf-decode-tmp" \
  python3 -B tools/rapid-profiler/tree-work/test_perf_data.py
TMPDIR="$PWD/target/evaluation/perf-decode-tmp" \
  python3 -B tools/rapid-profiler/tree-work/test_decode_perf.py
```

Use normal Python assertion mode; `-O` is refused. These tests exercise fabricated syntax and CLI behavior, not capture or native qualification. No test or capture outcome is reported here.
