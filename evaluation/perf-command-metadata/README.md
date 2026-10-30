# Perf record command metadata

The installed perf recorded one command word where the authenticated invocation
had 40. Its record path created a zeroed session environment without initializing
the command vector. The header writer consequently wrote only the perf executable
name. The retained capture remains refused by the exact-command check.

The small [upstream patch](producer.patch) copies record's argument pointers
before option parsing moves them, sets the new session's command vector before
recording, and releases the pointer copy on the existing cleanup path. It changes
only Linux `tools/perf/builtin-record.c`. This patch is derived from the Linux
GPL-2.0-only perf source; the upstream source and license remain authoritative.
The separate resulting executable does not replace the installed perf and is
not a reproduction of its vendor package.

On the AMD EPYC Zen 5 dev host, one fixed new capture retained all 40 command
words exactly, including whitespace, quotes and literal shell punctuation.
Changing one word of the expected vector still produces
`cmdline_authority_mismatch`. The unchanged strict decoder reports
`DECODED_UNQUALIFIED`; command equality provides no sample attribution or
performance qualification. [results.json](results.json) retains both build
outcomes, exact revisions, tool/binary/capture hashes, CPU reservations, load
averages and decoder results. Raw files and full commands stay in `ignored/`.

Reproduce with a separate sparse Linux checkout at
`df2908090cda368b01ff43709f51890076c56157` (v7.3-rc2), containing the paths in
`tools/perf/MANIFEST` plus the root Makefile. The measured checkout contained
2,962 files and 43,839,645 payload bytes. Apply the patch once to the pristine
source. Set `PERF_SOURCE`, `PERF_OUTPUT` and `PROBE` to fresh local paths; output
and probe paths must be under this checkout's `ignored/`. Use four reserved CPUs
for the build and one for the capture.

```sh
git -C "$PERF_SOURCE" apply --check "$PWD/evaluation/perf-command-metadata/producer.patch"
git -C "$PERF_SOURCE" apply "$PWD/evaluation/perf-command-metadata/producer.patch"
mkdir "$PERF_OUTPUT"
make -C "$PERF_SOURCE/tools/perf" -f Makefile.perf -j4 \
  PYTHON=/usr/bin/python3.9 PYTHON_CONFIG=/usr/bin/false \
  O="$PERF_OUTPUT/" DEBUG=0 NO_LIBPYTHON=1 NO_JVMTI=1 \
  NO_LIBBPF=1 BUILD_BPF_SKEL=0 NO_LIBTRACEEVENT=1 NO_LIBPFM4=1 \
  NO_LIBDEBUGINFOD=1 NO_SLANG=1 NO_GTK2=1 "$PERF_OUTPUT/perf"
python3 -B evaluation/perf-command-metadata/command.py prepare \
  --producer "$PERF_OUTPUT/perf" --raw "$PROBE"
python3 -B tools/unwind-oracle/bounded_command.py \
  --request "$PROBE/request.json" --receipt "$PROBE/receipt.json"
python3 -B evaluation/perf-command-metadata/command.py inspect --raw "$PROBE"
python3 -B evaluation/perf-command-metadata/controls.py --raw "$PROBE"
```

Invoke `Makefile.perf` directly: the wrapper Makefile otherwise chooses all
online CPUs despite `-j4`. `DEBUG=0` selects upstream's `-O3` release build;
WERROR remains unchanged. Python embedding is disabled, so `/usr/bin/false`
explicitly denotes the absent development-config tool; the real Python 3.9
interpreter still generates the complete PMU tables. Libelf, recording and the
requested event/sample fields remain enabled. The first build, with implicit
Python detection, stopped in configuration and is retained as a failure.

The sparse build logged a missing optional root `scripts/Makefile.warn` during
version discovery but linked successfully; its generated perf version was
`.gdf2908090cda`. Source authority is the full upstream revision and patch hash,
not that abbreviated version string. Build limits were 900 seconds, four jobs,
512 MiB output-tree storage and 128 MiB per output file. The successful build
took 32.3 seconds and used 212,623,360 bytes of output storage. The command probe
uses the existing descendant-owning runner with 20 CPU seconds, 30 wall seconds
and a 16 MiB per-file limit; inspection requires its successful closed receipt.
The read-only controls repeat the real capture check and reject 34 mutations of
the required input manifest or exact request. They leave the capture unchanged.

This command profile places `record` immediately after the canonical executable
path. Global options consumed before `cmd_record` are outside this repair's
claim and must still satisfy exact equality if used. No argument is appended to
captured data from the expected command. Allocation-failure paths were reviewed
at source level; they have not received fault-injection execution here.
