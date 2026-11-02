# Supplemental LOOP fast-byte component reproduction

The recorded diagnostic ran at clean source
`3c6cac6de974ddf8aee00f52d9d17b65bb11c995` on reserved CPU 16. Its driver was a
separate 15,008-byte file with SHA256
`fa8dbbe1ed62a434d8e1050450161fbaa78aa8c21c2566b1b20065e4d423494a`, published later
as `evaluation/inprocess/loop_fast_bytes.py`. To reproduce that historical source,
copy the published driver outside the checkout **before** entering a clean
checkout at `3c6cac6d`; verify its hash. Do not add it to that historical tree or
change a receipt's revision. The driver uses the current working directory as
the source root and records its own whole-file identity separately.

The prerequisite is the complete original five-component receipt, with all 60
commands, inputs, artifacts, aliases and captures retained, at the same exact
source, CPU and hardware. The recorded prerequisite was
`target/evaluation/inprocess/loop-diagnostic-r3-components/receipt.json`,
353,813 bytes, SHA256
`ce2f5b992b1697a47878582572df93e9615f2cc7f57dd7961004b9d6dced0ee2`.
It used the actual 12,007,764-byte supplied decoder archive SHA256
`d5ae6933ce1e905be557a9dac3ffd2341c7649c42f58f9594bba2365ea8ba399`.
If those private files are unavailable, collect a fresh baseline on the chosen
reserved CPU with the unchanged tracked collector:

```sh
python3 -B evaluation/inprocess/loop_components/run.py \
  --expect-revision 3c6cac6de974ddf8aee00f52d9d17b65bb11c995 \
  --archive ACTUAL_DECODER_ARCHIVE --archive-sha256 ACTUAL_ARCHIVE_SHA256 \
  --cpu RESERVED_CPU --output target/evaluation/inprocess/components-FRESH
```

Keep the same CPU reservation (or reacquire that exact CPU without overlap).
Use the actual newly written receipt and its SHA256, not the historical hash
above, unless replaying the retained historical receipt. From the clean source
root, run the copied driver:

```sh
python3 -B /ABSOLUTE_OUTSIDE_CHECKOUT/loop_fast_bytes.py \
  --expect-revision 3c6cac6de974ddf8aee00f52d9d17b65bb11c995 \
  --component-receipt ACTUAL_COMPLETE_COMPONENT_RECEIPT \
  --component-receipt-sha256 ACTUAL_COMPLETE_RECEIPT_SHA256 \
  --output target/evaluation/inprocess/loop-fastbytes-FRESH
```

All 16 supplemental commands are mandatory: the original 23-length byte oracle,
the 981,320/83,320-byte guarded-size wrapper, and fast-profile chooser, PF11 and
LP12 component builds/runs. Original component comparators and whole scalar/fast
stdout equality remain required. Metadata has 30 CPU/60 wall seconds, 512 MiB
address space and 64 MiB file limits; links/component metadata retain 30/60 and
16 MiB file limits; oracle runs retain 5/15 and 16 MiB file limits. Captures cap
at 16 MiB. Failure stops the sequence and remains failed.

The recorded compact summary is 9,825 bytes, SHA256
`2df6cffaf9d79b7982754e4c6ef691e3e3b3652cde66ae7c6520b15e0743e076`; its private
receipt is 9,648 bytes, SHA256
`01517a3044b0c679b4861464caf2147257ca291bfefc1d77c9474a0080a99320`.
This is component diagnostic evidence only. It supplies no native or owner
execution, archive build provenance, original 392/522 qualification or
performance credit. The separate native populations and benchmark remain required.
