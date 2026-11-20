# Agent guide

`liteinst` is a standalone Rust library for hooking machine code in a running
program; [README.md](README.md) describes it.

Backend compatibility work that builds on this library (Hermit's LiteInst
backend, and in-guest-trap, the same runtime with site patching off) follows
Hermit's
[`compat-ratcheting` skill](https://github.com/facebookexperimental/hermit/blob/main/.claude/skills/compat-ratcheting/SKILL.md).
