#!/bin/sh
set -eu
cd "$(dirname "$0")/../../.."
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_DEV_OPT_LEVEL=0 CARGO_PROFILE_TEST_OPT_LEVEL=0
export CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true
export CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true
export PYTHONDONTWRITEBYTECODE=1
manifest=evaluation/adjacent-b2/artifact-verifier/Cargo.toml
cargo fmt --manifest-path "$manifest" -- --check
cargo clippy -j 4 --manifest-path "$manifest" --locked --offline --all-targets -- -D warnings
cargo test -j 4 --manifest-path "$manifest" --locked --offline
python3 -B -m unittest discover -s evaluation/adjacent-b2/artifact-verifier -p '*controls.py' -v
