#!/bin/sh
set -eu

EXPECTED_OPENMLS_REVISION=47dbedecad0c1fd8eb5368d582250ebfcc1e1ce6
EXPECTED_RUSTC='rustc 1.97.1 (8bab26f4f 2026-07-14)'
EXPECTED_RUSTC_COMMIT=8bab26f4f68e0e26f0bb7960be334d5b520ea452
EXPECTED_CARGO='cargo 1.97.1 (c980f4866 2026-06-30)'

if [ "$#" -ne 4 ]; then
    echo "usage: $0 OPENMLS_CHECKOUT OUTPUT_JSON CARGO_BIN RUSTC_BIN" >&2
    exit 64
fi

OPENMLS_CHECKOUT=$1
OUTPUT_JSON=$2
CARGO_BIN=$3
RUSTC_BIN=$4
HARNESS_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SOURCE_LINK=$HARNESS_DIR/openmls-src

test -x "$CARGO_BIN"
test -x "$RUSTC_BIN"
test -d "$OPENMLS_CHECKOUT/.git"
test ! -e "$SOURCE_LINK"

test "$(git -C "$OPENMLS_CHECKOUT" rev-parse HEAD)" = "$EXPECTED_OPENMLS_REVISION"
test "$(git -C "$OPENMLS_CHECKOUT" rev-parse "HEAD^{commit}")" = "$EXPECTED_OPENMLS_REVISION"
test -z "$(git -C "$OPENMLS_CHECKOUT" status --porcelain)"
test "$($RUSTC_BIN --version)" = "$EXPECTED_RUSTC"
test "$($RUSTC_BIN -Vv | sed -n 's/^commit-hash: //p')" = "$EXPECTED_RUSTC_COMMIT"
test "$($CARGO_BIN --version)" = "$EXPECTED_CARGO"

ln -s "$OPENMLS_CHECKOUT" "$SOURCE_LINK"
cleanup() {
    unlink "$SOURCE_LINK"
}
trap cleanup EXIT HUP INT TERM

env RUSTC="$RUSTC_BIN" "$CARGO_BIN" run \
    --locked \
    --manifest-path "$HARNESS_DIR/Cargo.toml" \
    -- "$OUTPUT_JSON"
