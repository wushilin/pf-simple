#!/bin/sh
# Runs the conformance driver from the built jars (run build.sh first).
# See conformance/README.md.
dir="$(cd "$(dirname "$0")" && pwd)"
exec java -cp "$dir/build/pfrelay.jar:$dir/build/pfrelay-conformance.jar" \
    io.github.wushilin.pfrelay.conformance.Driver "$@"
