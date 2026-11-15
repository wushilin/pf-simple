#!/bin/sh
# Runs the conformance driver from the built jars (run build.sh first).
# See conformance/README.md.
dir="$(cd "$(dirname "$0")" && pwd)"
cp="$dir/build/pfrelay.jar:$dir/build/pfrelay-quic.jar:$dir/build/pfrelay-quic-conformance.jar"
for j in "$dir"/lib/*.jar; do
    cp="$cp:$j"
done
exec java -cp "$cp" io.github.wushilin.pfrelayquic.conformance.Driver "$@"
