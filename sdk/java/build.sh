#!/bin/sh
# Builds the Java SDK with the JDK alone: compiles, packs the jars into
# build/, and runs the tests. Run it from anywhere.
set -eu
cd "$(dirname "$0")"
JAVAC_FLAGS="--release 17 -encoding UTF-8 -Xlint:all,-serial -Werror"
rm -rf build
mkdir -p build/classes/main build/classes/test build/classes/conformance

javac $JAVAC_FLAGS -d build/classes/main $(find src/main/java -name '*.java')
jar --create --file build/pfrelay.jar -C build/classes/main .

javac $JAVAC_FLAGS -cp build/pfrelay.jar -d build/classes/conformance $(find src/conformance/java -name '*.java')
jar --create --file build/pfrelay-conformance.jar \
    --main-class io.github.wushilin.pfrelay.conformance.Driver -C build/classes/conformance .

# The tests live in the SDK's package, to reach what is package-private.
javac $JAVAC_FLAGS -cp build/classes/main -d build/classes/test $(find src/test/java -name '*.java')
java -cp build/classes/main:build/classes/test io.github.wushilin.pfrelay.TestMain
