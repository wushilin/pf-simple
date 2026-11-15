#!/bin/sh
# Builds the Java QUIC SDK with the JDK alone: fetches its QUIC library
# (kwik, from Maven Central, checked against the hashes below) into lib/,
# compiles pfrelay from ../java and this SDK, packs the jars into build/,
# and runs the tests. Run it from anywhere.
#
# It never writes to ../java, so it can run while ../java/build.sh does.
set -eu
cd "$(dirname "$0")"
JAVAC_FLAGS="--release 17 -encoding UTF-8 -Xlint:all,-serial -Werror"
CENTRAL="${MAVEN_CENTRAL:-https://repo1.maven.org/maven2}"

# group/artifact/version and the jar's SHA-256: what pom.xml asks for.
DEPS="
tech/kwik/kwik/0.12.3 fc135bd50e5ad085473bd642a4972ae83d5fc6b3edbadeb69a13a01623b2694e
tech/kwik/agent15/4.0 46eeb97aab499b3884b659f9d7b7db24a03326265df521481d2023a8f8d8c621
at/favre/lib/hkdf/2.0.0 65aa13f71a1a8b9cac439504af213d761fef9b002b6d06f06c16e50f86ec422b
com/io7m/repackage/io/whitfin/io.whitfin.siphash/2.0.1 95b6678908a4d69c0ef6510e960fae2d38511a57e13fc1b4408c658162c3a07f
"

mkdir -p lib
echo "$DEPS" | while read -r gav sum; do
    [ -n "$gav" ] || continue
    version=${gav##*/}
    rest=${gav%/*}
    artifact=${rest##*/}
    jar="lib/$artifact-$version.jar"
    if [ ! -f "$jar" ]; then
        echo "fetching $artifact $version" >&2
        curl -fsSL -o "$jar.part" "$CENTRAL/$gav/$artifact-$version.jar"
        mv "$jar.part" "$jar"
    fi
    if ! echo "$sum  $jar" | sha256sum -c --status; then
        echo "$jar does not have the expected SHA-256; remove it and try again" >&2
        rm -f "$jar"
        exit 1
    fi
done
LIBS=$(ls lib/*.jar | tr '\n' ':')

rm -rf build
mkdir -p build/classes/pfrelay build/classes/main build/classes/test build/classes/conformance

# pfrelay, from the sources next door, so that the two always match.
javac $JAVAC_FLAGS -d build/classes/pfrelay $(find ../java/src/main/java -name '*.java')
jar --create --file build/pfrelay.jar -C build/classes/pfrelay .

javac $JAVAC_FLAGS -cp "build/pfrelay.jar:$LIBS" -d build/classes/main $(find src/main/java -name '*.java')
jar --create --file build/pfrelay-quic.jar -C build/classes/main .

javac $JAVAC_FLAGS -cp "build/pfrelay.jar:build/pfrelay-quic.jar:$LIBS" -d build/classes/conformance \
    $(find src/conformance/java -name '*.java')
jar --create --file build/pfrelay-quic-conformance.jar \
    --main-class io.github.wushilin.pfrelayquic.conformance.Driver -C build/classes/conformance .

# The tests live in the SDK's package, to reach what is package-private.
javac $JAVAC_FLAGS -cp "build/pfrelay.jar:build/classes/main:$LIBS" -d build/classes/test $(find src/test/java -name '*.java')
java -cp "build/pfrelay.jar:build/classes/main:build/classes/test:$LIBS" io.github.wushilin.pfrelayquic.TestMain
