#!/usr/bin/env bash

set -euo pipefail

jar_file="${1:-}"

if [[ -z "${jar_file}" ]]; then
  echo "usage: $0 <jar-file>" >&2
  exit 2
fi

if [[ ! -f "${jar_file}" ]]; then
  echo "jar not found: ${jar_file}" >&2
  exit 1
fi

jar_path="$(cd "$(dirname "${jar_file}")" && pwd)/$(basename "${jar_file}")"
pom_dir="META-INF/maven/com.kirahowe/secrets"
pom_xml="${pom_dir}/pom.xml"
pom_props="${pom_dir}/pom.properties"

# Read the runtime dependency version from deps.edn rather than duplicating it
# here, so the two can't silently drift apart.
deps_edn_path="$(pwd)/deps.edn"
babashka_cli_version="$(clojure -M -e "(print (get-in (clojure.edn/read-string (slurp \"${deps_edn_path}\")) [:deps (quote org.babashka/cli) :mvn/version]))")"
test -n "${babashka_cli_version}"

mkdir -p target

jar tf "${jar_path}" > target/jar-entries.txt
test -s target/jar-entries.txt
jar tf "${jar_path}" > /dev/null

find src -type f -name '*.clj' | LC_ALL=C sort | sed 's#^src/##' > target/expected-src-entries.txt
test -s target/expected-src-entries.txt

awk '
  /\/$/ { next }
  /^META-INF\// { next }
  { print }
' target/jar-entries.txt | LC_ALL=C sort > target/actual-src-entries.txt
test -s target/actual-src-entries.txt

diff -u target/expected-src-entries.txt target/actual-src-entries.txt

grep -qx "${pom_xml}" target/jar-entries.txt
grep -qx "${pom_props}" target/jar-entries.txt

unzip -tq "${jar_path}"
unzip -p "${jar_path}" "${pom_xml}" > target/jar-pom.xml
unzip -p "${jar_path}" "${pom_props}" > target/jar-pom.properties

test -s target/jar-pom.xml
test -s target/jar-pom.properties

grep -q '<groupId>com.kirahowe</groupId>' target/jar-pom.xml
grep -q '<artifactId>secrets</artifactId>' target/jar-pom.xml
grep -q '<version>0.1.0</version>' target/jar-pom.xml
grep -q '<description>Manage application secrets as a version-controlled, age-encrypted EDN file\.</description>' target/jar-pom.xml
grep -q '<name>MIT</name>' target/jar-pom.xml
grep -q '<url>https://opensource.org/license/mit</url>' target/jar-pom.xml
grep -q '<url>https://github.com/kirahowe/secrets</url>' target/jar-pom.xml
# A release build records the tag it was built from; the development build makes
# no provenance claim, because it copies the live tree at whatever ref is
# checked out. Whichever this jar is, the pom may not advertise a tag that
# disagrees with the version it declares.
if grep -q '<tag>' target/jar-pom.xml; then
  grep -q '<tag>v0.1.0</tag>' target/jar-pom.xml
fi
grep -q '<groupId>org.clojure</groupId>' target/jar-pom.xml
grep -q '<artifactId>clojure</artifactId>' target/jar-pom.xml
grep -q '<version>1.12.4</version>' target/jar-pom.xml

grep -q '^groupId=com.kirahowe$' target/jar-pom.properties
grep -q '^artifactId=secrets$' target/jar-pom.properties
grep -q '^version=0.1.0$' target/jar-pom.properties

inspect_tmpdir="$(mktemp -d)"
trap 'rm -rf "${inspect_tmpdir}"' EXIT

(
  cd "${inspect_tmpdir}"
  clojure -Sdeps "{:paths [\"${jar_path}\"] :deps {org.babashka/cli {:mvn/version \"${babashka_cli_version}\"}}}" \
    -e "(require 'com.kirahowe.secrets 'com.kirahowe.secrets.cli 'com.kirahowe.secrets.age 'com.kirahowe.secrets.manifest)"
)
