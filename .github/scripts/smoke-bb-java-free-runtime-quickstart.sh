#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_dir="$(mktemp -d)"
home_dir="${work_dir}/home"
cache_dir="${work_dir}/cache"
config_dir="${work_dir}/config"
repo_copy="${work_dir}/secrets"
example_copy="${repo_copy}/examples/quickstart-bb"
tmp_bb_edn="${work_dir}/bb.edn"

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

mkdir -p "${home_dir}" "${cache_dir}" "${config_dir}" "${repo_copy}/examples"
cp -R "${repo_root}/src" "${repo_copy}/src"
cp -R "${repo_root}/examples/quickstart-bb" "${example_copy}"

grep -q ':paths \["src"\]' "${example_copy}/bb.edn"
grep -q ':deps  {com.kirahowe/secrets {:local/root "../.."}}' "${example_copy}/bb.edn"
sed '/^ :deps  {com.kirahowe\/secrets {:local\/root "\.\.\/\.\."}}$/d; s/:paths \["src"\]/:paths ["src" "..\/..\/src"]/' \
  "${example_copy}/bb.edn" > "${tmp_bb_edn}"
mv "${tmp_bb_edn}" "${example_copy}/bb.edn"

echo "OS: $(uname -a)"
bb --version
age --version 2>&1 | head -n 1

if command -v java >/dev/null 2>&1; then
  echo "java unexpectedly present on PATH: $(command -v java)" >&2
  exit 1
fi

if [[ -n "${JAVA_HOME:-}" ]]; then
  echo "JAVA_HOME unexpectedly set: ${JAVA_HOME}" >&2
  exit 1
fi

export HOME="${home_dir}"
export XDG_CACHE_HOME="${cache_dir}"
export XDG_CONFIG_HOME="${config_dir}"

test ! -e "${HOME}/.deps.clj"
test ! -e "${HOME}/.gitlibs"
test ! -e "${HOME}/.m2"
grep -q ':paths \["src" "\.\.\/\.\.\/src"\]' "${example_copy}/bb.edn"
! grep -q ':deps' "${example_copy}/bb.edn"
! grep -q ':local/root' "${example_copy}/bb.edn"

(
  cd "${example_copy}"
  bb bootstrap
  bb run
  bb verify
)

test ! -e "${HOME}/.deps.clj"
test ! -e "${HOME}/.gitlibs"
test ! -e "${HOME}/.m2"
test -f "${example_copy}/.local/secrets.edn.age"
test -f "${example_copy}/.local/secrets.edn.manifest"

echo "Isolated repo copy: ${repo_copy}"
echo "Cold HOME: ${HOME}"
find "${HOME}" -maxdepth 2 -mindepth 1 | sort
