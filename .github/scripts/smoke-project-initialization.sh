#!/usr/bin/env bash

# Bootstrap with this checkout's source because a consumer cannot yet have the
# dependency wired. The initializer pins the commit this checkout is at, which
# is asserted below. The generated task then runs with that coordinate
# overridden to this checkout through -Sdeps, so the consumer half exercises
# the code under test whether or not the commit has been pushed: resolving the
# pin from GitHub needs it there, and a pull request's merge commit never is.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
head_commit="$(git -C "${repo_root}" rev-parse HEAD)"
checkout_override="{:deps {io.github.kirahowe/secrets {:local/root \"${repo_root}\"}}}"
work_dir="$(mktemp -d)"

cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

assert_status() {
  local consumer="$1"
  local expected="$2"
  local actual
  actual="$(git -C "${consumer}" status --porcelain --untracked-files=all)"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "Unexpected public git status for ${consumer}:" >&2
    printf '%s\n' "${actual}" >&2
    echo "Expected:" >&2
    printf '%s\n' "${expected}" >&2
    exit 1
  fi
}

assert_pin() {
  local file="$1"
  if ! grep -q -F ":git/sha \"${head_commit}\"" "${file}"; then
    echo "Expected ${file} to pin this checkout's HEAD ${head_commit}, found:" >&2
    cat "${file}" >&2
    exit 1
  fi
}

run_case() {
  local layout="$1"
  local consumer="${work_dir}/${layout}-consumer"
  local isolated_home="${work_dir}/${layout}-home"
  local clj_config="${work_dir}/${layout}-clj-config"

  mkdir -p "${consumer}" "${isolated_home}" "${clj_config}"
  git -C "${consumer}" init --quiet

  (
    cd "${consumer}"
    # tools.deps writes classpath cache data beneath CLJ_CONFIG. Keep that
    # consumer-resolution cache disposable without changing $HOME (which bb's
    # embedded dependency launcher uses to find its installed Clojure tools).
    export CLJ_CONFIG="${clj_config}"
    mkdir -p "${isolated_home}/.config/initializer-smoke-${layout}"

    bb "-Duser.home=${isolated_home}" -cp "${repo_root}/src" -m com.kirahowe.secrets.init \
      --app "initializer-smoke-${layout}" --layout "${layout}" --apply --keygen
    assert_pin bb.edn
    printf '%s' 'smoke-first-secret' | bb "-Duser.home=${isolated_home}" \
      -Sdeps "${checkout_override}" secrets set :example/api-key
    bb "-Duser.home=${isolated_home}" -Sdeps "${checkout_override}" secrets verify
  )

  test -f "${consumer}/bb.edn"
  test -f "${consumer}/secrets/secrets.edn.example"

  case "${layout}" in
    tracked)
      test -f "${consumer}/secrets/secrets.edn.age"
      test -f "${consumer}/secrets/secrets.edn.manifest"
      test -f "${isolated_home}/.config/initializer-smoke-tracked/key.txt"
      assert_status "${consumer}" $'?? bb.edn\n?? secrets/secrets.edn.age\n?? secrets/secrets.edn.example\n?? secrets/secrets.edn.manifest'
      ;;
    disposable)
      test -f "${consumer}/.local/secrets/secrets.edn.age"
      test -f "${consumer}/.local/secrets/secrets.edn.manifest"
      test -f "${consumer}/.local/secrets/key.txt"
      assert_status "${consumer}" $'?? .gitignore\n?? bb.edn\n?? secrets/secrets.edn.example'
      ;;
    *)
      echo "Unknown layout: ${layout}" >&2
      exit 2
      ;;
  esac
}

# The initializer creates missing files only. A project that already has a
# bb.edn keeps it byte for byte and is told what to add to it.
run_existing_case() {
  local consumer="${work_dir}/existing-consumer"
  local isolated_home="${work_dir}/existing-home"
  local output

  mkdir -p "${consumer}" "${isolated_home}"
  printf '%s\n' ';; mine' '{:tasks {hello {:task (println "hello")}}}' > "${consumer}/bb.edn"
  cp "${consumer}/bb.edn" "${work_dir}/existing-bb.edn"

  output="$(cd "${consumer}" && bb "-Duser.home=${isolated_home}" -cp "${repo_root}/src" \
    -m com.kirahowe.secrets.init --app initializer-smoke-existing --apply)"

  cmp "${consumer}/bb.edn" "${work_dir}/existing-bb.edn"
  test -f "${consumer}/secrets/secrets.edn.example"
  for expected in "bb.edn, under :deps:" "bb.edn, under :tasks:" ":git/sha \"${head_commit}\""; do
    if ! grep -q -F -- "${expected}" <<< "${output}"; then
      echo "Expected the initializer to print '${expected}', got:" >&2
      printf '%s\n' "${output}" >&2
      exit 1
    fi
  done
}

run_case tracked
run_case disposable
run_existing_case

echo "Project initialization smoke passed."
