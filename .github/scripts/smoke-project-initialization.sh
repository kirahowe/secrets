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

# An empty project gets a bb.edn and the template, and the task the initializer
# wrote then sets and verifies a first secret. The identity is a throwaway key
# file named by SECRETS_AGE_IDENTITY_FILE: --keygen stores its key in the macOS
# Keychain, which this script must never write to and CI does not have.
run_new_case() {
  local consumer="${work_dir}/new-consumer"
  local isolated_home="${work_dir}/new-home"
  local clj_config="${work_dir}/new-clj-config"

  local identity_file="${work_dir}/new-identity.txt"

  mkdir -p "${consumer}" "${isolated_home}" "${clj_config}"
  git -C "${consumer}" init --quiet
  if ! command -v age-keygen > /dev/null; then
    echo "age-keygen is not installed; the smoke test needs it." >&2
    exit 1
  fi
  age-keygen -o "${identity_file}" 2> /dev/null

  (
    cd "${consumer}"
    # tools.deps writes classpath cache data beneath CLJ_CONFIG. Keep that
    # consumer-resolution cache disposable without changing $HOME (which bb's
    # embedded dependency launcher uses to find its installed Clojure tools).
    export CLJ_CONFIG="${clj_config}"

    bb "-Duser.home=${isolated_home}" -cp "${repo_root}/src" -m com.kirahowe.secrets.init \
      --app initializer-smoke-new --apply
    assert_pin bb.edn
    printf '%s' 'smoke-first-secret' | SECRETS_AGE_IDENTITY_FILE="${identity_file}" bb "-Duser.home=${isolated_home}" \
      -Sdeps "${checkout_override}" secrets set :example/api-key
    SECRETS_AGE_IDENTITY_FILE="${identity_file}" bb "-Duser.home=${isolated_home}" \
      -Sdeps "${checkout_override}" secrets verify
  )

  test -f "${consumer}/bb.edn"
  test -f "${consumer}/secrets/secrets.edn.example"
  test -f "${consumer}/secrets/secrets.edn.age"
  test -f "${consumer}/secrets/secrets.edn.manifest"
  # There is no default key file, so nothing may appear under the home's .config.
  if [[ -e "${isolated_home}/.config" ]]; then
    echo "Expected no ${isolated_home}/.config, found:" >&2
    find "${isolated_home}/.config" >&2
    exit 1
  fi
  assert_status "${consumer}" $'?? bb.edn\n?? secrets/secrets.edn.age\n?? secrets/secrets.edn.example\n?? secrets/secrets.edn.manifest'
}

# --keygen needs the macOS Keychain, so without one it must fail before it
# writes anything. Skipped on macOS, where it would store a key in the real
# login Keychain.
run_keygen_without_keychain_case() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo "Skipping the --keygen refusal check on macOS: it has a real Keychain."
    return 0
  fi

  local consumer="${work_dir}/keygen-consumer"
  local isolated_home="${work_dir}/keygen-home"
  mkdir -p "${consumer}" "${isolated_home}"

  local output
  if output="$(cd "${consumer}" && bb "-Duser.home=${isolated_home}" -cp "${repo_root}/src" \
    -m com.kirahowe.secrets.init --app initializer-smoke-keygen --apply --keygen 2>&1)"; then
    echo "Expected init --apply --keygen to fail without a Keychain." >&2
    exit 1
  fi
  if ! grep -q -F -- "--keygen stores the key in the macOS Keychain" <<< "${output}"; then
    echo "Expected the refusal to say --keygen needs the Keychain, got:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
  if [[ -n "$(find "${consumer}" -mindepth 1 -print -quit)" ]]; then
    echo "Expected a refused --keygen to write nothing." >&2
    exit 1
  fi
  if [[ -e "${isolated_home}/.config" ]]; then
    echo "Expected a refused --keygen to create no ${isolated_home}/.config." >&2
    exit 1
  fi
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

run_new_case
run_keygen_without_keychain_case
run_existing_case

echo "Project initialization smoke passed."
