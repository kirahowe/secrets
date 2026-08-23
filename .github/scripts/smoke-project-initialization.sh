#!/usr/bin/env bash

# Bootstrap with this checkout's source because a consumer cannot yet have the
# dependency wired. After that first command, deliberately run the generated
# task normally so its pinned Git dependency is resolved like a fresh consumer.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
    printf '%s' 'smoke-first-secret' | bb "-Duser.home=${isolated_home}" secrets set :example/api-key
    bb "-Duser.home=${isolated_home}" secrets verify
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

run_case tracked
run_case disposable

echo "Project initialization smoke passed."
