# 035 — Scaffold the running version

Status: `open`
Priority: P1

## Problem

The initializer writes this library's own coordinate into a new project. That
coordinate is the git pin in `src/com/kirahowe/secrets/coordinate.edn`, which
commit `8dbff9c` made the one place it is written:

```clojure
{:git {:lib io.github.kirahowe/secrets
       :tag "v0.1.0"
       :sha "89ded34ce8bd146754cc3ec9971d1ea1fd25da28"}}
```

The initializer always runs from a checkout of the library. The README's
bootstrap is `bb -cp /path/to/secrets/src -m com.kirahowe.secrets.init`, and a
`:local/root` or git dependency in a project puts the same source tree on the
classpath. Whatever checkout that is, it writes the pin stored in its tree.

tools.deps requires `:git/sha` beside `:git/tag`, and a commit cannot contain
its own hash, so the sha stored in the tree is always the previous tagged
release. Run the initializer from the v0.2.0 checkout and the new project gets
v0.1.0. A project can never be bootstrapped at the version that bootstrapped
it.

## Evidence

- `default-dependency` in `src/com/kirahowe/secrets/init.clj` is built from the
  `:git` entry of `coordinate.edn`, and nothing else informs it.
- The pin and the newest tag are both `v0.1.0` today, so nothing has broken
  yet. It breaks at the first release after this one.
- A stale pin is not harmless: `v0.1.0` has no `doctor` command and writes v1
  manifests, which current `verify` rejects.
- `release/git-coordinate!`, added in `8dbff9c` and run by
  `clojure -T:build release`, checks the only property that can hold, that the
  pinned tag names the pinned sha. It cannot check that the pin is the release
  being cut.

## Desired outcome

Stop storing a sha. Scaffold the version that is running by locating it at
runtime, from the URL of the `com/kirahowe/secrets/coordinate.edn` resource:

- A tools.deps git dependency lives at `~/.gitlibs/libs/<lib>/<full sha>/`.
  Babashka uses the same layout. The sha is a path segment; take it from there.
- Anything else on a filesystem is a working copy. Ask `git rev-parse HEAD` in
  the directory that contains `src/`.
- A `jar:file:` URL means the library was resolved as a Maven artifact. Write
  `{:mvn/version <version>}` from the coordinate file; the jar was built from
  the tag that says that version, so the two agree by construction.

For the two git cases, write `{:git/tag "v<version>" :git/sha <sha>}` when the
tag `v<version>` exists and names that commit, and `{:git/sha <sha>}` alone
otherwise. A sha alone is a valid tools.deps coordinate.

Then:

- Drop `:tag` and `:sha` from `coordinate.edn`. Keep `:lib`, `:version`, and
  the git `:lib`.
- Drop `release/git-coordinate!` and its test, or rewrite it to a property
  that can hold at release time. `exact-tag!` already checks that `v<version>`
  names `HEAD`, which is the property that matters.
- Say so in the preview. When the running checkout is dirty, or its `HEAD` is
  not on a tag, the pin is a commit a consumer can only resolve once it is
  pushed. The preview should name the coordinate it is about to write and
  flag that case, rather than let a consumer find out at resolve time.
- Keep the locator pure. One function takes the resource URL and an injected
  `git` runner and returns the coordinate, so the three shapes are unit tests
  over strings. The initialization smoke script and the `verify` skill cover
  the real path.
- Decide what `coordinate_test.clj` holds the README to once the pin is
  computed. The README currently shows the `v0.1.0` pin as an example. Either
  the test resolves `v<version>` in the repository and skips when the tag is
  not fetched (CI checkouts are shallow), or the README shows a placeholder.

The Maven switch at Clojars time is then already in place: the jar case writes
`:mvn/version`, and no code path stores a sha anywhere.

## Acceptance criteria

- [ ] From a working copy at tag vX, the initializer writes
      `{:git/tag "vX" :git/sha <HEAD>}`.
- [ ] From an untagged commit it writes `{:git/sha <HEAD>}` and the preview
      says the commit must be pushed before a consumer can resolve it.
- [ ] From a `~/.gitlibs` checkout it writes that checkout's sha, with the tag
      when the tag names it.
- [ ] From the jar it writes `{:mvn/version <version>}`.
- [ ] `coordinate.edn` stores no sha, and nothing else in the repository
      hand-copies one.
- [ ] The README's example agrees with what a released checkout writes, by
      whichever mechanism the fix chooses, and `coordinate_test.clj` enforces it.

## Non-goals

- Publishing to Clojars, or making the Maven coordinate the default before an
  artifact exists.
- Changing how a consumer's `bb.edn` or `deps.edn` is merged; only the value
  written under the library's key changes.

## Dependencies / related files

- `src/com/kirahowe/secrets/coordinate.edn`, `src/com/kirahowe/secrets/init.clj`
- `build/com/kirahowe/secrets/release.clj`, `build.clj`
- `test/com/kirahowe/secrets/coordinate_test.clj`,
  `test/com/kirahowe/secrets/release_test.clj`,
  `test/com/kirahowe/secrets/publish_policy_test.clj` (its fixture copies
  `coordinate.edn` into the temporary repository)
- `.github/scripts/smoke-project-initialization.sh`, `.claude/skills/verify`
- README: the quickstart bootstrap command and the Releasing section.

## Verification

- `release_test`, `publish_policy_test`, both full suites, `bb lint`,
  `bb format:check`, and `.github/scripts/smoke-project-initialization.sh`
  pass.
- Filed 2026-09-06 after the review of `8dbff9c`. That commit is the state
  this fix starts from.
