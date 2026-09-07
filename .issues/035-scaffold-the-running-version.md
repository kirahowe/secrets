# 035 — Scaffold the running version

Status: `resolved`
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

- [x] From a working copy at tag vX, the initializer writes
      `{:git/tag "vX" :git/sha <HEAD>}`.
- [x] From an untagged commit it writes `{:git/sha <HEAD>}` and the preview
      says the commit must be pushed before a consumer can resolve it.
- [x] From a `~/.gitlibs` checkout it writes that checkout's sha, with the tag
      when the tag names it.
- [x] From the jar it writes `{:mvn/version <version>}`.
- [x] `coordinate.edn` stores no sha, and nothing else in the repository
      hand-copies one.
- [x] The README's example agrees with what a released checkout writes, by
      whichever mechanism the fix chooses, and `coordinate_test.clj` enforces it.

## Resolution

Resolved 2026-09-06, more simply than proposed above. Nothing has been
published, so the previous pin needed no compatibility.

`coordinate.edn` holds `:lib`, `:version`, and `:git-lib`, and no commit.
`init/library-dependency` takes the URL of the coordinate resource, the
coordinates, and a git runner, and returns the `{lib coordinate}` entry for the
library that is running. A `file:` URL is a source checkout: git is asked, in
the directory the resource was loaded from, for `HEAD` and for the tags that
point at it, and the entry is `{:git/tag "v<version>" :git/sha <HEAD>}` when
the release tag is among them and `{:git/sha <HEAD>}` otherwise. Any other URL
is the jar, and the entry is `{:mvn/version <version>}`. There is no separate
`~/.gitlibs` case: tools.gitlibs materializes a library as a git worktree,
which answers `git rev-parse HEAD` like any checkout. A source tree outside git
is refused with a message saying so.

The dependency is located once per run, in a delay, so `--help` and argument
errors never run git. The preview names the coordinate in full, because a
bb.edn hunk redacts the commit as an opaque token, and when the commit is not
a release tag it says to push it before another machine resolves the project.

`release/git-coordinate!` and its test are gone. `exact-tag!` already checks
that `v<version>` names `HEAD`, which is the property that matters. The README
shows the git coordinate with the tag and a placeholder in place of the
commit. `coordinate_test.clj` holds the README's tag to `v<version>` and its
Maven version to `:version`, refuses a forty-hex commit in the README, checks
that the coordinate file has no commit, and checks that the initializer's
dependency is this checkout's `HEAD`. The three URL shapes and the refusal are
unit tests over a fake git.

The initialization smoke script asserts that the scaffolded `bb.edn` pins the
checkout's `HEAD`, then runs the consumer's task with the coordinate
overridden to the checkout through `-Sdeps`, so it exercises the code under
test whether or not the commit is pushed. Resolving the pin from GitHub in CI
was not an option: a pull request's merge commit is never there.

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
- Run 2026-09-06 on the fix: all of the above pass. The initializer was also
  run by hand from the development jar, which wrote `{:mvn/version "0.1.0"}`,
  from a clone whose `HEAD` carried `v0.1.0`, which wrote the tag and that
  commit, and from a source tree copied out of git, which was refused. The one
  failure in both suites, `rendered-book-is-compliant-test`, came from a
  `bb book:watch` serving `book/rendered` at the time and is unrelated.
