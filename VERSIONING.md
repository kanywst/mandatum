# Versioning and compatibility

Mandatum follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

There are two things users depend on, and they are versioned separately because they change at different rates and breaking them costs different amounts.

## 1. The Go API

Versioned by the repository's git tags: `vMAJOR.MINOR.PATCH`.

| Change | Bump |
| --- | --- |
| Removing or renaming an exported symbol, changing a signature | MAJOR |
| Adding an exported symbol, adding a functional option | MINOR |
| Fixes with no API change | PATCH |

Before v1.0.0 the API may change in any minor release, per SemVer §4. Each such change is called out in [CHANGELOG.md](CHANGELOG.md) with the migration.

From v1.0.0, a major version bump means a new module path (`/v2`), so an incompatible release can never be picked up by an unsuspecting `go get`.

## 2. The wire format

The Delegation Assertion format is versioned independently by the `mdt.v` claim, because a deployment upgrades verifiers and issuers at different times and the two must interoperate across that gap.

- `mdt.v` is an integer. It increments only for a change that an older verifier could misinterpret.
- A verifier MUST reject an assertion whose `mdt.v` it does not implement. Best-effort interpretation of an unknown version is how a narrowing rule gets silently skipped.
- Adding an optional claim that an older verifier can safely ignore does not bump `mdt.v`. Anything affecting verification, attenuation, or sequence evaluation does.
- A release supporting a new `mdt.v` also supports the previous one for at least one MAJOR cycle, so issuers and verifiers can be rolled separately.

The relationship between the two is recorded in every release note: which `mdt.v` values a version accepts and which it issues.

## Supported Go versions

The `go` directive in `go.mod` is the minimum, and CI builds against it as well as against the current release. It is deliberately not the newest Go: requiring a toolchain released weeks ago is a barrier for anyone whose build environment moves more slowly than this project does.

Raising the minimum is a MINOR bump before v1.0 and a MAJOR bump after, and needs a reason in the pull request beyond a language feature being convenient.

## Deprecation

Nothing is removed without a deprecation period.

1. The symbol or behaviour is marked deprecated in the code, in [CHANGELOG.md](CHANGELOG.md), and in the release notes, with the replacement named.
2. It keeps working, unchanged, for at least **two MINOR releases** or **six months**, whichever is longer.
3. It is removed only in a MAJOR release.

A deprecation notice always says what to use instead. A deprecation without a migration path is a bug in the deprecation.

### The exception

A deprecation period does not apply where keeping a behaviour would leave users insecure — for example a verification path found to be unsound. Such a change ships as a patch release, is announced as a security advisory per [SECURITY.md](SECURITY.md), and the release notes state plainly that it breaks compatibility and why. Silently leaving an authorization bypass in place to honour a deprecation schedule is not a trade this project makes.

## Supported versions

Before v1.0.0, only the latest minor release receives fixes.

From v1.0.0: the latest minor release of the current major, plus the final minor release of the previous major for **twelve months** after the major bump. Security fixes are backported to both.

The current support window is always stated in [SECURITY.md](SECURITY.md).

## Release cadence

Minor releases when there is something worth releasing, targeted at roughly quarterly. Patch releases as needed. There is no schedule that ships a release with nothing in it, and no schedule that delays a security fix.

Pre-releases use SemVer pre-release identifiers (`v0.4.0-rc.1`). A pre-release carries no compatibility promise and is not supported.
