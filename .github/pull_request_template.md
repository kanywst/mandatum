<!-- Thanks for contributing. CONTRIBUTING.md has the full details. -->

## What this changes

<!-- What problem does it solve? Link the issue. -->

Fixes #

## How you know it works

<!-- Tests added, or how you verified it. "Tests pass" is not an answer on
     its own; say what the new test would have caught. -->

## Checklist

- [ ] `make verify` passes locally
- [ ] Tests added; for a bug fix, a test that fails without the change
- [ ] `docs/spec/` updated if the wire format, verification, or attenuation
      changed — the specification is normative and the code follows it
- [ ] `CHANGELOG.md` updated under Unreleased, if this is user-visible
- [ ] Commits are signed off (`git commit -s`)
- [ ] No path where a failed check results in allowing an action

<!-- That last item is not boilerplate. A verifier that fails open is worse
     than no verifier, because operators believe they are protected. -->
