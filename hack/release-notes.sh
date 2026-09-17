#!/usr/bin/env bash
#
# Print the release notes for a version.
#
#   hack/release-notes.sh 0.1.0
#
# The notes are that version's CHANGELOG section, followed by how to verify
# the artifacts. Not a pointer to the changelog: a release page that says
# "see CHANGELOG.md" makes the reader leave the page they are on to find out
# what they are being offered, and whoever is reading it is usually deciding
# whether to upgrade rather than browsing.
#
# There is one place the content lives, and it is CHANGELOG.md. This reads
# it; it never restates it. A version with no section is an error, because a
# release nobody wrote down is a release nobody can audit — the same check
# the release workflow used to make with grep, now made by the thing that
# needs the section rather than beside it.
#
# Relative links are rewritten to absolute ones pinned at the tag. A release
# page is read outside the repository, and a link to ROADMAP.md that resolves
# against whatever `main` says today is a link to a document that has moved
# on from the release it describes.

set -euo pipefail

usage() {
  echo "usage: $0 <version>   # the version without the leading v, e.g. 0.1.0" >&2
  exit 2
}

version="${1:-}"
[ -n "$version" ] || usage

changelog="${CHANGELOG_FILE:-CHANGELOG.md}"
repository="${GITHUB_REPOSITORY:-kanywst/mandatum}"
tag="v${version}"
base="https://github.com/${repository}/blob/${tag}/"

[ -f "$changelog" ] || { echo "$0: no $changelog here" >&2; exit 1; }

# The section runs from this version's heading to the next release heading,
# or to the block of reference-style link definitions the file ends with.
# Matched at the start of the line so that a version mentioned in prose
# cannot open a section.
#
# The second boundary is not decoration. Those definitions sit after the last
# heading rather than under it, so the oldest section in the file has no
# heading below it to stop at and would run to the end — silently, and only
# for the oldest section, which is exactly the one a first release publishes.
# Both boundaries are ignored inside a fenced code block. This changelog
# quotes wire format — JSON claim sets, JWS payloads — and a fence holding a
# line that begins `## ` or looks like a link definition (`[^1]: ` is valid
# Markdown) would end the section early. That failure is silent in a way the
# last one was not: the triggering line is dropped rather than leaked, so
# the output looks like a shorter entry rather than a wrong one.
section=$(awk -v heading="## [${version}]" '
  index($0, heading) == 1 { inside = 1; next }
  inside && /^[[:space:]]*```/ { fenced = !fenced; print; next }
  inside && fenced { print; next }
  inside && /^## / { exit }
  inside && /^\[[^]]+\]:[[:space:]]/ { exit }
  inside { print }
  END { if (fenced) { exit 3 } }
' "$changelog") || {
  status=$?
  if [ "$status" -eq 3 ]; then
    echo "$0: the ${version} entry opens a code fence it never closes" >&2
    exit 1
  fi
  exit "$status"
}

if [ -z "${section//[[:space:]]/}" ]; then
  echo "$0: $changelog has no entry for ${version}." >&2
  echo "A release nobody wrote down is a release nobody can audit." >&2
  exit 1
fi

# Rewrite relative Markdown links. Absolute URLs, anchors and mail links are
# left alone, and fenced code blocks are skipped: a JSON example containing
# the same two characters is not a link.
resolved=$(printf '%s\n' "$section" | awk -v base="$base" '
  /^[[:space:]]*```/ { fenced = !fenced; print; next }
  fenced { print; next }
  {
    line = $0
    out = ""
    while (match(line, /\]\([^)]*\)/)) {
      before = substr(line, 1, RSTART - 1)
      token = substr(line, RSTART, RLENGTH)
      target = substr(token, 3, RLENGTH - 3)
      if (target ~ /^https?:\/\// || target ~ /^#/ || target ~ /^mailto:/) {
        out = out before token
      } else {
        out = out before "](" base target ")"
      }
      line = substr(line, RSTART + RLENGTH)
    }
    print out line
  }
')

# Trim the blank lines the section boundaries leave behind.
resolved=$(printf '%s\n' "$resolved" | sed -e '/./,$!d' | awk '
  { lines[NR] = $0 }
  END {
    last = NR
    while (last > 0 && lines[last] ~ /^[[:space:]]*$/) { last-- }
    for (i = 1; i <= last; i++) { print lines[i] }
  }
')

cat <<EOF
${resolved}

## Verifying this release

\`\`\`bash
cosign verify-blob \\
  --bundle checksums.txt.bundle \\
  --certificate-identity-regexp 'https://github.com/${repository}/.github/workflows/release.yml@.*' \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
  checksums.txt

sha256sum -c checksums.txt
\`\`\`

An SPDX SBOM is attached. Build provenance is attested and can be checked with \`gh attestation verify\`.

The full changelog, including which Delegation Assertion format versions every release accepts and issues, is in [CHANGELOG.md](${base}CHANGELOG.md).
EOF
