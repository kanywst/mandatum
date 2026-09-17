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
# The space after the colon is optional, because CommonMark makes it optional:
# `[label]:https://example.com` is a definition, and a boundary that misses it
# is the same silent run to the end for anyone who writes them that way.
# Both boundaries are ignored inside a fenced code block. This changelog
# quotes wire format — JSON claim sets, JWS payloads — and a fence holding a
# line that begins `## ` or looks like a link definition (`[^1]: ` is valid
# Markdown) would end the section early. That failure is silent in a way the
# leaking one is not: the triggering line is dropped rather than leaked, so
# the output looks like a shorter entry rather than a wrong one.
#
# A fence closes only on its own delimiter, and on a run at least as long as
# the one that opened it, which is what CommonMark says and what a toggle
# flipping on either character gets wrong: a tilde block quoting a backtick
# block would end at the inner example.
# One pass, because the fence state machine belongs to one program. It was
# two — an extractor and a link rewriter, each tracking fences — and both
# copies had to be corrected together twice, which is the argument against
# having two.
resolved=$(awk -v heading="## [${version}]" -v base="$base" '
  # Absolute URLs, anchors and mail links are left alone; everything else is
  # resolved against the tag.
  function rewrite(line,   out, before, token, target) {
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
    return out line
  }

  # Fence tracking runs from the top of the file, not from the heading:
  # an entry that quotes another entry inside a fence would otherwise open
  # the section at the quotation. The same lines are printed only once the
  # walk is inside the section.
  ! fenced && match($0, /^[[:space:]]*(`{3,}|~{3,})/) {
    marker = substr($0, RSTART, RLENGTH)
    sub(/^[[:space:]]*/, "", marker)
    fence_char = substr(marker, 1, 1)
    fence_len = length(marker)
    fenced = 1
    if (inside) { print }
    next
  }
  fenced {
    if (match($0, /^[[:space:]]*(`{3,}|~{3,})[[:space:]]*$/)) {
      closer = substr($0, RSTART, RLENGTH)
      gsub(/[[:space:]]/, "", closer)
      if (substr(closer, 1, 1) == fence_char && length(closer) >= fence_len) { fenced = 0 }
    }
    if (inside) {
      # A changelog heading swallowed by a fence is ordinary when an entry
      # quotes another entry, and is the symptom of an unclosed fence when
      # the entry then never reaches a boundary. END tells the two apart.
      if ($0 ~ /^## /) { swallowed_heading = 1 }
      print
    }
    next
  }

  index($0, heading) == 1 { inside = 1; next }
  ! inside { next }

  /^## / { ended = 1; exit }
  /^\[[^]]+\]:[[:space:]]*[^[:space:]]/ { ended = 1; exit }

  { print rewrite($0) }

  # Reaching the end of the file with a fence open means the file is
  # malformed, whichever entry was asked for. The consequence is not a
  # cosmetic one: an unclosed fence is closed by whatever fence the next
  # entry opens, so two entries merge into one set of notes with nothing to
  # show for it — and markdownlint does not report an unclosed fence at all,
  # so this is the only place it is caught.
  END {
    if (fenced) { exit 3 }
    # Ran to the end of the file, having passed a heading inside a fence.
    # The oldest entry legitimately ends at the end of the file; one that
    # swallowed a heading on the way there did not end, it kept going.
    if (inside && ! ended && swallowed_heading) { exit 4 }
  }
' "$changelog") || {
  status=$?
  if [ "$status" -eq 4 ]; then
    echo "$0: the ${version} entry ran to the end of $changelog through a heading inside a code fence." >&2
    echo "A fence somewhere in the entry is closed by a later one rather than by its own." >&2
    exit 1
  fi
  if [ "$status" -eq 3 ]; then
    echo "$0: $changelog has a code fence that is never closed." >&2
    echo "An unclosed fence is closed by the next entry's own delimiter, which merges the two." >&2
    exit 1
  fi
  exit "$status"
}

if [ -z "${resolved//[[:space:]]/}" ]; then
  echo "$0: $changelog has no entry for ${version}." >&2
  echo "A release nobody wrote down is a release nobody can audit." >&2
  exit 1
fi

# Trim the blank lines the section boundaries leave behind.
resolved=$(printf '%s\n' "$resolved" | sed -e '/./,$!d' | awk '
  { lines[NR] = $0 }
  END {
    last = NR
    while (last > 0 && lines[last] ~ /^[[:space:]]*$/) { last-- }
    for (i = 1; i <= last; i++) { print lines[i] }
  }
')

# Printed rather than interpolated. The template is full of backticks and
# the notes carry whatever the changelog says, so an unquoted heredoc would
# put both one editing slip from being executed. Bash does not re-scan the
# result of a parameter expansion, so the changelog's own `$(...)` is inert
# either way — but the template's is not, and this removes the question.
printf '%s\n\n' "$resolved"

cat <<'FIXED'
## Verifying this release

```bash
cosign verify-blob \
  --bundle checksums.txt.bundle \
FIXED

printf "  --certificate-identity-regexp 'https://github.com/%s/.github/workflows/release.yml@.*' \\\\\n" "$repository"

cat <<'FIXED'
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

sha256sum -c checksums.txt
```

An SPDX SBOM is attached. Build provenance is attested and can be checked with `gh attestation verify`.

FIXED

printf 'The full changelog, including which Delegation Assertion format versions every release accepts and issues, is in [CHANGELOG.md](%sCHANGELOG.md).\n' "$base"
