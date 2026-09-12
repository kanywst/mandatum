#!/usr/bin/env bash
#
# Check, or update, the marker each translation carries recording which
# version of its English source it was made from.
#
#   hack/translations.sh check    report translations whose source has moved on
#   hack/translations.sh update   re-stamp every translation as current
#
# check always exits zero. It reports; it does not gate. English is normative,
# so a translation behind its source is usable, and blocking an English
# correction until someone can translate it would make the documentation worse
# rather than better. Read the output, not the exit code.
#
# The marker is a digest of the English file's contents rather than a commit
# hash. A commit hash cannot name the commit that contains it, so a change and
# its translation landing together can only point the marker at the commit
# before them — which reads as "this section is untranslated" when it is not.
# A content digest has no such problem and can be checked mechanically.
#
# A stale marker is not a build failure. It is a fact a reader needs: English
# is normative, so a translation behind its source is usable but incomplete,
# and pretending otherwise is the actual hazard.

set -euo pipefail

readonly MARKER_PREFIX='translated-from:'

usage() {
  echo "usage: $0 {check|update}" >&2
  exit 2
}

# Which checksum tool exists is a property of the machine, not of each file,
# so it is resolved once.
if command -v sha256sum >/dev/null 2>&1; then
  SHA256=(sha256sum)
else
  SHA256=(shasum -a 256)
fi

digest_of() {
  "${SHA256[@]}" "$1" | cut -d' ' -f1
}

# English source for a translation: docs/x.ja.md -> docs/x.md
source_of() {
  local translation="$1"
  local dir base
  dir=$(dirname "$translation")
  base=$(basename "$translation")
  echo "${dir}/${base%.*.md}.md"
}

recorded_digest() {
  # No match is a normal outcome, not an error, so grep's exit status is
  # swallowed deliberately: under `set -e` it would otherwise abort the run
  # on the very case this function exists to report.
  grep -oE "${MARKER_PREFIX}[^\n]*sha-256:[0-9a-f]{64}" "$1" 2>/dev/null |
    tail -1 | sed -E 's/.*sha-256://' || true
}

# Language suffixes this project uses. Matching '*.*.md' would catch any
# two-dot filename — a dated snapshot, say — and report it as a translation
# with no source. Add a code here when a language is added.
readonly LANGUAGES=(ja)

translations() {
  local lang
  for lang in "${LANGUAGES[@]}"; do
    find . -name "*.${lang}.md" -not -path './.git/*'
  done | sort
}

mode="${1:-}"
case "$mode" in
  check|update) ;;
  *) usage ;;
esac

stale=0
marker_line=""
checked=0

while IFS= read -r translation; do
  [ -n "$translation" ] || continue
  source=$(source_of "$translation")

  if [ ! -e "$source" ]; then
    echo "orphan: $translation has no English source at $source" >&2
    stale=1
    continue
  fi

  checked=$((checked + 1))
  want=$(digest_of "$source")
  have=$(recorded_digest "$translation")

  if [ "$have" = "$want" ]; then
    continue
  fi

  if [ "$mode" = update ]; then
    if [ -z "$have" ]; then
      echo "no marker in $translation; add one reading: *${MARKER_PREFIX} sha-256:<64 hex digits>*" >&2
      stale=1
      continue
    fi
    # Rewrite in place, beside the file rather than in a temp directory so
    # this works wherever the repository does. The substitution is confined
    # to the marker line: a document may quote other digests, and a blanket
    # replace would rewrite those too.
    # Only the last marker line is rewritten. A document may quote an
    # example marker in prose — docs/i18n.md documents the format, and a
    # translation of it would — and a blanket substitution would rewrite the
    # illustration too.
    tmp="${translation}.tmp"
    marker_line=$(grep -nE "${MARKER_PREFIX}[^\n]*sha-256:[0-9a-f]{64}" "$translation" |
      tail -1 | cut -d: -f1)
    sed -E "${marker_line}s/sha-256:[0-9a-f]{64}/sha-256:${want}/" "$translation" > "$tmp"
    mv "$tmp" "$translation"
    echo "updated $translation"
  else
    if [ -z "$have" ]; then
      echo "::warning file=${translation#./}::no translated-from marker; a reader cannot tell how current this is"
    else
      echo "::warning file=${translation#./}::$source has changed since this was translated (recorded sha-256:${have:0:12}…, current sha-256:${want:0:12}…)"
    fi
    echo "stale: $translation (source: $source)"
    stale=1
  fi
done < <(translations)

if [ "$mode" = check ]; then
  if [ "$stale" -eq 0 ]; then
    echo "all $checked translation(s) are current"
  else
    echo
    echo "Run 'make translations' after bringing the translations up to date."
    echo "English is normative, so this does not block a merge — see docs/i18n.md."
  fi
fi

exit 0
