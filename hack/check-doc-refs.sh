#!/usr/bin/env bash
#
# Fail if a document refers to another document that does not exist, unless
# that document is declared unwritten in the Planned table of docs/README.md.
#
# This exists because the same defect appeared three times: a sentence saying
# "X is documented in `foo.md`", in the present tense, about a file nobody had
# written. Each time it was found by reading rather than by anything checking.
# The author of such a sentence intends to write the file, which is exactly
# why the author is the last person who will notice it is missing.
#
# The inverse is checked too: a document listed as Planned that now exists is
# a stale table entry, and a reader consulting the table would conclude the
# work is outstanding when it is done.

set -euo pipefail

readonly PLANNED_SOURCE="docs/README.md"

# Markdown reference forms this looks at:
#   [text](path/to/doc.md)      relative to the referring file, or to the
#                               repository root when it starts with "/"
#   `path/to/doc.md`            relative to the repository root
#
# The two are held to different standards, deliberately. A link must resolve,
# always: a link to an unwritten document renders as a clickable dead end, and
# declaring it Planned somewhere else does not help the reader who clicked it.
# A mention in prose may point at a document declared Planned, because "this
# will be recorded in X" is a legitimate thing to write about work not done.
#
# Fenced code blocks are stripped first: a sample command containing a path is
# an illustration, not a reference.
strip_fences() {
  awk '/^[[:space:]]*```/ { fence = !fence; next } !fence'
}

# Paths that are patterns rather than references.
is_glob() {
  case "$1" in
    *'*'* | *'?'* | *'['* ) return 0 ;;
    *) return 1 ;;
  esac
}

planned() {
  # Rows of the Planned table name their document in the first cell, in
  # backticks. Everything after the table's blank line is prose.
  [ -f "$PLANNED_SOURCE" ] || return 0
  # shellcheck disable=SC2016  # the backticks below are literal markdown
  awk '/^## Planned/ { inside = 1; next }
       inside && /^## / { inside = 0 }
       inside && /^\| `/ { print }' "$PLANNED_SOURCE" |
    sed -E 's/^\| `([^`]+)`.*/\1/'
}

mapfile -t PLANNED < <(planned)

is_planned() {
  local candidate="$1" entry
  for entry in "${PLANNED[@]}"; do
    [ -n "$entry" ] || continue
    # The table names paths relative to docs/; a reference may be written
    # either way round.
    [ "$candidate" = "$entry" ] && return 0
    [ "$candidate" = "docs/$entry" ] && return 0
    [ "docs/$candidate" = "$entry" ] && return 0
  done
  return 1
}

problems=0
checked=0

while IFS= read -r file; do
  dir=$(dirname "$file")
  stripped=$(strip_fences < "$file")

  # Linked references, resolved against the referring file.
  linked=$(printf '%s\n' "$stripped" |
    grep -oE '\]\([^)#][^)]*\.md[^)]*\)' 2>/dev/null |
    sed -E 's/^\]\(//; s/\)$//; s/#.*$//' || true)

  # Backticked mentions, resolved against the repository root.
  # shellcheck disable=SC2016  # the backticks are literal markdown, not a subshell
  mentioned=$(printf '%s\n' "$stripped" |
    grep -oE '`[A-Za-z0-9._/-]+\.md`' 2>/dev/null |
    tr -d '`' || true)

  while IFS= read -r target; do
    [ -n "$target" ] || continue
    case "$target" in http://*|https://*|mailto:*) continue ;; esac
    is_glob "$target" && continue
    checked=$((checked + 1))

    # GitHub resolves a leading slash against the repository root. Resolving
    # it against the referring directory instead produces a path that may
    # happen to exist, which would accept a broken link silently.
    case "$target" in
      /*) resolved=".${target}" ;;
      *)  resolved="$dir/$target" ;;
    esac
    [ -e "$resolved" ] && continue

    echo "::error file=${file#./}::links to $target, which does not exist"
    echo "broken link: ${file#./} -> $target"
    if is_planned "${target#/}"; then
      echo "  It is listed as Planned, which permits mentioning it in prose but not linking to it:"
      echo "  a link renders as a clickable dead end whatever the table says."
    fi
    problems=$((problems + 1))
  done <<< "$linked"

  while IFS= read -r target; do
    [ -n "$target" ] || continue
    is_glob "$target" && continue
    checked=$((checked + 1))
    # A bare filename in backticks may be a sibling of the referring file or a
    # path from the root; either resolving is enough.
    [ -e "$target" ] && continue
    [ -e "$dir/$target" ] && continue
    if is_planned "$target"; then
      continue
    fi
    echo "::error file=${file#./}::mentions $target, which does not exist and is not listed as Planned in $PLANNED_SOURCE"
    echo "dangling reference: ${file#./} -> $target"
    echo "  Either write it, reword the sentence so it does not claim the document exists,"
    echo "  or add it to the Planned table in $PLANNED_SOURCE."
    problems=$((problems + 1))
  done <<< "$mentioned"
done < <(git ls-files '*.md')

# A Planned entry that now exists is a stale table row: a reader would
# conclude the work is outstanding when it is done.
for entry in "${PLANNED[@]}"; do
  [ -n "$entry" ] || continue
  if [ -e "$entry" ] || [ -e "docs/$entry" ]; then
    echo "::error file=${PLANNED_SOURCE}::$entry is listed as Planned but now exists"
    echo "stale Planned entry: $entry exists; move it to the available table"
    problems=$((problems + 1))
  fi
done

# A reference to a specification rule that does not exist. This check exists
# because the audience rule was enforced in code and referenced by the threat
# model while the specification's section 6 still listed six rules: the
# document pointed at a rule nobody reading it could find, and every check in
# this file passed, because the file it pointed at existed.
SPEC="docs/spec/delegation-assertion.md"
if [ -f "$SPEC" ]; then
  # The rules of section 6 are its top-level numbered list. Count it.
  rules=$(awk '/^## 6\. /{inside=1; next} /^## 6\.[0-9]/{inside=0} /^## 7\. /{inside=0} inside && /^[0-9]+\. /{n=$1; sub(/\./, "", n); if (n+0 > max) max = n+0} END{print max+0}' "$SPEC")
  if [ "$rules" -eq 0 ]; then
    echo "::error file=${SPEC}::could not find the numbered rules of section 6"
    problems=$((problems + 1))
  else
    while IFS= read -r file; do
      while IFS= read -r n; do
        [ -n "$n" ] || continue
        checked=$((checked + 1))
        if [ "$n" -gt "$rules" ] || [ "$n" -lt 1 ]; then
          echo "::error file=${file}::references section 6 rule $n; section 6 has $rules rules"
          echo "$file references a section 6 rule that does not exist: rule $n"
          problems=$((problems + 1))
        fi
      done < <(grep -oE '(§6|section 6) rule [0-9]+' "$file" | grep -oE '[0-9]+$')
    done < <(git ls-files '*.md')
  fi
fi

if [ "$problems" -eq 0 ]; then
  echo "$checked document reference(s) resolve, or are declared unwritten."
  exit 0
fi

echo
echo "$problems problem(s). A sentence in the present tense about a document"
echo "nobody has written is the same defect as a claim the code does not honour."
exit 1
