#!/usr/bin/env bash
#
# Fail if any transitive dependency carries a license outside the CNCF
# allowlist. Run locally with `make license-check`; CI runs the same script.
#
# The check exists because CNCF sandbox applications are auto-closed for
# non-allowlisted transitive dependency licenses, and because discovering that
# at application time means rewriting code rather than swapping a dependency.

set -euo pipefail

ALLOWLIST="$(dirname "$0")/cncf-allowed-licenses.txt"
MODULE="$(go list -m)"

if ! command -v go-licenses >/dev/null 2>&1; then
  echo "go-licenses not found. Install it with:" >&2
  echo "  go install github.com/google/go-licenses@latest" >&2
  exit 127
fi

# Strip comments and blank lines from the allowlist.
mapfile -t allowed < <(grep -v '^[[:space:]]*#' "$ALLOWLIST" | grep -v '^[[:space:]]*$')

is_allowed() {
  local candidate="$1"
  for entry in "${allowed[@]}"; do
    [[ "$candidate" == "$entry" ]] && return 0
  done
  return 1
}

echo "Checking dependency licenses for ${MODULE} against the CNCF allowlist."

violations=0
unknown=0

# go-licenses csv emits: package,license-url,license-name
while IFS=, read -r pkg url license; do
  [[ -z "${pkg:-}" ]] && continue

  # The module's own packages are Apache-2.0 by definition.
  [[ "$pkg" == "$MODULE"* ]] && continue

  case "$license" in
    Unknown|"")
      echo "UNKNOWN  ${pkg} (${url:-no license file found})"
      unknown=$((unknown + 1))
      continue
      ;;
  esac

  if is_allowed "$license"; then
    continue
  fi

  echo "DENIED   ${pkg}: ${license}"
  violations=$((violations + 1))
done < <(go-licenses csv ./... 2>/dev/null)

if (( unknown > 0 )); then
  echo
  echo "${unknown} dependency license(s) could not be determined."
  echo "An undetermined license is treated as a failure: the project cannot"
  echo "assert compliance for a license it has not identified."
fi

if (( violations > 0 )); then
  echo
  echo "${violations} dependency license(s) are outside the CNCF allowlist."
  echo "See hack/cncf-allowed-licenses.txt. Replace the dependency; a"
  echo "Governing Board exception is rarely granted."
fi

if (( violations > 0 || unknown > 0 )); then
  exit 1
fi

echo "All dependency licenses are on the CNCF allowlist."
