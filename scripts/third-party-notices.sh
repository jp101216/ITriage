#!/usr/bin/env bash
# Writes THIRD-PARTY-NOTICES.txt: the licenses and copyright notices of every
# Rust crate built into the Windows and Linux apps, and of the bundled fonts.
# The installers carry the file, so run this after any change to Cargo.lock.
#
#   scripts/third-party-notices.sh           rewrite the file
#   scripts/third-party-notices.sh --check   fail if the file is out of date (CI)
#
# Needs cargo-about (the version CI installs is pinned in ci.yml):
#   cargo install cargo-about --version 0.9.3 --locked --features cli
#
# about.toml says which licenses are accepted and where to find the texts
# cargo-about can't find by itself; about.hbs is the layout.
set -euo pipefail
cd "$(dirname "$0")/.."

out=THIRD-PARTY-NOTICES.txt
new=$(mktemp)
trap 'rm -f "$new"' EXIT

if ! cargo about --version >/dev/null 2>&1; then
  echo "cargo-about isn't installed. Install it with:" >&2
  echo "  cargo install cargo-about --version 0.9.3 --locked --features cli" >&2
  exit 2
fi

# --fail: a crate whose license isn't in about.toml's accepted list, or whose
# clarification no longer matches its file, stops here.
cargo about generate --locked --workspace --fail about.hbs > "$new"

{
  printf '\n\n%s\n' "================================================================================"
  printf '%s\n' "Fonts"
  printf '%s\n\n' "================================================================================"
  printf '%s\n' "The app carries Rajdhani, Chakra Petch and Share Tech Mono, each under the"
  printf '%s\n' "SIL Open Font License 1.1."
  for f in src/fonts/LICENSE-*.txt; do
    name=$(basename "$f" .txt)
    name=${name#LICENSE-}
    printf '\n%s\n%s\n%s\n\n' \
      "--------------------------------------------------------------------------------" \
      "${name//-/ }" \
      "--------------------------------------------------------------------------------"
    cat "$f"
  done
} >> "$new"

# One style of line ending, whatever the license files used.
sed -i 's/\r$//' "$new"

if grep -q "has no license file of its own" "$new"; then
  echo "warning: a crate's package has no license file, so the license's standard text" >&2
  echo "was used, without that crate's copyright notice. Search $out for" >&2
  echo "'has no license file of its own' and add a clarification to about.toml." >&2
fi

if [[ "${1:-}" == "--check" ]]; then
  if ! diff -u "$out" "$new" > /dev/null; then
    echo "$out is out of date: the dependencies changed since it was written." >&2
    echo "Run scripts/third-party-notices.sh and commit the result." >&2
    diff -u "$out" "$new" | head -60 >&2 || true
    exit 1
  fi
  echo "$out is up to date."
else
  cat "$new" > "$out"
  echo "Wrote $out ($(wc -c < "$out") bytes)."
fi
