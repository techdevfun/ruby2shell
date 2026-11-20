#!/usr/bin/env bash
# Capture the demo transcript from the REAL CLI (no hand-edited output).
# Fixture Ruby installs are dirs with a fake `ruby` shell script
# printing a fixture -v output on -v (see examples/ for provenance):
#   - 3.4.12 (RECORDED -v from the real Ruby built from source on
#     this machine, 20/11/2026) + default Rails app: EXPOSED
#   - 3.4.13 (representative format, fixed): SAFE
#   - 3.2.0 (representative format, EOL, no fix): AT-RISK
# Part 5 checks the fixed install against the same Rails app -> SAFE.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH=/tmp/ruby2shell-demo
BIN="$SCRATCH/bin"
rm -rf "$SCRATCH"
mkdir -p "$BIN" "$ROOT/demo"
ln -sf "$ROOT/dist/cli.js" "$BIN/ruby2shell"
chmod +x "$ROOT/dist/cli.js"
export PATH="$BIN:$PATH"

WORK="$SCRATCH/fleet"
mkdir -p "$WORK"
make_fake_ruby() {
  local name="$1" version_file="$2"
  mkdir -p "$WORK/$name/bin"
  cat > "$WORK/$name/bin/ruby" <<EOF
#!/bin/sh
if [ "\$1" = "-v" ]; then cat "$version_file"; exit 0; fi
exit 0
EOF
  chmod +x "$WORK/$name/bin/ruby"
}
make_fake_ruby "ruby-3412" "$ROOT/examples/ruby-v-3.4.12.txt"
make_fake_ruby "ruby-3413" "$ROOT/examples/ruby-v-3.4.13.txt"
make_fake_ruby "ruby-320" "$ROOT/examples/ruby-v-3.2.0.txt"

APP="$SCRATCH/app-rails"
cp -r "$ROOT/examples/app-rails" "$APP"
OUT="$ROOT/demo/transcript.txt"
{
  echo "# ruby2shell demo - real CLI output on fixture Ruby installs"
  echo "# (fake ruby binaries print fixture -v outputs from examples/;"
  echo "#  the 3.4.12 -v text is RECORDED from the real Ruby built"
  echo "#  from source on this machine, 20/11/2026; the 3.4.13 /"
  echo "#  3.2.0 texts are representative format; the fleet below"
  echo "#  is synthetic, the Rails app is a synthetic fixture)"
  echo ""
  echo "\$ ruby2shell scan --dirs ruby-3412 ruby-3413 ruby-320 --app app-rails --no-system"
  ruby2shell scan --dirs "$WORK/ruby-3412" "$WORK/ruby-3413" "$WORK/ruby-320" --app "$APP" --no-system || echo "exit: $?"
  echo ""
  echo "\$ ruby2shell check ruby-3412 --app app-rails"
  ruby2shell check "$WORK/ruby-3412" --app "$APP" || echo "exit: $?"
  echo ""
  echo "\$ ruby2shell config-scan app-rails"
  ruby2shell config-scan "$APP" || echo "exit: $?"
  echo ""
  echo "\$ ruby2shell playbook"
  ruby2shell playbook
  echo ""
  echo "# Upgrade the fixture to the fixed Ruby and check again"
  echo "\$ ruby2shell check ruby-3413 --app app-rails"
  ruby2shell check "$WORK/ruby-3413" --app "$APP" || echo "exit: $?"
} > "$OUT" 2>&1

echo "transcript written: $OUT ($(wc -l < "$OUT") lines)"
