#!/usr/bin/env bash
set -euo pipefail

ZIP=$(ls -1 TRUST-AI*.zip 2>/dev/null | sort -V | tail -1 || true)

if [ -n "$ZIP" ]; then
  echo "Found archive: $ZIP"
  rm -rf _app
  mkdir _app
  unzip -q -o "$ZIP" -d _app
  APP_DIR=_app
  if [ ! -f "$APP_DIR/package.json" ]; then
    INNER=$(find _app -maxdepth 3 -name package.json -not -path '*/node_modules/*' | head -1 | xargs -r dirname)
    [ -n "$INNER" ] && APP_DIR="$INNER"
  fi
else
  echo "No archive found, using repository root"
  APP_DIR=.
fi

if [ ! -f "$APP_DIR/package.json" ] || [ ! -f "$APP_DIR/index.html" ]; then
  echo "::error::package.json / index.html not found in '$APP_DIR'"
  ls -la "$APP_DIR" || true
  exit 1
fi

echo "APP_DIR=$APP_DIR"
echo "APP_DIR=$APP_DIR" >> "$GITHUB_ENV"
