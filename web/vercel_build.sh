#!/usr/bin/env bash
# Vercel build: publishes the phone version of PhishGuard as a static site (public/).
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf public && mkdir -p public
[ "$(grep -c '</head>' web/phishguard_app.html)" = 1 ] || { echo "phishguard_app.html must have exactly one </head>" >&2; exit 1; }
# installable app: icons + manifest, and their <head> tags (web/pwa/ is written by build_pg.py)
awk -v head="$(cat web/pwa/head.html)" '/<\/head>/ && !done { sub(/<\/head>/, head "\n</head>"); done = 1 } { print }' \
  web/phishguard_app.html > public/index.html
cp -r web/pwa/icons web/pwa/favicon.ico web/pwa/manifest.webmanifest public/
bash web/fetch_ocr.sh >/dev/null          # on-device screenshot and QR readers → web/ocr/
cp -r web/ocr public/ocr
echo "public/ ready: $(du -sh public | cut -f1)"
