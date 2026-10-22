#!/usr/bin/env bash
# Vercel build: publishes the phone version of PhishGuard as a static site (public/).
set -euo pipefail
cd "$(dirname "$0")/.."
rm -rf public && mkdir -p public
cp web/phishguard_app.html public/index.html
bash web/fetch_ocr.sh >/dev/null          # on-device screenshot reader → web/ocr/
cp -r web/ocr public/ocr
echo "public/ ready: $(du -sh public | cut -f1)"
