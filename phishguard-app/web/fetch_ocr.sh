#!/usr/bin/env bash
# Downloads the on-device screenshot reader (Tesseract.js, Apache-2.0) into web/ocr/.
# The published phone version serves these files next to phishguard_app.html (publish them as ocr/…),
# because the page that hosts it can only fetch its own files.
set -euo pipefail
cd "$(dirname "$0")"
tmp="$(mktemp -d)"
(cd "$tmp" && npm init -y >/dev/null && npm i --no-save tesseract.js@5.1.1 tesseract.js-core@5.1.1 \
  @tesseract.js-data/eng@1.0.0 @tesseract.js-data/spa@1.0.0 @tesseract.js-data/urd@1.0.0 @tesseract.js-data/hin@1.0.0 >/dev/null)
nm="$tmp/node_modules"
mkdir -p ocr
cp "$nm/tesseract.js/dist/tesseract.min.js" "$nm/tesseract.js/dist/worker.min.js" ocr/
cp "$nm/tesseract.js-core/tesseract-core-simd-lstm.wasm.js" "$nm/tesseract.js-core/tesseract-core-lstm.wasm.js" ocr/
for l in eng spa urd hin; do cp "$nm/@tesseract.js-data/$l/4.0.0_best_int/$l.traineddata.gz" ocr/; done
rm -rf "$tmp"
ls -lh ocr
