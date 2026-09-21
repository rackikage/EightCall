#!/usr/bin/env bash
# Pack FLEET into dist/FLEET.tar.gz (excludes build output, keys, and dist itself).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p FLEET/dist
COPYFILE_DISABLE=1 tar -czf FLEET/dist/FLEET.tar.gz \
  --exclude 'FLEET/dist' --exclude 'node_modules' --exclude 'FLEET/node/dist' \
  --exclude 'authorized_keys' --exclude '.DS_Store' FLEET
shasum -a 256 FLEET/dist/FLEET.tar.gz | tee FLEET/dist/FLEET.tar.gz.sha256
