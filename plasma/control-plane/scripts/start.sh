#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

echo "building..."
npm run build

echo "starting plasma (single persistent process)..."
exec npm run start
