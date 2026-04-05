#!/bin/sh
set -eu

export NODE_ENV="${NODE_ENV:-production}"
export DOUYIN_CLOUD="${DOUYIN_CLOUD:-true}"
export PORT="${PORT:-8000}"
export DB_PATH="${DB_PATH:-/data/database.sqlite}"

echo "[run.sh] starting service on port ${PORT}"

exec node dist/server.js
