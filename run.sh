#!/bin/sh
set -eu

export NODE_ENV="${NODE_ENV:-production}"
export DOUYIN_CLOUD="${DOUYIN_CLOUD:-true}"
export PORT="${PORT:-8000}"
export DB_PATH="${DB_PATH:-/data/database.sqlite}"
export DOUYIN_APP_ID="${DOUYIN_APP_ID:-${APP_ID:-${TT_APP_ID:-}}}"
export DOUYIN_APP_SECRET="${DOUYIN_APP_SECRET:-${APP_SECRET:-${APPSECREAT:-${DOUYIN_APPSECREAT:-}}}}"
export DOUYIN_PAY_SALT="${DOUYIN_PAY_SALT:-${PAY_SALT:-}}"

echo "[run.sh] starting service on port ${PORT}"
echo "[run.sh] env summary: NODE_ENV=${NODE_ENV} DOUYIN_CLOUD=${DOUYIN_CLOUD}"
echo "[run.sh] env summary: DOUYIN_APP_ID=${DOUYIN_APP_ID:-<empty>} APP_SECRET_SET=$( [ -n "${DOUYIN_APP_SECRET:-}" ] && echo yes || echo no ) PAY_SALT_SET=$( [ -n "${DOUYIN_PAY_SALT:-}" ] && echo yes || echo no ) DB_PATH=${DB_PATH}"

exec node dist/server.js
