#!/usr/bin/env bash
# Big Bounty worker installer — intended to run as root on the VM "New",
# typically via an Azure VM runCommand so no inbound SSH is needed.
#
# Secrets are NOT baked into this script. They are written to
# /etc/bigbounty/worker.env (chmod 600) from environment variables that the
# caller supplies as PROTECTED runCommand parameters, e.g.:
#   AzureWebJobsStorage, BIGBOUNTY_JOBS_QUEUE, BIGBOUNTY_JOBS_TABLE,
#   BIGBOUNTY_AUTH_TABLE, BIGBOUNTY_RESULTS_CONTAINER, BROWSERBASE_API_KEY,
#   OPENROUTER_BUGBOUNTY / NVIDIA_BUGBOUNTY..., BIGBOUNTY_MAX_CONCURRENCY, etc.
#
# Code delivery (the VM has restricted outbound and may not reach GitHub):
#   Preferred: BIGBOUNTY_PKG_URL = a short-lived blob SAS URL to a tar.gz of the
#              repo (engine lib/ + templates/ + azure/worker). The VM can always
#              reach its own storage account.
#   Fallback:  BIGBOUNTY_REPO_URL (+ optional token) for a git clone, only if
#              outbound git is permitted.
set -euo pipefail

APP_DIR=/opt/bigbounty
ENV_DIR=/etc/bigbounty
ENV_FILE="$ENV_DIR/worker.env"

echo "[bb] installing prerequisites"
if ! command -v node >/dev/null 2>&1 || [ "$(node -v | cut -c2- | cut -d. -f1)" -lt 20 ]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - || true
  apt-get install -y nodejs || (apt-get update && apt-get install -y nodejs)
fi
command -v node >/dev/null 2>&1 || { echo "[bb] node install failed"; exit 1; }

echo "[bb] fetching application code"
mkdir -p "$APP_DIR"
if [ -n "${BIGBOUNTY_PKG_URL:-}" ]; then
  tmp=$(mktemp /tmp/bb-pkg.XXXXXX.tgz)
  curl -fsSL "$BIGBOUNTY_PKG_URL" -o "$tmp"
  tar -xzf "$tmp" -C "$APP_DIR" --strip-components="${BIGBOUNTY_PKG_STRIP:-0}"
  rm -f "$tmp"
elif [ -n "${BIGBOUNTY_REPO_URL:-}" ]; then
  rm -rf "$APP_DIR.git" && git clone --depth 1 "$BIGBOUNTY_REPO_URL" "$APP_DIR.src" && cp -a "$APP_DIR.src/." "$APP_DIR/"
else
  echo "[bb] no BIGBOUNTY_PKG_URL or BIGBOUNTY_REPO_URL provided"; exit 1
fi

echo "[bb] installing dependencies (engine + worker)"
cd "$APP_DIR" && npm ci --omit=dev 2>/dev/null || npm install --omit=dev
cd "$APP_DIR/azure/worker" && npm ci --omit=dev 2>/dev/null || npm install --omit=dev

echo "[bb] writing env file (600)"
mkdir -p "$ENV_DIR"; : > "$ENV_FILE"; chmod 600 "$ENV_FILE"
for k in AzureWebJobsStorage BIGBOUNTY_STORAGE_CONNECTION BIGBOUNTY_JOBS_QUEUE \
         BIGBOUNTY_JOBS_TABLE BIGBOUNTY_AUTH_TABLE BIGBOUNTY_RESULTS_CONTAINER \
         BIGBOUNTY_MAX_CONCURRENCY BIGBOUNTY_JOB_TIMEOUT_MS BIGBOUNTY_MAX_ATTEMPTS \
         BROWSERBASE_API_KEY OPENROUTER_BUGBOUNTY NVIDIA_BUGBOUNTY \
         nvidia_bugbounty_2 nvidia_bugbounty_3 nvidia_bugbounty_4 nvidia_bugbounty_5 nvidia_bugbounty_6; do
  v="${!k:-}"; [ -n "$v" ] && printf '%s=%s\n' "$k" "$v" >> "$ENV_FILE"
done

echo "[bb] installing systemd service"
cp "$APP_DIR/azure/worker/bigbounty-worker.service" /etc/systemd/system/bigbounty-worker.service
systemctl daemon-reload
systemctl enable bigbounty-worker
systemctl restart bigbounty-worker
sleep 2
systemctl --no-pager --full status bigbounty-worker | head -20 || true
echo "[bb] done"
