#!/usr/bin/env bash
set -euo pipefail

# Defaults (user can override with env)
: "${CRON_SCHEDULE:=*/55 * * * *}"
: "${OUT_DIR:=/app/out}"
: "${GEN_ARGS:=}"  # extra args if needed in future

# Write the crontab from env
cat >/etc/crontab <<EOF
${CRON_SCHEDULE} cd /app/src && DSTAMP=\$(date -u +%Y%m%d%H%M) && \
exec python -m ruleGenerator.src.generateRuleDocs --out "${OUT_DIR}/ruleMetrics-\${DSTAMP}.ndjson" ${GEN_ARGS}
EOF

echo "[entrypoint] Using schedule: ${CRON_SCHEDULE}"
echo "[entrypoint] Writing to: ${OUT_DIR}"
echo "[entrypoint] Crontab contents:"
cat /etc/crontab

# exec supercronic
exec /usr/local/bin/supercronic /etc/crontab
