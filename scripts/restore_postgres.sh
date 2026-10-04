#!/usr/bin/env bash
set -euo pipefail

BACKUP_FILE="${1:-}"
TARGET_DB="${2:-aegis_restore_test}"

if [[ -z "${BACKUP_FILE}" || ! -f "${BACKUP_FILE}" ]]; then
    echo "[ERROR] Usage: $0 <backup_file.sql.gz> [target_db]" >&2
    exit 1
fi

echo "[INFO] Restoring backup ${BACKUP_FILE} to database '${TARGET_DB}'..."

# Ensure target database exists
docker compose exec -T postgres psql -U postgres -d postgres -c "DROP DATABASE IF EXISTS ${TARGET_DB};"
docker compose exec -T postgres psql -U postgres -d postgres -c "CREATE DATABASE ${TARGET_DB};"

# Restore schema and data
gunzip -c "${BACKUP_FILE}" | docker compose exec -T postgres psql -U postgres -d "${TARGET_DB}" > /dev/null

echo "[SUCCESS] Restore complete to database '${TARGET_DB}'"

# Verify table count in restored database
TABLE_COUNT=$(docker compose exec -T postgres psql -U postgres -d "${TARGET_DB}" -t -A -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';")
echo "[INFO] Restored public table count: ${TABLE_COUNT}"
