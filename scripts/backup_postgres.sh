#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="${1:-./backups}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/aegis_postgres_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"

echo "[INFO] Starting PostgreSQL backup for AEGIS AI..."
docker compose exec -T postgres pg_dump -U postgres -d aegis --clean --if-exists | gzip > "${BACKUP_FILE}"

if [[ -s "${BACKUP_FILE}" ]]; then
    echo "[SUCCESS] Backup successfully created at: ${BACKUP_FILE}"
    echo "[INFO] Size: $(du -h "${BACKUP_FILE}" | cut -f1)"
else
    echo "[ERROR] Backup file is empty or failed to create." >&2
    exit 1
fi
