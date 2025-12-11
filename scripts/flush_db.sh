#!/usr/bin/env bash
set -euo pipefail

# Flush data-service DB tables
docker compose exec data-service-db \
  psql -U kms -d kms_poc_data -c "TRUNCATE data_records, audit_logs RESTART IDENTITY;"

# Flush KMS DB tables
docker compose exec kms-db \
  psql -U kms -d kms_poc_kms -c "TRUNCATE crks, audit_logs RESTART IDENTITY;"
