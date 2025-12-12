# KMS Playground

This project demonstrates envelope encryption across a Key Management Service (KMS), a data service, and a UI to visualize the flow. The KMS issues and unwraps Data Encryption Keys (DEKs), while the data service encrypts/decrypts application data. Both services persist state in their dedicated Postgres instances and expose debug endpoints for UI visualisation and testing. For a deeper architectural overview, see `ARCHITECTURE_KMS101.md`.

## Services

- KMS Service (FastAPI): manages CRKs/DEKs, AES-GCM wrapping, persists CRK metadata in Postgres (kms-db). Internal-only behind nginx.
- KMS Service Database (PostgreSQL): stores CRK metadata (wrapped CRKs, versions, status).
- Data Service (FastAPI): uses KMS for DEKs, AES-GCM encrypt/decrypt, persists encrypted records in Postgres (data-service-db). Internal-only behind nginx.
- Data Service Database (PostgreSQL): stores encrypted data records (ciphertext, nonce, tag, wrapped DEK).
- UI (React/Vite): playground to exercise store/decrypt flows and view data/logs.
- Nginx proxy: fronts the UI and proxies `/kms` and `/data` to the backend services; only port 80 is exposed externally.

## Run with Docker Compose
From the project root:
```
docker compose up --build
```

Verify (healthcheck via proxy):
```
curl http://localhost/kms/health
curl http://localhost/data/health
```

UI:
- Open `http://<host>` (port 80 via nginx proxy)
- Use the buttons to POST/GET `/data` endpoints and visualize logs/data

Manual API test (without UI):
Issue a POST request to the data service to encrypt and store data, then a GET request to retrieve and decrypt it (via proxy):
```
curl -X POST http://localhost/data/data \
  -H "Content-Type: application/json" \
  -d '{"customer_id": "cust-123", "data": "Hello KMS101"}'
curl http://localhost/data/data/<data_id>
```

## Utilities
- `scripts/flush_db.sh`: truncate data and KMS Postgres tables (`data_records`, `crks`, `audit_logs`) while services are running to reset the playground quickly.
To run the script, ensure services are up and execute:
```
./scripts/flush_db.sh
```

## Explore the architecture
For design details, key hierarchy, planned APIs, and schema notes, see `ARCHITECTURE_KMS101.md`.
