# KMS Playground

This project demonstrates envelope encryption across a Key Management Service (KMS), a data service, and a UI to visualize the flow. The KMS issues and unwraps Data Encryption Keys (DEKs), while the data service encrypts/decrypts application data. Both services persist state in Postgres and expose debug endpoints for learning and testing. For a deeper architectural overview, see `ARCHITECTURE_KMS101.md`.

## Services
- KMS Service (FastAPI, port 8000): manages CRKs/DEKs, AES-GCM wrapping, persisted CRKs in Postgres.
- Data Service (FastAPI, port 8001): uses KMS for DEKs, AES-GCM encrypt/decrypt, persists encrypted records in Postgres.
- UI (React/Vite, port 5173 via nginx): playground to exercise store/decrypt flows and view debug data/logs.
- Postgres instances: one for KMS CRKs, one for data records (see schema details below).

### Database schemas
- `data-service-db` (`kms_poc_data`):
  - `data_records`: `data_id` (PK), `customer_id`, `ciphertext`, `nonce`, `tag`, `wrapped_dek` (JSON with CRK metadata + wrapped key).
  - `audit_logs`: `id`, `ts`, `level`, `event`, `corr_id`, `customer_id`, `crk_id`, `data_id`, `detail`.
- `kms-db` (`kms_poc_kms`):
  - `crks`: `crk_id` (PK), `customer_id`, `version`, `status`, `algorithm`, `wrapped_crk`.
  - `audit_logs`: `id`, `ts`, `level`, `event`, `corr_id`, `customer_id`, `crk_id`, `detail`.

## Run with Docker Compose
From the project root:
```
docker compose up --build
```

Verify(heathcheck):
```
curl http://localhost:8000/health
curl http://localhost:8001/health
```

UI:
- Open `http://localhost:5173`
- Use the form to POST/GET `/data`; debug panes read from `/_debug/data`, `/_debug/crks`, `/_debug/logs` (dev only).

Manual API test (without UI):
Issue a POST request to the data service to encrypt and store data, then a GET request to retrieve and decrypt it:
```
curl -X POST http://localhost:8001/data \
  -H "Content-Type: application/json" \
  -d '{"customer_id": "cust-123", "data": "Hello KMS101"}'
curl http://localhost:8001/data/<data_id>
```

## Local UI (dev mode)
```
cd ui
npm install
npm run dev
```
Then open the printed URL (default `http://localhost:5173`). The UI will use the compose services on localhost unless you point it elsewhere.

## Utilities
- `scripts/flush_db.sh`: truncate data and KMS Postgres tables (`data_records`, `crks`, `audit_logs`) while services are running to reset the playground quickly.
To run the script, ensure services are up and execute:
```./scripts/flush_db.sh
```

## Explore the architecture
For design details, key hierarchy, planned APIs, and schema notes, see `ARCHITECTURE_KMS101.md`.
