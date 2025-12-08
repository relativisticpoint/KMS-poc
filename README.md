# KMS101 – KMS Proof of Concept

This project is a small proof of concept for a Key Management Service (KMS)
and a data service that uses envelope encryption.

## Services

- KMS Service (FastAPI, port 8000)
- Data Service (FastAPI, port 8001)
- PostgreSQL database (port 5432)

Current state:
- KMS exposes in-memory endpoints to create/rotate CRKs and generate/unwrap DEKs using AES-GCM wrapping (real crypto), still stored in memory. Per-customer CRK reuse (get-or-create) is enforced server-side.
- Data service calls KMS, AES-GCM encrypts/decrypts data, and stores records in memory (no Postgres usage yet).
- CORS is enabled on both services to support the browser UI at `ui/`.
- UI is containerized (nginx) and available via docker-compose on port 5173.

## Running

From the project root:

    cd /Users/ahmedsami/Desktop/KMS101
    docker compose up --build

Then check:

    curl http://localhost:8000/health
    curl http://localhost:8001/health

Quick manual test (mock/in-memory flow):

```
curl -X POST http://localhost:8001/data \
  -H "Content-Type: application/json" \
  -d '{"customer_id": "cust-123", "data": "Hello KMS101"}'
```

Response:

```
{"data_id": "<uuid>"}
```

Then retrieve:

```
curl http://localhost:8001/data/<uuid>
```

## UI (visualizer)

A small React UI lives under `ui/` to visualize and exercise the flow.

```
cd ui
npm install
npm run dev
```

Then open the printed URL (default `http://localhost:5173`) and use the form to POST/GET `/data`. Debug state panes read `/_debug/data` and `/_debug/crks` from the services (available in dev only).

Running via Docker:

```
docker compose up --build
```

The UI will be served at `http://localhost:5173` from the `ui` service (nginx).

## Notes for AI / Code Assistants

If you're using an AI code assistant (Copilot, ChatGPT, etc.), please read
or reference `ARCHITECTURE_KMS101.md` first. It describes:

- The KMS vs data-service responsibilities
- The key hierarchy (MK → CRK → DEK)
- Planned APIs and crypto choices

Code suggestions should:
- Keep KMS logic in `kms-service`
- Keep data storage and encryption/decryption logic in `data-service`
- Use the envelope encryption pattern (CRK wraps DEK, DEK encrypts data)
