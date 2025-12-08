import React, { useEffect, useState } from "react";
import { KmsFlow } from "./KmsFlow";
import "./App.css";

const apiDefaults = {
  dataBaseUrl: "http://localhost:8001",
  kmsBaseUrl: "http://localhost:8000",
};

const App = () => {
  const [customerId, setCustomerId] = useState("cust-123");
  const [plaintext, setPlaintext] = useState("Hello KMS101");
  const [crkId, setCrkId] = useState("");
  const [latestId, setLatestId] = useState("");
  const [status, setStatus] = useState("");
  const [dataStore, setDataStore] = useState({});
  const [crkStore, setCrkStore] = useState({});
  const [dataBaseUrl, setDataBaseUrl] = useState(apiDefaults.dataBaseUrl);
  const [kmsBaseUrl, setKmsBaseUrl] = useState(apiDefaults.kmsBaseUrl);

  const fetchStores = async () => {
    try {
      const [dataRes, crkRes] = await Promise.all([
        fetch(`${dataBaseUrl}/_debug/data`).then((r) => r.json()),
        fetch(`${kmsBaseUrl}/_debug/crks`).then((r) => r.json()),
      ]);
      setDataStore(dataRes);
      setCrkStore(crkRes);
    } catch (err) {
      setStatus("Failed to fetch debug stores (ensure services are running)");
    }
  };

  useEffect(() => {
    fetchStores();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleEncrypt = async () => {
    setStatus("Encrypting...");
    try {
      const resp = await fetch(`${dataBaseUrl}/data`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          customer_id: customerId,
          data: plaintext,
          crk_id: crkId || undefined,
        }),
      });
      if (!resp.ok) {
        throw new Error(`Store failed: ${resp.status}`);
      }
      const body = await resp.json();
      setLatestId(body.data_id);
      setStatus(`Stored data_id ${body.data_id}`);
      await fetchStores();
    } catch (err) {
      setStatus(err.message);
    }
  };

  const handleDecrypt = async () => {
    if (!latestId) {
      setStatus("No data_id yet—store data first.");
      return;
    }
    setStatus("Decrypting...");
    try {
      const resp = await fetch(`${dataBaseUrl}/data/${latestId}`);
      const body = await resp.json();
      if (!resp.ok) {
        throw new Error(body.detail || `Fetch failed: ${resp.status}`);
      }
      setStatus(`Decrypted: ${body.data}`);
      await fetchStores();
    } catch (err) {
      setStatus(err.message);
    }
  };

  return (
    <main className="app-shell">
      <header className="hero">
        <h1>KMS101 – Envelope Encryption</h1>
        <p>
          See how the KMS, CRKs, and DEKs work together to encrypt and decrypt data
          in the PoC.
        </p>
      </header>

      <div className="cards-grid">
        <section className="card">
          <div className="card-header">
            <p className="eyebrow">Application</p>
            <h2>Data service</h2>
          </div>
          <div className="form-grid">
            <label>
              Customer ID
              <input value={customerId} onChange={(e) => setCustomerId(e.target.value)} />
            </label>
            <label>
              Plaintext
              <textarea
                value={plaintext}
                onChange={(e) => setPlaintext(e.target.value)}
                rows={2}
              />
            </label>
            <label>
              CRK ID (optional)
              <input
                value={crkId}
                onChange={(e) => setCrkId(e.target.value)}
                placeholder="auto-create if empty"
              />
            </label>
            <label>
              Data service URL
              <input value={dataBaseUrl} onChange={(e) => setDataBaseUrl(e.target.value)} />
            </label>
            <label>
              KMS service URL
              <input value={kmsBaseUrl} onChange={(e) => setKmsBaseUrl(e.target.value)} />
            </label>
          </div>
          <div className="actions">
            <button onClick={handleEncrypt}>Store data (POST /data)</button>
            <button onClick={handleDecrypt} className="ghost">
              Decrypt latest (GET /data/&lt;id&gt;)
            </button>
            <button onClick={fetchStores} className="ghost">
              Refresh debug state
            </button>
          </div>
          <div className="small-debug">
            <div>
              <strong>Latest data_id:</strong> {latestId || "none yet"}
            </div>
            {status && <div className="status">{status}</div>}
          </div>
          <div className="card-footer">
            <h4>What the data service does</h4>
            <p>
              This card simulates the application / data service. When you click <em>Store data</em>,
              it calls POST <code>/data</code>. The data service then calls the KMS to get a Data
              Encryption Key (DEK), encrypts your plaintext with the DEK, and stores only ciphertext
              + a wrapped DEK in the database.
            </p>
          </div>
        </section>

        <section className="card">
          <div className="card-header">
            <p className="eyebrow">Keys</p>
            <h2>KMS</h2>
          </div>
          <div className="state-block">
            <p className="subtitle">KMS CRKs (in-memory debug view)</p>
            <pre>{JSON.stringify(crkStore, null, 2)}</pre>
          </div>
          <div className="card-footer">
            <h4>What the KMS does</h4>
            <p>
              The KMS owns the master key and customer root keys (CRKs). For encryption it generates
              a DEK and wraps it with a CRK via <code>POST /v1/deks:generate</code>. For decryption
              it unwraps the DEK via <code>POST /v1/deks:unwrap</code>. It never stores plaintext
              data—only key material and crypto operations.
            </p>
          </div>
        </section>

        <section className="card">
          <div className="card-header">
            <p className="eyebrow">Storage</p>
            <h2>Database</h2>
          </div>
          <div className="state-block">
            <p className="subtitle">Data store (encrypted objects)</p>
            <pre>{JSON.stringify(dataStore, null, 2)}</pre>
          </div>
          <div className="card-footer">
            <h4>What the database stores</h4>
            <p>
              The database holds only encrypted data and wrapped DEKs. It does not have the master
              key or CRKs, so it cannot decrypt by itself. Each record contains ciphertext, AEAD
              metadata (nonce/tag), and a wrapped DEK that only the KMS can unwrap.
            </p>
          </div>
        </section>
      </div>

      <KmsFlow />
    </main>
  );
};

export default App;
