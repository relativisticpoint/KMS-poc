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
  const [decryptId, setDecryptId] = useState("");
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);
  const [dataStore, setDataStore] = useState({});
  const [crkStore, setCrkStore] = useState({});
  const [dataBaseUrl, setDataBaseUrl] = useState(apiDefaults.dataBaseUrl);
  const [kmsBaseUrl, setKmsBaseUrl] = useState(apiDefaults.kmsBaseUrl);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [lastCrkUsed, setLastCrkUsed] = useState(null);
  const [lastRequest, setLastRequest] = useState("");

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
    setLoading(true);
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
      setDecryptId((prev) => prev || body.data_id);
      setStatus(`Stored data_id ${body.data_id}`);
      if (body?.wrapped_dek?.crk_id) {
        setLastCrkUsed(body.wrapped_dek.crk_id);
      }
      setLastRequest("POST /data → POST /v1/deks:generate");
      await fetchStores();
    } catch (err) {
      setStatus(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    const targetId = decryptId || latestId;
    if (!targetId) {
      setStatus("Provide a data_id or store data first.");
      return;
    }
    setStatus("Decrypting...");
    setLoading(true);
    try {
      const resp = await fetch(`${dataBaseUrl}/data/${targetId}`);
      const body = await resp.json();
      if (!resp.ok) {
        throw new Error(body.detail || `Fetch failed: ${resp.status}`);
      }
      setStatus(`Decrypted (${targetId}): ${body.data}`);
      setLastRequest(`GET /data/${targetId} → POST /v1/deks:unwrap`);
      await fetchStores();
    } catch (err) {
      setStatus(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="app-shell">
      <header className="hero">
        <h1>KMS101 – Envelope Encryption</h1>
        <p>
          An interactive demonstration of how envelope encryption works. Data is encrypted with a
          Data Encryption Key (DEK), which is then encrypted with a Customer Root Key (CRK) from the
          KMS before storage.
        </p>
        <div className="steps">
          <span className="pill step data">1) Store data</span>
          <span className="pill step kms">2) KMS generates DEK</span>
          <span className="pill step db">3) DB stores ciphertext</span>
          <span className="pill step kms">4) KMS unwraps DEK</span>
          <span className="pill step data">5) Data service decrypts</span>
        </div>
      </header>

      <div className="cards-grid">
        <section className="card card-data">
          <div className="card-header">
            <p className="eyebrow">Application</p>
            <h2>Data service</h2>
          </div>
          <div className="section-title">Store &amp; encrypt data</div>
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
            <div className="accordion">
              <button
                type="button"
                className="link-button"
                onClick={() => setAdvancedOpen((o) => !o)}
              >
                {advancedOpen ? "Hide advanced (URLs)" : "Show advanced (URLs)"}
              </button>
              {advancedOpen && (
                <div className="advanced-grid">
                  <label>
                    Data service URL
                    <input value={dataBaseUrl} onChange={(e) => setDataBaseUrl(e.target.value)} />
                  </label>
                  <label>
                    KMS service URL
                    <input value={kmsBaseUrl} onChange={(e) => setKmsBaseUrl(e.target.value)} />
                  </label>
                </div>
              )}
            </div>
          </div>
          <div className="actions">
            <button onClick={handleEncrypt} disabled={loading}>
              {loading ? "Working..." : "Store data (POST /data)"}
            </button>
          </div>
          <p className="helper">
            This calls POST <code>/data</code> on the data service, which calls the KMS to generate a
            DEK and stores ciphertext + wrapped DEK in the database.
          </p>

          <div className="divider">Decrypt data</div>
          <div className="single-input">
            <label>
              Data ID to decrypt
              <input
                value={decryptId}
                onChange={(e) => setDecryptId(e.target.value)}
                placeholder="enter data_id or use latest"
              />
            </label>
          </div>
          <div className="actions">
            <button onClick={handleDecrypt} disabled={loading}>
              {loading ? "Working..." : "Decrypt (GET /data/<id>)"}
            </button>
            <button
              className="ghost small"
              type="button"
              onClick={() => setDecryptId(latestId)}
              disabled={!latestId}
            >
              Use latest ID
            </button>
            <button className="ghost" onClick={fetchStores} type="button">
              Refresh debug state
            </button>
          </div>
          {(latestId || status) && (
            <div className="small-debug">
              {latestId && (
                <div>
                  <strong>Latest data_id:</strong> {latestId}
                </div>
              )}
              {status && (
                <div className="status">
                  <strong>Last result:</strong> {status}
                </div>
              )}
            </div>
          )}
          <div className="card-footer">
            <h4>What the data service does</h4>
            <ul className="bullet-list">
              <li>Exposes <code>/data</code> to store and retrieve encrypted data.</li>
              <li>
                For storing, it calls the KMS to get a DEK, encrypts plaintext, and stores ciphertext
                + wrapped DEK.
              </li>
              <li>
                For decrypting, it loads the wrapped DEK and asks the KMS to unwrap it before
                decrypting.
              </li>
            </ul>
          </div>
        </section>

        <section className="card card-kms">
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
            <ul className="bullet-list">
              <li>Owns the master key and customer root keys (CRKs).</li>
              <li>
                When storing data, data-service calls <code>POST /v1/deks:generate</code> to create
                a DEK and wrap it under a CRK.
              </li>
              <li>
                When decrypting, data-service calls <code>POST /v1/deks:unwrap</code> so it can
                decrypt locally.
              </li>
              <li>The KMS never stores plaintext application data.</li>
            </ul>
          </div>
        </section>

        <section className="card card-db">
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
            <ul className="bullet-list">
              <li>Only encrypted data and wrapped DEKs.</li>
              <li>No master key and no CRKs → cannot decrypt by itself.</li>
              <li>
                Each record has ciphertext + AEAD metadata (nonce, tag) and a wrapped DEK that only
                the KMS can unwrap.
              </li>
            </ul>
          </div>
        </section>
      </div>

      <KmsFlow />
    </main>
  );
};

export default App;
