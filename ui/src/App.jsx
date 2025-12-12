import React, { useEffect, useState } from "react";
import "./App.css";

const apiDefaults = {
  dataBaseUrl: "/data",
  kmsBaseUrl: "/kms",
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
  const [kmsLogs, setKmsLogs] = useState([]);
  const [dataLogs, setDataLogs] = useState([]);
  const [decryptStatus, setDecryptStatus] = useState("");
  const [resetStatus, setResetStatus] = useState("");
  const [resetting, setResetting] = useState(false);

  const fetchStores = async () => {
    setResetStatus("");
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

  const fetchKmsLogs = async () => {
    setResetStatus("");
    try {
      const logs = await fetch(`${kmsBaseUrl}/_debug/logs`).then((r) => r.json());
      setKmsLogs(logs);
    } catch {
      // ignore log fetch errors for UI
    }
  };

  const fetchDataLogs = async () => {
    setResetStatus("");
    try {
      const logs = await fetch(`${dataBaseUrl}/_debug/logs`).then((r) => r.json());
      setDataLogs(logs);
    } catch {
      // ignore log fetch errors for UI
    }
  };

  useEffect(() => {
    fetchKmsLogs();
    fetchDataLogs();
    const id = setInterval(fetchKmsLogs, 8000);
    const id2 = setInterval(fetchDataLogs, 8000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kmsBaseUrl, dataBaseUrl]);

  const handleEncrypt = async () => {
    setResetStatus("");
    setDecryptStatus("");
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
      if (body?.wrapped_dek?.crk_id) {
        setLastCrkUsed(body.wrapped_dek.crk_id);
      }
      setLastRequest("POST /data → POST /v1/deks:generate");
      await fetchStores();
      await fetchKmsLogs();
      await fetchDataLogs();
    } catch (err) {
      setDecryptStatus(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDecrypt = async () => {
    setResetStatus("");
    const targetId = decryptId || latestId;
    if (!targetId) {
      setDecryptStatus("Provide a data_id or store data first.");
      return;
    }
    setDecryptStatus("Decrypting...");
    setLoading(true);
    try {
      const resp = await fetch(`${dataBaseUrl}/data/${targetId}`);
      const body = await resp.json();
      if (!resp.ok) {
        throw new Error(body.detail || `Fetch failed: ${resp.status}`);
      }
      setDecryptStatus(body.data);
      setLastRequest(`GET /data/${targetId} → POST /v1/deks:unwrap`);
      await fetchStores();
      await fetchKmsLogs();
      await fetchDataLogs();
    } catch (err) {
      setDecryptStatus(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async () => {
    setResetting(true);
    setResetStatus("");
    try {
      await Promise.all([
        fetch(`${dataBaseUrl}/flush`, { method: "POST" }),
        fetch(`${kmsBaseUrl}/flush`, { method: "POST" }),
      ]);
      setLatestId("");
      setDecryptId("");
      setCrkId("");
      setLastCrkUsed(null);
      setResetStatus("Playground reset");
      await fetchStores();
      await fetchKmsLogs();
      await fetchDataLogs();
    } catch (err) {
      setResetStatus(`Reset failed: ${err.message}`);
    } finally {
      setResetting(false);
    }
  };

  return (
    <main className="app-shell">
      <header className="hero">
        <h1>KMS Playground</h1>
        <p>An interactive demonstration of how envelope encryption for a KMS service works.</p>
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
            <div className="accordion">
              <button type="button" className="link-button subtle" onClick={() => setAdvancedOpen((o) => !o)}>
                {advancedOpen ? "Hide advanced parameters" : "Show advanced parameters"}
              </button>
              {advancedOpen && (
                <div className="advanced-grid">
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
              )}
            </div>
          </div>
          <div className="actions">
            <button onClick={handleEncrypt} disabled={loading}>
              {loading ? "Working..." : "Store data (POST /data)"}
            </button>
          </div>
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
          {decryptStatus && (
            <div className="small-debug">
              <div className="status">
                <strong>Decrypted data:</strong> {decryptStatus}
              </div>
            </div>
          )}
          <div className="divider">Reset playground</div>
          <div className="actions">
            <button
              className="danger"
              type="button"
              onClick={handleReset}
              disabled={resetting || loading}
            >
              {resetting ? "Resetting..." : "Reset playground"}
            </button>
          </div>
          <p className="helper">Clears KMS keys, data, and logs.</p>
          {resetStatus && (
            <div className="small-debug">
              <div className="status">
                <strong>Reset:</strong> {resetStatus}
              </div>
            </div>
          )}
        </section>

        <section className="card card-kms">
          <div className="card-header">
            <p className="eyebrow">Keys</p>
            <h2>KMS</h2>
          </div>
          <div className="state-block">
            <p className="subtitle">KMS Database</p>
            <pre>{JSON.stringify(crkStore, null, 2)}</pre>
          </div>
          <div className="state-block">
            <p className="subtitle">KMS logs (raw JSON)</p>
            {kmsLogs && kmsLogs.length > 0 ? (
              <pre>{JSON.stringify(kmsLogs, null, 2)}</pre>
            ) : (
              <div className="faint">No recent KMS logs.</div>
            )}
          </div>
          <button className="ghost small" type="button" onClick={fetchKmsLogs}>
            Refresh logs
          </button>
        </section>

        <section className="card card-db">
          <div className="card-header">
            <p className="eyebrow">Storage</p>
            <h2>Database</h2>
          </div>
          <div className="state-block">
            <p className="subtitle">Data store (e.g. S3 bucket)</p>
            <pre>{JSON.stringify(dataStore, null, 2)}</pre>
          </div>
          <div className="state-block">
            <p className="subtitle">Data Service logs (raw JSON)</p>
            {dataLogs && dataLogs.length > 0 ? (
              <pre>{JSON.stringify(dataLogs, null, 2)}</pre>
            ) : (
              <div className="faint">No recent data logs.</div>
            )}
          </div>
          <button className="ghost small" type="button" onClick={fetchDataLogs}>
            Refresh logs
          </button>
        </section>
      </div>
    </main>
  );
};

export default App;
