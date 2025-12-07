import React from "react";
import "./KmsFlow.css";

const steps = [
  {
    title: "Master Key (MK)",
    desc: "Derived in KMS from MASTER_KEY_PASSPHRASE; lives only in memory; wraps CRKs.",
    call: "Internal: derive master key via PBKDF2",
  },
  {
    title: "Customer Root Key (CRK)",
    desc: "Generated per customer; wrapped under MK (AES-GCM); stored as wrapped CRK.",
    call: "KMS: POST /v1/customers/{customer_id}/root-keys",
  },
  {
    title: "Data Encryption Key (DEK)",
    desc: "Generated per object; wrapped under CRK; plaintext DEK returned to data-service.",
    call: "KMS: POST /v1/deks:generate",
  },
  {
    title: "Encrypt Data (Data Service)",
    desc: "Data-service encrypts plaintext with DEK (AES-GCM) and stores ciphertext + nonce + tag + wrapped DEK.",
    call: "DATA: POST /data",
  },
  {
    title: "Decrypt Data (Data Service)",
    desc: "Data-service asks KMS to unwrap the DEK, then decrypts ciphertext with DEK.",
    call: "KMS: POST /v1/deks:unwrap\nDATA: GET /data/{id}",
  },
];

export const KmsFlow = () => {
  return (
    <section className="kms-flow">
      <div className="flow-header">
        <p className="eyebrow">Envelope encryption steps</p>
        <h2>MK → CRK → DEK → Data</h2>
      </div>
      <div className="timeline">
        {steps.map((step, idx) => (
          <div className="card" key={step.title}>
            <div className="badge">{idx + 1}</div>
            <div className="card-body">
              <h3>{step.title}</h3>
              <p>{step.desc}</p>
              {step.call && <pre className="callout">{step.call}</pre>}
            </div>
          </div>
        ))}
      </div>
      <div className="legend">
        <span className="pill kms">KMS</span>
        <span className="pill data">Data Service</span>
        <span className="pill db">DB (wrapped keys + ciphertext)</span>
      </div>
    </section>
  );
};
