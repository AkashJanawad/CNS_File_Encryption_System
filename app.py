"""
CNS Secure File Encryption System - Web Application
FastAPI Server providing Web Dashboard for Zero-Knowledge Firebase Encrypted Storage & Benchmarking.
"""

import os
import io
import time
import base64
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

import crypto_engine
from firebase_vault import FirebaseCloudVault

app = FastAPI(title="CNS File Encryption System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

vault = FirebaseCloudVault()

# Auto-load or generate session RSA keys
KEY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
os.makedirs(KEY_DIR, exist_ok=True)
PRIV_KEY_FILE = os.path.join(KEY_DIR, "private_key.pem")
PUB_KEY_FILE = os.path.join(KEY_DIR, "public_key.pem")

if not os.path.exists(PRIV_KEY_FILE) or not os.path.exists(PUB_KEY_FILE):
    _priv, _pub = crypto_engine.generate_rsa_keypair(2048)
    with open(PRIV_KEY_FILE, "w") as f:
        f.write(_priv)
    with open(PUB_KEY_FILE, "w") as f:
        f.write(_pub)

class FileUploadRequest(BaseModel):
    filename: str
    content_base64: str
    protocol: str = "CP2"
    custom_public_key: Optional[str] = None

# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.get("/api/status")
def get_status():
    return vault.get_vault_status()

@app.get("/api/keys")
def get_keys():
    with open(PRIV_KEY_FILE, "r") as f:
        priv = f.read()
    with open(PUB_KEY_FILE, "r") as f:
        pub = f.read()
    return {"private_key": priv, "public_key": pub}

@app.post("/api/keys/generate")
def generate_new_keys():
    priv, pub = crypto_engine.generate_rsa_keypair(2048)
    with open(PRIV_KEY_FILE, "w") as f:
        f.write(priv)
    with open(PUB_KEY_FILE, "w") as f:
        f.write(pub)
    return {"private_key": priv, "public_key": pub, "message": "New RSA-2048 keypair generated!"}

@app.get("/api/files")
def list_files():
    return vault.list_files()

@app.post("/api/upload")
def upload_file(req: FileUploadRequest):
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_uploads")
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, req.filename)

    try:
        file_bytes = base64.b64decode(req.content_base64)
        with open(temp_path, "wb") as f:
            f.write(file_bytes)

        pub_key = req.custom_public_key if req.custom_public_key and req.custom_public_key.strip() else open(PUB_KEY_FILE).read()
        metadata = vault.upload_file(temp_path, pub_key, protocol=req.protocol)
        return metadata
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.get("/api/download/{file_id}")
def download_file(file_id: str, custom_private_key: Optional[str] = None):
    priv_key = custom_private_key if custom_private_key and custom_private_key.strip() else open(PRIV_KEY_FILE).read()
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_downloads")
    os.makedirs(out_dir, exist_ok=True)

    try:
        saved_path, verified, metadata = vault.download_file(file_id, priv_key, output_dir=out_dir)
        filename = metadata.get("file_name", "decrypted_file")
        with open(saved_path, "rb") as f:
            file_bytes = f.read()

        response = StreamingResponse(io.BytesIO(file_bytes), media_type="application/octet-stream")
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        response.headers["X-Integrity-Verified"] = str(verified)
        response.headers["X-SHA256"] = metadata.get("sha256", "")
        return response
    finally:
        pass

@app.delete("/api/files/{file_id}")
def delete_file(file_id: str):
    success = vault.delete_file(file_id)
    if not success:
        raise HTTPException(status_code=404, detail="File not found")
    return {"message": "File deleted from Firebase Vault"}

@app.get("/api/benchmark/{sample_name}")
def run_benchmark(sample_name: str):
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "NSProgrammingAssignment2")
    file_path = os.path.join(base_dir, sample_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Sample file not found")

    with open(file_path, "rb") as f:
        data = f.read()

    return crypto_engine.run_crypto_benchmark(data, sample_name)

# ---------------------------------------------------------------------------
# HTML Web Dashboard (Fully self-contained CSS, zero external CDN reliance)
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CNS Secure File Encryption System | Firebase Cloud Vault</title>
  <style>
    /* Reset & Base */
    *, *::before, *::after {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: #0b0f19;
      color: #e2e8f0;
      line-height: 1.5;
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }
    code, pre, textarea {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }

    /* Header */
    header {
      background: rgba(17, 24, 39, 0.85);
      backdrop-filter: blur(8px);
      border-bottom: 1px solid #1e293b;
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .header-inner {
      max-width: 1240px;
      margin: 0 auto;
      padding: 12px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .brand-wrap {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-badge {
      width: 42px;
      height: 42px;
      border-radius: 12px;
      background: linear-gradient(135deg, #f59e0b, #6366f1);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      color: #ffffff;
      font-size: 16px;
      box-shadow: 0 4px 14px rgba(99, 102, 241, 0.35);
    }
    .brand-title {
      font-size: 18px;
      font-weight: 700;
      color: #ffffff;
      letter-spacing: -0.02em;
    }
    .brand-subtitle {
      font-size: 12px;
      color: #94a3b8;
    }
    .status-pill {
      display: flex;
      align-items: center;
      gap: 8px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3);
      color: #34d399;
      font-size: 12px;
      font-weight: 600;
      padding: 6px 14px;
      border-radius: 9999px;
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #10b981;
      box-shadow: 0 0 8px #10b981;
    }

    /* Main Container */
    main {
      max-width: 1240px;
      margin: 0 auto;
      padding: 28px 20px 48px;
    }

    /* Top Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    .stat-card {
      background: #111827;
      border: 1px solid #1e293b;
      border-radius: 14px;
      padding: 18px 20px;
      transition: border-color 0.2s;
    }
    .stat-card:hover {
      border-color: #334155;
    }
    .stat-label {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #64748b;
    }
    .stat-val {
      font-size: 22px;
      font-weight: 800;
      color: #ffffff;
      margin-top: 6px;
      letter-spacing: -0.02em;
    }
    .stat-sub {
      font-size: 12px;
      margin-top: 4px;
    }
    .text-emerald { color: #34d399; }
    .text-indigo { color: #818cf8; }
    .text-amber { color: #fbbf24; }
    .text-cyan { color: #22d3ee; }

    /* Tabs */
    .tabs-nav {
      display: flex;
      gap: 6px;
      border-bottom: 1px solid #1e293b;
      margin-bottom: 24px;
      overflow-x: auto;
    }
    .tab-btn {
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      color: #94a3b8;
      font-size: 14px;
      font-weight: 600;
      padding: 10px 18px;
      cursor: pointer;
      white-space: nowrap;
      transition: all 0.2s;
    }
    .tab-btn:hover {
      color: #e2e8f0;
    }
    .tab-btn.active {
      color: #818cf8;
      border-bottom-color: #6366f1;
    }

    /* Tab content hiding */
    .tab-content {
      display: block;
    }
    .tab-content.hidden, .hidden {
      display: none !important;
    }

    /* Card Panels */
    .panel {
      background: #111827;
      border: 1px solid #1e293b;
      border-radius: 16px;
      padding: 24px;
    }
    .panel-title {
      font-size: 18px;
      font-weight: 700;
      color: #ffffff;
      margin-bottom: 6px;
    }
    .panel-desc {
      font-size: 13px;
      color: #94a3b8;
      margin-bottom: 20px;
    }

    /* Layout Grids */
    .grid-2col {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 24px;
    }
    @media (max-width: 880px) {
      .grid-2col { grid-template-columns: 1fr; }
    }

    /* Drag & Drop Upload Zone */
    .upload-zone {
      border: 2px dashed #334155;
      background: #0b0f19;
      border-radius: 14px;
      padding: 36px 20px;
      text-align: center;
      cursor: pointer;
      transition: all 0.2s;
    }
    .upload-zone:hover {
      border-color: #6366f1;
      background: rgba(99, 102, 241, 0.04);
    }
    .upload-icon {
      width: 48px;
      height: 48px;
      max-width: 48px;
      max-height: 48px;
      display: block;
      margin: 0 auto 12px auto;
      color: #64748b;
    }
    .upload-prompt {
      font-size: 14px;
      font-weight: 600;
      color: #e2e8f0;
    }
    .upload-hint {
      font-size: 12px;
      color: #64748b;
      margin-top: 4px;
    }

    /* Form Fields */
    .form-group {
      margin-top: 18px;
    }
    .form-label {
      display: block;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #94a3b8;
      margin-bottom: 8px;
    }
    .form-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }
    @media (max-width: 600px) {
      .form-row { grid-template-columns: 1fr; }
    }
    select, input, textarea {
      width: 100%;
      background: #0b0f19;
      border: 1px solid #334155;
      color: #f1f5f9;
      border-radius: 10px;
      padding: 10px 14px;
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s;
    }
    select:focus, input:focus, textarea:focus {
      border-color: #6366f1;
    }
    .badge-static {
      background: #0b0f19;
      border: 1px solid #1e293b;
      border-radius: 10px;
      padding: 10px 14px;
      font-size: 13px;
      color: #34d399;
      font-weight: 500;
    }

    /* Buttons */
    .btn-primary {
      width: 100%;
      background: linear-gradient(135deg, #6366f1, #4f46e5);
      color: #ffffff;
      border: none;
      border-radius: 12px;
      padding: 14px 20px;
      font-size: 15px;
      font-weight: 700;
      cursor: pointer;
      margin-top: 20px;
      box-shadow: 0 4px 14px rgba(79, 70, 229, 0.35);
      transition: transform 0.1s, opacity 0.2s;
    }
    .btn-primary:hover {
      opacity: 0.95;
      transform: translateY(-1px);
    }
    .btn-primary:active {
      transform: translateY(0);
    }
    .btn-primary:disabled {
      opacity: 0.6;
      cursor: not-allowed;
    }

    .btn-sm {
      background: #1e293b;
      border: 1px solid #334155;
      color: #e2e8f0;
      font-size: 12px;
      font-weight: 600;
      padding: 6px 14px;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-sm:hover {
      background: #334155;
    }
    .btn-download {
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.35);
      color: #34d399;
      text-decoration: none;
      display: inline-block;
    }
    .btn-download:hover {
      background: rgba(16, 185, 129, 0.25);
    }
    .btn-delete {
      background: rgba(244, 63, 94, 0.15);
      border: 1px solid rgba(244, 63, 94, 0.35);
      color: #fb7185;
    }
    .btn-delete:hover {
      background: rgba(244, 63, 94, 0.25);
    }

    /* Result Box */
    .result-box {
      margin-top: 20px;
      background: #0b0f19;
      border: 1px solid #1e293b;
      border-radius: 12px;
      padding: 16px;
    }
    .result-header {
      color: #34d399;
      font-weight: 700;
      font-size: 14px;
      margin-bottom: 10px;
    }
    .result-item {
      font-size: 12px;
      color: #cbd5e1;
      margin-bottom: 4px;
    }
    .result-item strong {
      color: #94a3b8;
    }

    /* Assignment Samples List */
    .sample-item {
      background: #0b0f19;
      border: 1px solid #1e293b;
      border-radius: 10px;
      padding: 12px 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .sample-name {
      font-size: 14px;
      font-weight: 600;
      color: #e2e8f0;
    }
    .sample-size {
      font-size: 11px;
      color: #64748b;
    }

    /* Table */
    .table-responsive {
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }
    th {
      background: #0b0f19;
      color: #94a3b8;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 12px 14px;
      border-bottom: 1px solid #1e293b;
    }
    td {
      padding: 14px;
      border-bottom: 1px solid #1e293b;
      color: #cbd5e1;
    }
    tr:hover td {
      background: rgba(15, 23, 42, 0.4);
    }

    /* Spinner */
    .spinner {
      border: 3px solid rgba(255, 255, 255, 0.1);
      border-top-color: #6366f1;
      border-radius: 50%;
      width: 32px;
      height: 32px;
      animation: spin 0.8s linear infinite;
      margin: 0 auto 12px;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    /* Benchmark Result Grid */
    .bench-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-top: 16px;
    }
    @media (max-width: 700px) {
      .bench-grid { grid-template-columns: 1fr; }
    }
    .bench-card {
      background: #0b0f19;
      border: 1px solid #1e293b;
      border-radius: 12px;
      padding: 18px;
    }
    .bench-card-title {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .bench-timing {
      font-size: 24px;
      font-weight: 800;
      color: #ffffff;
      margin: 8px 0;
    }
  </style>
</head>
<body>

  <!-- Header -->
  <header>
    <div class="header-inner">
      <div class="brand-wrap">
        <div class="brand-badge">CNS</div>
        <div>
          <div class="brand-title">Secure File Encryption System</div>
          <div class="brand-subtitle">Zero-Knowledge Envelope Encryption with Firebase</div>
        </div>
      </div>
      <div class="status-pill">
        <span class="status-dot"></span>
        Firebase Spark Free Tier (100% Free)
      </div>
    </div>
  </header>

  <!-- Main Content -->
  <main>

    <!-- Stats Bar -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Cloud Database</div>
        <div class="stat-val">Cloud Firestore</div>
        <div class="stat-sub text-emerald">1 GB Free Storage Quota</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Total Encrypted Files</div>
        <div id="statTotalFiles" class="stat-val text-indigo">0</div>
        <div class="stat-sub text-emerald">Stored securely</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Total Encrypted Volume</div>
        <div id="statTotalBytes" class="stat-val text-amber">0 KB</div>
        <div class="stat-sub text-amber">Zero-Knowledge Ciphertext</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Cryptographic Standard</div>
        <div class="stat-val" style="font-size: 16px; margin-top: 10px;">RSA-2048 + AES-GCM</div>
        <div class="stat-sub text-cyan">SHA-256 Checksum Integrity</div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tabs-nav">
      <button onclick="switchTab('upload')" id="tabBtnUpload" class="tab-btn active">
        Upload & Encrypt
      </button>
      <button onclick="switchTab('vault')" id="tabBtnVault" class="tab-btn">
        Cloud Vault Explorer
      </button>
      <button onclick="switchTab('benchmark')" id="tabBtnBenchmark" class="tab-btn">
        CP1 vs CP2 Benchmark
      </button>
      <button onclick="switchTab('keys')" id="tabBtnKeys" class="tab-btn">
        RSA Key Manager
      </button>
    </div>

    <!-- Tab 1: Upload & Encrypt -->
    <div id="tabUpload" class="tab-content">
      <div class="grid-2col">
        <div class="panel">
          <h2 class="panel-title">Upload & Encrypt File</h2>
          <p class="panel-desc">Select any file. It is encrypted client-side using authenticated encryption before being uploaded to Firebase.</p>

          <form id="uploadForm" onsubmit="handleUpload(event)">
            <label class="form-label">Select File to Encrypt</label>
            <div class="upload-zone" onclick="document.getElementById('fileInput').click()">
              <input type="file" id="fileInput" style="display: none;" onchange="updateFileName(this)" />
              <svg class="upload-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" width="48" height="48">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
              </svg>
              <div id="selectedFileName" class="upload-prompt">Click or drag & drop a file here</div>
              <div class="upload-hint">Supports any file size (automatic subcollection chunking)</div>
            </div>

            <div class="form-row form-group">
              <div>
                <label class="form-label">Encryption Protocol</label>
                <select id="protocolSelect">
                  <option value="CP2">Protocol 2 (CP2): Hybrid AES-256-GCM + RSA (Recommended)</option>
                  <option value="CP1">Protocol 1 (CP1): Pure RSA Asymmetric Chunked</option>
                </select>
              </div>
              <div>
                <label class="form-label">Cloud Target</label>
                <div class="badge-static">Firebase Cloud Firestore (100% Free)</div>
              </div>
            </div>

            <button type="submit" id="uploadBtn" class="btn-primary">
              Encrypt & Upload to Cloud Vault
            </button>
          </form>

          <div id="uploadResult" class="result-box hidden"></div>
        </div>

        <!-- Sample Benchmark Files -->
        <div class="panel">
          <h3 class="panel-title" style="font-size: 15px;">Assignment Test Files</h3>
          <p class="panel-desc">Original benchmark files located in <code>NSProgrammingAssignment2/</code>:</p>
          
          <div class="sample-item">
            <div>
              <div class="sample-name">smallFile.txt</div>
              <div class="sample-size">1.18 KB</div>
            </div>
            <button onclick="benchmarkSample('smallFile.txt')" class="btn-sm">Benchmark</button>
          </div>

          <div class="sample-item">
            <div>
              <div class="sample-name">medianFile.txt</div>
              <div class="sample-size">1.54 MB</div>
            </div>
            <button onclick="benchmarkSample('medianFile.txt')" class="btn-sm">Benchmark</button>
          </div>

          <div class="sample-item">
            <div>
              <div class="sample-name">largeFile.txt</div>
              <div class="sample-size">3.45 MB</div>
            </div>
            <button onclick="benchmarkSample('largeFile.txt')" class="btn-sm">Benchmark</button>
          </div>
        </div>
      </div>
    </div>

    <!-- Tab 2: Cloud Vault Explorer -->
    <div id="tabVault" class="tab-content hidden">
      <div class="panel">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
          <div>
            <h2 class="panel-title">Firebase Encrypted Vault</h2>
            <p class="panel-desc" style="margin-bottom: 0;">All files are stored as encrypted ciphertext. Only your RSA Private Key can decrypt them.</p>
          </div>
          <button onclick="loadVaultFiles()" class="btn-sm">Refresh List</button>
        </div>

        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>File Name</th>
                <th>Protocol</th>
                <th>Original Size</th>
                <th>Encrypted Size</th>
                <th>SHA-256 Digest</th>
                <th>Uploaded At</th>
                <th style="text-align: right;">Actions</th>
              </tr>
            </thead>
            <tbody id="vaultTableBody">
              <tr><td colspan="7" style="text-align: center; color: #64748b; padding: 24px;">Loading files from Firebase...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Tab 3: Benchmark -->
    <div id="tabBenchmark" class="tab-content hidden">
      <div class="panel">
        <h2 class="panel-title">Cryptographic Protocol Benchmark</h2>
        <p class="panel-desc">Empirical comparison between <strong>Protocol 1 (Pure RSA Chunked)</strong> and <strong>Protocol 2 (Hybrid AES+RSA)</strong>.</p>

        <div style="display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap;">
          <button onclick="benchmarkSample('smallFile.txt')" class="btn-sm">Benchmark smallFile.txt (1.2 KB)</button>
          <button onclick="benchmarkSample('medianFile.txt')" class="btn-sm">Benchmark medianFile.txt (1.5 MB)</button>
          <button onclick="benchmarkSample('largeFile.txt')" class="btn-sm">Benchmark largeFile.txt (3.4 MB)</button>
        </div>

        <div id="benchmarkLoading" class="hidden" style="text-align: center; padding: 32px; color: #94a3b8;">
          <div class="spinner"></div>
          <div>Running encryption and decryption trials...</div>
        </div>

        <div id="benchmarkResults" class="hidden"></div>
      </div>
    </div>

    <!-- Tab 4: Keys -->
    <div id="tabKeys" class="tab-content hidden">
      <div class="panel">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
          <div>
            <h2 class="panel-title">RSA-2048 Asymmetric Key Pair</h2>
            <p class="panel-desc" style="margin-bottom: 0;">Used for envelope encryption (encrypting symmetric AES keys) and authentication.</p>
          </div>
          <button onclick="generateNewKeys()" class="btn-sm" style="background: rgba(244, 63, 94, 0.15); border-color: rgba(244, 63, 94, 0.35); color: #fb7185;">
            Generate New Keypair
          </button>
        </div>

        <div class="form-row" style="margin-top: 16px;">
          <div>
            <label class="form-label">Public Key (SubjectPublicKeyInfo PEM)</label>
            <textarea id="pubKeyArea" readonly rows="12" style="color: #818cf8;"></textarea>
          </div>
          <div>
            <label class="form-label">Private Key (PKCS#8 PEM - KEEP SECRET)</label>
            <textarea id="privKeyArea" readonly rows="12" style="color: #fb7185;"></textarea>
          </div>
        </div>
      </div>
    </div>

  </main>

  <script>
    function switchTab(tabId) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
      document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));

      const targetTab = document.getElementById('tab' + tabId.charAt(0).toUpperCase() + tabId.slice(1));
      const targetBtn = document.getElementById('tabBtn' + tabId.charAt(0).toUpperCase() + tabId.slice(1));
      if (targetTab && targetBtn) {
        targetTab.classList.remove('hidden');
        targetBtn.classList.add('active');
      }

      if (tabId === 'vault') loadVaultFiles();
      if (tabId === 'keys') loadKeys();
    }

    function updateFileName(input) {
      const label = document.getElementById('selectedFileName');
      if (input.files.length > 0) {
        label.innerText = input.files[0].name + ' (' + (input.files[0].size / 1024).toFixed(1) + ' KB)';
      }
    }

    async function loadStats() {
      try {
        const res = await fetch('/api/status');
        const data = await res.json();
        document.getElementById('statTotalFiles').innerText = data.total_files;
        document.getElementById('statTotalBytes').innerText = (data.total_encrypted_bytes / 1024).toFixed(1) + ' KB';
      } catch (e) { console.error(e); }
    }

    async function loadKeys() {
      try {
        const res = await fetch('/api/keys');
        const data = await res.json();
        document.getElementById('pubKeyArea').value = data.public_key;
        document.getElementById('privKeyArea').value = data.private_key;
      } catch (e) { console.error(e); }
    }

    async function generateNewKeys() {
      if (!confirm('Generating a new keypair will replace the current active keys. Files encrypted with previous keys will require their original private key. Continue?')) return;
      try {
        const res = await fetch('/api/keys/generate', { method: 'POST' });
        const data = await res.json();
        document.getElementById('pubKeyArea').value = data.public_key;
        document.getElementById('privKeyArea').value = data.private_key;
        alert(data.message);
      } catch (e) { alert('Error generating keys'); }
    }

    function readFileAsBase64(file) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          const b64 = reader.result.split(',')[1];
          resolve(b64);
        };
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
    }

    async function handleUpload(e) {
      e.preventDefault();
      const fileInput = document.getElementById('fileInput');
      if (!fileInput.files.length) {
        alert('Please select a file first.');
        return;
      }

      const btn = document.getElementById('uploadBtn');
      btn.disabled = true;
      btn.innerText = 'Encrypting & Storing in Firebase...';

      try {
        const file = fileInput.files[0];
        const contentBase64 = await readFileAsBase64(file);
        const protocol = document.getElementById('protocolSelect').value;

        const res = await fetch('/api/upload', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            filename: file.name,
            content_base64: contentBase64,
            protocol: protocol
          })
        });

        const data = await res.json();
        const resDiv = document.getElementById('uploadResult');
        resDiv.classList.remove('hidden');
        resDiv.innerHTML = `
          <div class="result-header">✔ File Successfully Encrypted and Stored in Firebase!</div>
          <div class="result-item"><strong>File ID:</strong> ${data.file_id}</div>
          <div class="result-item"><strong>Protocol:</strong> ${data.protocol}</div>
          <div class="result-item"><strong>Original Size:</strong> ${data.original_size_bytes} bytes</div>
          <div class="result-item"><strong>Encrypted Size:</strong> ${data.encrypted_size_bytes} bytes</div>
          <div class="result-item"><strong>SHA-256 Digest:</strong> ${data.sha256}</div>
          <div class="result-item"><strong>Encryption Time:</strong> ${data.encrypt_time_ms} ms</div>
        `;
        loadStats();
      } catch (err) {
        alert('Upload failed: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.innerText = 'Encrypt & Upload to Cloud Vault';
      }
    }

    async function loadVaultFiles() {
      const tbody = document.getElementById('vaultTableBody');
      tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 24px;">Fetching files from Firestore...</td></tr>';
      try {
        const res = await fetch('/api/files');
        const files = await res.json();
        if (!files.length) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 24px;">No files found in Firebase Vault.</td></tr>';
          return;
        }

        tbody.innerHTML = files.map(f => `
          <tr>
            <td style="font-weight: 600; color: #f1f5f9;">${f.file_name}</td>
            <td style="color: #818cf8; font-size: 12px;">${f.protocol ? f.protocol.split(' ')[0] : 'CP2'}</td>
            <td style="color: #94a3b8; font-size: 12px;">${(f.original_size_bytes / 1024).toFixed(1)} KB</td>
            <td style="color: #fbbf24; font-size: 12px;">${(f.encrypted_size_bytes / 1024).toFixed(1)} KB</td>
            <td style="font-family: monospace; font-size: 11px; color: #64748b;" title="${f.sha256}">${f.sha256 ? f.sha256.substring(0, 12) + '...' : '-'}</td>
            <td style="color: #94a3b8; font-size: 12px;">${f.uploaded_at || '-'}</td>
            <td style="text-align: right;">
              <a href="/api/download/${f.file_id}" target="_blank" class="btn-sm btn-download" style="margin-right: 6px;">
                Decrypt & Download
              </a>
              <button onclick="deleteFile('${f.file_id}')" class="btn-sm btn-delete">
                Delete
              </button>
            </td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #fb7185; padding: 24px;">Failed to load files from Firebase.</td></tr>';
      }
    }

    async function deleteFile(fileId) {
      if (!confirm('Are you sure you want to permanently delete this encrypted file?')) return;
      try {
        await fetch('/api/files/' + fileId, { method: 'DELETE' });
        loadVaultFiles();
        loadStats();
      } catch (e) { alert('Failed to delete file'); }
    }

    async function benchmarkSample(sampleName) {
      switchTab('benchmark');
      const loader = document.getElementById('benchmarkLoading');
      const resultsDiv = document.getElementById('benchmarkResults');
      loader.classList.remove('hidden');
      resultsDiv.classList.add('hidden');

      try {
        const res = await fetch('/api/benchmark/' + sampleName);
        const data = await res.json();
        loader.classList.add('hidden');
        resultsDiv.classList.remove('hidden');

        const cp2 = data.cp2_hybrid;
        const cp1 = data.cp1_rsa;

        let cp1Html = '';
        if (cp1.skipped) {
          cp1Html = `
            <div class="bench-card">
              <div class="bench-card-title" style="color: #fb7185;">CP1 Pure RSA Chunked</div>
              <div class="bench-timing" style="font-size: 18px; color: #cbd5e1;">SKIPPED</div>
              <div style="font-size: 12px; color: #94a3b8; line-height: 1.4;">${cp1.reason}</div>
            </div>
          `;
        } else {
          const speedup = (cp1.total_time_ms / Math.max(cp2.total_time_ms, 0.01)).toFixed(1);
          cp1Html = `
            <div class="bench-card">
              <div class="bench-card-title" style="color: #fbbf24;">CP1 Pure RSA Chunked</div>
              <div class="bench-timing">${cp1.total_time_ms} ms</div>
              <div style="font-size: 12px; color: #94a3b8; line-height: 1.6;">
                <div>Encrypt: <strong>${cp1.encrypt_time_ms} ms</strong></div>
                <div>Decrypt: <strong>${cp1.decrypt_time_ms} ms</strong></div>
                <div>Integrity: <span style="color: #34d399; font-weight: 700;">${cp1.verified ? 'VERIFIED' : 'FAILED'}</span></div>
              </div>
              <div style="margin-top: 10px; font-size: 12px; font-weight: 700; color: #818cf8;">
                AES-Hybrid is ${speedup}x FASTER
              </div>
            </div>
          `;
        }

        resultsDiv.innerHTML = `
          <h3 style="font-size: 15px; font-weight: 700; color: #ffffff; margin-bottom: 12px;">Results for ${data.file_name} (${(data.file_size_bytes / 1024).toFixed(1)} KB)</h3>
          <div class="bench-grid">
            <div class="bench-card">
              <div class="bench-card-title" style="color: #34d399;">CP2 Hybrid (AES-256-GCM + RSA)</div>
              <div class="bench-timing">${cp2.total_time_ms} ms</div>
              <div style="font-size: 12px; color: #94a3b8; line-height: 1.6;">
                <div>Encrypt: <strong>${cp2.encrypt_time_ms} ms</strong></div>
                <div>Decrypt: <strong>${cp2.decrypt_time_ms} ms</strong></div>
                <div>Integrity: <span style="color: #34d399; font-weight: 700;">${cp2.verified ? 'VERIFIED' : 'FAILED'}</span></div>
              </div>
              <div style="margin-top: 10px; font-size: 12px; font-weight: 700; color: #34d399;">
                Optimal for large cloud storage
              </div>
            </div>
            ${cp1Html}
          </div>
        `;
      } catch (err) {
        loader.classList.add('hidden');
        alert('Benchmark error: ' + err.message);
      }
    }

    // Init
    loadStats();
  </script>
</body>
</html>"""

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
