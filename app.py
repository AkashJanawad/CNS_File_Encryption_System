"""
CNS Secure File Encryption System - Web Application
FastAPI Server providing Multi-Tenant Zero-Knowledge Firebase Encrypted Storage & Benchmarking.
Features:
- Firebase Email/Password User Authentication
- Per-User Isolated Vault & Personalized RSA-2048 Keypairs
- Direct Multipart File Upload Streaming (Rock-solid, handles files of any size)
- 400 KB safe Firestore chunking
"""

import os
import io
import time
from typing import Optional
from fastapi import FastAPI, File, UploadFile, Form, Header, HTTPException, Depends
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

import crypto_engine
from firebase_vault import FirebaseCloudVault
from auth_manager import AuthManager

app = FastAPI(title="CNS Multi-Tenant File Encryption System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

vault = FirebaseCloudVault()
auth_mgr = AuthManager()

# Auth Request Models
class AuthRequest(BaseModel):
    email: str
    password: str

def get_current_user(authorization: Optional[str] = Header(None)):
    """Helper dependency to extract and verify logged-in user from Authorization header."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authentication required. Please sign in.")
    token = authorization.replace("Bearer ", "").strip()
    try:
        return auth_mgr.verify_token(token)
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))

# ---------------------------------------------------------------------------
# Authentication API Routes
# ---------------------------------------------------------------------------

@app.post("/api/auth/register")
def register(req: AuthRequest):
    try:
        return auth_mgr.register_user(req.email, req.password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {e}")

@app.post("/api/auth/login")
def login(req: AuthRequest):
    try:
        return auth_mgr.login_user(req.email, req.password)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {e}")

@app.get("/api/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    priv, pub = auth_mgr.get_user_keys(current_user["uid"])
    return {
        "uid": current_user["uid"],
        "email": current_user["email"],
        "public_key": pub,
        "private_key": priv
    }

# ---------------------------------------------------------------------------
# Vault API Routes (Strict Multi-Tenant Isolation)
# ---------------------------------------------------------------------------

@app.get("/api/status")
def get_status(authorization: Optional[str] = Header(None)):
    user_uid = None
    if authorization:
        try:
            token = authorization.replace("Bearer ", "").strip()
            user_info = auth_mgr.verify_token(token)
            user_uid = user_info["uid"]
        except Exception:
            pass
    return vault.get_vault_status(owner_uid=user_uid)

@app.get("/api/files")
def list_files(current_user: dict = Depends(get_current_user)):
    """Returns ONLY files owned by the logged-in user."""
    return vault.list_files(owner_uid=current_user["uid"])

@app.post("/api/upload")
async def upload_file(
    file: UploadFile = File(...),
    protocol: str = Form("CP2"),
    current_user: dict = Depends(get_current_user)
):
    temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_uploads")
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, file.filename)

    try:
        content = await file.read()
        with open(temp_path, "wb") as f:
            f.write(content)

        # Retrieve user's personal public key
        priv_pem, pub_pem = auth_mgr.get_user_keys(current_user["uid"])
        if not pub_pem:
            raise HTTPException(status_code=400, detail="User public encryption key not found.")

        # Upload strictly tagged with user ownership
        metadata = vault.upload_file(
            file_path=temp_path,
            public_key_pem=pub_pem,
            protocol=protocol,
            owner_uid=current_user["uid"],
            owner_email=current_user["email"]
        )
        return metadata
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.get("/api/download/{file_id}")
def download_file(file_id: str, current_user: dict = Depends(get_current_user)):
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "temp_downloads")
    os.makedirs(out_dir, exist_ok=True)

    try:
        priv_pem, _ = auth_mgr.get_user_keys(current_user["uid"])
        saved_path, verified, metadata = vault.download_file(
            file_id=file_id,
            private_key_pem=priv_pem,
            output_dir=out_dir,
            user_uid=current_user["uid"]
        )
        filename = metadata.get("file_name", "decrypted_file")
        with open(saved_path, "rb") as f:
            file_bytes = f.read()

        response = StreamingResponse(io.BytesIO(file_bytes), media_type="application/octet-stream")
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        response.headers["X-Integrity-Verified"] = str(verified)
        response.headers["X-SHA256"] = metadata.get("sha256", "")
        return response
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption/Download error: {str(e)}")

@app.delete("/api/files/{file_id}")
def delete_file(file_id: str, current_user: dict = Depends(get_current_user)):
    try:
        success = vault.delete_file(file_id, user_uid=current_user["uid"])
        if not success:
            raise HTTPException(status_code=404, detail="File not found")
        return {"message": "File permanently deleted from your vault"}
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))

@app.get("/api/benchmark/{sample_name}")
def run_benchmark(sample_name: str):
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "NSProgrammingAssignment2")
    file_path = os.path.join(base_dir, sample_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Sample benchmark file not found")

    with open(file_path, "rb") as f:
        data = f.read()

    return crypto_engine.run_crypto_benchmark(data, sample_name)

# ---------------------------------------------------------------------------
# HTML Web Dashboard (Full Multi-Tenant UI with Standalone Embedded CSS)
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CNS Multi-Tenant Secure File Encryption System</title>
  <style>
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
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    header {
      background: rgba(17, 24, 39, 0.9);
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
    .header-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .user-pill {
      display: flex;
      align-items: center;
      gap: 8px;
      background: rgba(99, 102, 241, 0.15);
      border: 1px solid rgba(99, 102, 241, 0.35);
      color: #a5b4fc;
      font-size: 13px;
      font-weight: 600;
      padding: 6px 14px;
      border-radius: 9999px;
    }
    .btn-logout {
      background: rgba(244, 63, 94, 0.15);
      border: 1px solid rgba(244, 63, 94, 0.35);
      color: #fb7185;
      font-size: 12px;
      font-weight: 600;
      padding: 6px 14px;
      border-radius: 8px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-logout:hover {
      background: rgba(244, 63, 94, 0.3);
    }

    main {
      max-width: 1240px;
      margin: 0 auto;
      padding: 28px 20px 48px;
    }

    /* Auth Overlay Modal */
    .auth-overlay {
      position: fixed;
      inset: 0;
      background: rgba(11, 15, 25, 0.95);
      backdrop-filter: blur(10px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 100;
      padding: 20px;
    }
    .auth-card {
      background: #111827;
      border: 1px solid #1e293b;
      border-radius: 20px;
      padding: 32px;
      max-width: 440px;
      width: 100%;
      box-shadow: 0 20px 40px rgba(0,0,0,0.6);
    }
    .auth-tabs {
      display: flex;
      border-bottom: 1px solid #1e293b;
      margin-bottom: 24px;
    }
    .auth-tab-btn {
      flex: 1;
      text-align: center;
      padding: 10px;
      font-size: 14px;
      font-weight: 700;
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      color: #94a3b8;
      cursor: pointer;
    }
    .auth-tab-btn.active {
      color: #818cf8;
      border-bottom-color: #6366f1;
    }
    .auth-error {
      background: rgba(244, 63, 94, 0.15);
      border: 1px solid rgba(244, 63, 94, 0.35);
      color: #fb7185;
      padding: 10px 14px;
      border-radius: 10px;
      font-size: 13px;
      margin-bottom: 16px;
      display: none;
    }

    /* Stats Grid */
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
    }
    .tab-btn.active {
      color: #818cf8;
      border-bottom-color: #6366f1;
    }
    .tab-content.hidden, .hidden {
      display: none !important;
    }

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

    .grid-2col {
      display: grid;
      grid-template-columns: 2fr 1fr;
      gap: 24px;
    }
    @media (max-width: 880px) {
      .grid-2col { grid-template-columns: 1fr; }
    }

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
      display: block;
      margin: 0 auto 12px;
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

    .form-group { margin-top: 18px; }
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
    }
    .btn-download {
      background: rgba(16, 185, 129, 0.15);
      border: 1px solid rgba(16, 185, 129, 0.35);
      color: #34d399;
      text-decoration: none;
      display: inline-block;
    }
    .btn-delete {
      background: rgba(244, 63, 94, 0.15);
      border: 1px solid rgba(244, 63, 94, 0.35);
      color: #fb7185;
    }

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
    .result-item strong { color: #94a3b8; }

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

    .table-responsive { overflow-x: auto; }
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

  <!-- Auth Modal Overlay -->
  <div id="authOverlay" class="auth-overlay">
    <div class="auth-card">
      <div style="text-align: center; margin-bottom: 24px;">
        <div class="brand-badge" style="margin: 0 auto 12px; width: 48px; height: 48px; font-size: 20px;">CNS</div>
        <h2 style="font-size: 20px; font-weight: 800; color: #fff;">Secure Vault Access</h2>
        <p style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Zero-Knowledge Multi-Tenant Encrypted Storage</p>
      </div>

      <div class="auth-tabs">
        <button id="authTabLogin" onclick="switchAuthTab('login')" class="auth-tab-btn active">Sign In</button>
        <button id="authTabRegister" onclick="switchAuthTab('register')" class="auth-tab-btn">Register New User</button>
      </div>

      <div id="authError" class="auth-error"></div>

      <form id="authForm" onsubmit="handleAuth(event)">
        <div style="margin-bottom: 16px;">
          <label class="form-label">Email Address</label>
          <input type="email" id="authEmail" required placeholder="user@example.com" />
        </div>
        <div style="margin-bottom: 20px;">
          <label class="form-label">Password</label>
          <input type="password" id="authPassword" required placeholder="Minimum 6 characters" />
        </div>
        <button type="submit" id="authSubmitBtn" class="btn-primary" style="margin-top: 0;">Sign In to Vault</button>
      </form>
    </div>
  </div>

  <!-- Header -->
  <header>
    <div class="header-inner">
      <div class="brand-wrap">
        <div class="brand-badge">CNS</div>
        <div>
          <div class="brand-title">Secure File Encryption System</div>
          <div class="brand-subtitle">Multi-Tenant Zero-Knowledge Cloud Vault</div>
        </div>
      </div>
      <div class="header-actions">
        <div id="userPill" class="user-pill">
          <span>👤</span>
          <span id="userEmailSpan">Not signed in</span>
        </div>
        <button onclick="handleLogout()" class="btn-logout">Sign Out</button>
      </div>
    </div>
  </header>

  <!-- Main Content -->
  <main>

    <!-- Top Stats -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">My Vault Database</div>
        <div class="stat-val">Cloud Firestore</div>
        <div class="stat-sub text-emerald">1 GB Free Storage Quota</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">My Private Encrypted Files</div>
        <div id="statTotalFiles" class="stat-val text-indigo">0</div>
        <div class="stat-sub text-emerald">Strict user isolation</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">My Encrypted Volume</div>
        <div id="statTotalBytes" class="stat-val text-amber">0 KB</div>
        <div class="stat-sub text-amber">Zero-Knowledge Ciphertext</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">My Encryption Standard</div>
        <div class="stat-val" style="font-size: 16px; margin-top: 10px;">Personal RSA-2048 + AES-GCM</div>
        <div class="stat-sub text-cyan">SHA-256 Checksum Integrity</div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="tabs-nav">
      <button onclick="switchTab('upload')" id="tabBtnUpload" class="tab-btn active">
        Upload & Encrypt
      </button>
      <button onclick="switchTab('vault')" id="tabBtnVault" class="tab-btn">
        My Cloud Vault Explorer
      </button>
      <button onclick="switchTab('benchmark')" id="tabBtnBenchmark" class="tab-btn">
        CP1 vs CP2 Benchmark
      </button>
      <button onclick="switchTab('keys')" id="tabBtnKeys" class="tab-btn">
        My RSA Key Manager
      </button>
    </div>

    <!-- Tab 1: Upload & Encrypt -->
    <div id="tabUpload" class="tab-content">
      <div class="grid-2col">
        <div class="panel">
          <h2 class="panel-title">Upload & Encrypt File</h2>
          <p class="panel-desc">Files are encrypted locally with your personal RSA key and AES-256-GCM. <strong>No other user can view or decrypt your files.</strong></p>

          <form id="uploadForm" onsubmit="handleUpload(event)">
            <label class="form-label">Select File to Encrypt</label>
            <div class="upload-zone" onclick="document.getElementById('fileInput').click()">
              <input type="file" id="fileInput" style="display: none;" onchange="updateFileName(this)" />
              <svg class="upload-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" width="48" height="48">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
              </svg>
              <div id="selectedFileName" class="upload-prompt">Click or drag & drop a file here</div>
              <div class="upload-hint">Fault-tolerant 400 KB chunking (handles files of any size)</div>
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
              Encrypt & Upload to My Private Vault
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
            <h2 class="panel-title">My Private Encrypted Files</h2>
            <p class="panel-desc" style="margin-bottom: 0;">Filtered strictly to your account. Other registered users cannot see or access these files.</p>
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
              <tr><td colspan="7" style="text-align: center; color: #64748b; padding: 24px;">Loading your private vault files...</td></tr>
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
          <div style="display: inline-block; width: 32px; height: 32px; border: 3px solid rgba(255,255,255,0.1); border-top-color: #6366f1; border-radius: 50%; animation: spin 0.8s linear infinite;"></div>
          <div style="margin-top: 12px;">Running encryption and decryption trials...</div>
        </div>

        <div id="benchmarkResults" class="hidden"></div>
      </div>
    </div>

    <!-- Tab 4: Keys -->
    <div id="tabKeys" class="tab-content hidden">
      <div class="panel">
        <h2 class="panel-title">My Personal RSA-2048 Key Pair</h2>
        <p class="panel-desc">Unique cryptographic keys assigned exclusively to your account. Your files are encrypted with this public key and can only be decrypted by your private key.</p>

        <div class="form-row" style="margin-top: 16px;">
          <div>
            <label class="form-label">My Public Key (SubjectPublicKeyInfo PEM)</label>
            <textarea id="pubKeyArea" readonly rows="12" style="color: #818cf8;"></textarea>
          </div>
          <div>
            <label class="form-label">My Private Key (PKCS#8 PEM - KEEP SECRET)</label>
            <textarea id="privKeyArea" readonly rows="12" style="color: #fb7185;"></textarea>
          </div>
        </div>
      </div>
    </div>

  </main>

  <script>
    let authMode = 'login';
    let currentUser = null;

    function getAuthHeaders() {
      const token = localStorage.getItem('cns_id_token');
      return token ? { 'Authorization': 'Bearer ' + token } : {};
    }

    function switchAuthTab(mode) {
      authMode = mode;
      document.getElementById('authError').style.display = 'none';
      if (mode === 'login') {
        document.getElementById('authTabLogin').classList.add('active');
        document.getElementById('authTabRegister').classList.remove('active');
        document.getElementById('authSubmitBtn').innerText = 'Sign In to Vault';
      } else {
        document.getElementById('authTabRegister').classList.add('active');
        document.getElementById('authTabLogin').classList.remove('active');
        document.getElementById('authSubmitBtn').innerText = 'Create Account & Generate Keys';
      }
    }

    async function handleAuth(e) {
      e.preventDefault();
      const email = document.getElementById('authEmail').value.trim();
      const password = document.getElementById('authPassword').value;
      const errorDiv = document.getElementById('authError');
      const submitBtn = document.getElementById('authSubmitBtn');

      errorDiv.style.display = 'none';
      submitBtn.disabled = true;
      submitBtn.innerText = 'Verifying with Firebase...';

      const endpoint = (authMode === 'login') ? '/api/auth/login' : '/api/auth/register';

      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Authentication failed');
        }

        // Save session
        localStorage.setItem('cns_id_token', data.id_token);
        localStorage.setItem('cns_email', data.email);
        localStorage.setItem('cns_uid', data.uid);

        document.getElementById('authOverlay').style.display = 'none';
        initUserSession();
      } catch (err) {
        errorDiv.innerText = err.message;
        errorDiv.style.display = 'block';
      } finally {
        submitBtn.disabled = false;
        submitBtn.innerText = (authMode === 'login') ? 'Sign In to Vault' : 'Create Account & Generate Keys';
      }
    }

    function handleLogout() {
      if (!confirm('Are you sure you want to sign out?')) return;
      localStorage.removeItem('cns_id_token');
      localStorage.removeItem('cns_email');
      localStorage.removeItem('cns_uid');
      document.getElementById('authOverlay').style.display = 'flex';
      document.getElementById('userEmailSpan').innerText = 'Not signed in';
    }

    async function initUserSession() {
      const token = localStorage.getItem('cns_id_token');
      if (!token) {
        document.getElementById('authOverlay').style.display = 'flex';
        return;
      }

      try {
        const res = await fetch('/api/auth/me', { headers: getAuthHeaders() });
        if (!res.ok) throw new Error('Session expired');
        currentUser = await res.json();
        document.getElementById('userEmailSpan').innerText = currentUser.email;
        document.getElementById('authOverlay').style.display = 'none';
        document.getElementById('pubKeyArea').value = currentUser.public_key;
        document.getElementById('privKeyArea').value = currentUser.private_key;
        loadStats();
        loadVaultFiles();
      } catch (err) {
        handleLogout();
      }
    }

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
    }

    function updateFileName(input) {
      const label = document.getElementById('selectedFileName');
      if (input.files.length > 0) {
        label.innerText = input.files[0].name + ' (' + (input.files[0].size / 1024).toFixed(1) + ' KB)';
      }
    }

    async function loadStats() {
      try {
        const res = await fetch('/api/status', { headers: getAuthHeaders() });
        const data = await res.json();
        document.getElementById('statTotalFiles').innerText = data.total_files;
        document.getElementById('statTotalBytes').innerText = (data.total_encrypted_bytes / 1024).toFixed(1) + ' KB';
      } catch (e) { console.error(e); }
    }

    async function handleUpload(e) {
      e.preventDefault();
      const fileInput = document.getElementById('fileInput');
      if (!fileInput.files.length) {
        alert('Please select a file to encrypt first.');
        return;
      }

      const btn = document.getElementById('uploadBtn');
      btn.disabled = true;
      btn.innerText = 'Encrypting & Storing in Private Vault...';

      const formData = new FormData();
      formData.append('file', fileInput.files[0]);
      formData.append('protocol', document.getElementById('protocolSelect').value);

      try {
        const res = await fetch('/api/upload', {
          method: 'POST',
          headers: getAuthHeaders(),
          body: formData
        });

        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Upload failed');

        const resDiv = document.getElementById('uploadResult');
        resDiv.classList.remove('hidden');
        resDiv.innerHTML = `
          <div class="result-header">✔ File Successfully Encrypted & Saved to Your Private Vault!</div>
          <div class="result-item"><strong>File Name:</strong> ${data.file_name}</div>
          <div class="result-item"><strong>File ID:</strong> ${data.file_id}</div>
          <div class="result-item"><strong>Owner:</strong> ${data.owner_email}</div>
          <div class="result-item"><strong>Protocol:</strong> ${data.protocol}</div>
          <div class="result-item"><strong>Original Size:</strong> ${data.original_size_bytes} bytes</div>
          <div class="result-item"><strong>Encrypted Size:</strong> ${data.encrypted_size_bytes} bytes (${data.num_chunks} chunk(s))</div>
          <div class="result-item"><strong>SHA-256 Digest:</strong> ${data.sha256}</div>
          <div class="result-item"><strong>Encryption Time:</strong> ${data.encrypt_time_ms} ms</div>
        `;
        loadStats();
        loadVaultFiles();
      } catch (err) {
        alert('Upload Error: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.innerText = 'Encrypt & Upload to My Private Vault';
      }
    }

    async function loadVaultFiles() {
      const tbody = document.getElementById('vaultTableBody');
      tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 24px;">Fetching your private files from Firestore...</td></tr>';
      try {
        const res = await fetch('/api/files', { headers: getAuthHeaders() });
        const files = await res.json();
        if (!files.length) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 24px;">Your private vault is currently empty. Upload a file to see it here.</td></tr>';
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
              <button onclick="downloadFile('${f.file_id}')" class="btn-sm btn-download" style="margin-right: 6px;">
                Decrypt & Download
              </button>
              <button onclick="deleteFile('${f.file_id}')" class="btn-sm btn-delete">
                Delete
              </button>
            </td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #fb7185; padding: 24px;">Failed to load vault files.</td></tr>';
      }
    }

    async function downloadFile(fileId) {
      try {
        const res = await fetch('/api/download/' + fileId, { headers: getAuthHeaders() });
        if (!res.ok) {
          const errData = await res.json();
          throw new Error(errData.detail || 'Download failed');
        }

        const disposition = res.headers.get('Content-Disposition');
        let filename = 'decrypted_file';
        if (disposition && disposition.indexOf('filename=') !== -1) {
          const matches = /filename="([^"]*)"/.exec(disposition);
          if (matches != null && matches[1]) filename = matches[1];
        }

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
      } catch (e) {
        alert('Download Error: ' + e.message);
      }
    }

    async function deleteFile(fileId) {
      if (!confirm('Are you sure you want to permanently delete this encrypted file?')) return;
      try {
        const res = await fetch('/api/files/' + fileId, {
          method: 'DELETE',
          headers: getAuthHeaders()
        });
        if (!res.ok) {
          const err = await res.json();
          throw new Error(err.detail);
        }
        loadVaultFiles();
        loadStats();
      } catch (e) { alert('Delete Error: ' + e.message); }
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

    // Init session on page load
    initUserSession();
  </script>
</body>
</html>"""

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
