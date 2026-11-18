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
# HTML Web Dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def serve_ui():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CNS File Encryption System | Firebase Cloud Vault</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Inter', sans-serif; }
    code, pre { font-family: 'JetBrains Mono', monospace; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen">

  <!-- Navigation Bar -->
  <header class="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-amber-500 to-indigo-600 flex items-center justify-center font-bold text-white shadow-lg shadow-indigo-500/20">
          CNS
        </div>
        <div>
          <h1 class="text-lg font-bold text-white leading-tight">Secure File Encryption System</h1>
          <p class="text-xs text-slate-400">Zero-Knowledge Envelope Encryption with Firebase</p>
        </div>
      </div>
      <div class="flex items-center gap-3">
        <div class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-medium">
          <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          Firebase Spark Free Tier (100% Free)
        </div>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="max-w-7xl mx-auto px-4 py-8">

    <!-- Top Stats Row -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
      <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div class="text-slate-400 text-xs uppercase tracking-wider font-semibold">Cloud Database</div>
        <div class="text-xl font-bold text-white mt-1">Cloud Firestore</div>
        <div class="text-xs text-emerald-400 mt-1">1 GB Free Storage Quota</div>
      </div>
      <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div class="text-slate-400 text-xs uppercase tracking-wider font-semibold">Total Encrypted Files</div>
        <div id="statTotalFiles" class="text-xl font-bold text-indigo-400 mt-1">0</div>
        <div class="text-xs text-slate-400 mt-1">Stored securely</div>
      </div>
      <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div class="text-slate-400 text-xs uppercase tracking-wider font-semibold">Total Encrypted Volume</div>
        <div id="statTotalBytes" class="text-xl font-bold text-amber-400 mt-1">0 KB</div>
        <div class="text-xs text-slate-400 mt-1">Zero-Knowledge Ciphertext</div>
      </div>
      <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
        <div class="text-slate-400 text-xs uppercase tracking-wider font-semibold">Cryptographic Standards</div>
        <div class="text-sm font-semibold text-slate-200 mt-1">RSA-2048 + AES-256-GCM</div>
        <div class="text-xs text-cyan-400 mt-1">SHA-256 Checksum Integrity</div>
      </div>
    </div>

    <!-- Navigation Tabs -->
    <div class="flex gap-2 border-b border-slate-800 mb-6">
      <button onclick="switchTab('upload')" id="tabBtnUpload" class="tab-btn px-4 py-2 text-sm font-medium border-b-2 border-indigo-500 text-indigo-400">
        Upload & Encrypt
      </button>
      <button onclick="switchTab('vault')" id="tabBtnVault" class="tab-btn px-4 py-2 text-sm font-medium border-b-2 border-transparent text-slate-400 hover:text-slate-200">
        Cloud Vault Explorer
      </button>
      <button onclick="switchTab('benchmark')" id="tabBtnBenchmark" class="tab-btn px-4 py-2 text-sm font-medium border-b-2 border-transparent text-slate-400 hover:text-slate-200">
        CP1 vs CP2 Benchmark
      </button>
      <button onclick="switchTab('keys')" id="tabBtnKeys" class="tab-btn px-4 py-2 text-sm font-medium border-b-2 border-transparent text-slate-400 hover:text-slate-200">
        RSA Key Manager
      </button>
    </div>

    <!-- Tab 1: Upload & Encrypt -->
    <div id="tabUpload" class="tab-content">
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
          <h2 class="text-lg font-bold text-white mb-2">Upload & Encrypt File</h2>
          <p class="text-sm text-slate-400 mb-6">Select a file. It will be encrypted locally with high-speed authenticated encryption before being stored in Firebase.</p>

          <form id="uploadForm" onsubmit="handleUpload(event)" class="space-y-5">
            <div>
              <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Choose File</label>
              <div class="border-2 border-dashed border-slate-700 hover:border-indigo-500 transition-colors rounded-xl p-8 text-center bg-slate-950/50 cursor-pointer" onclick="document.getElementById('fileInput').click()">
                <input type="file" id="fileInput" class="hidden" onchange="updateFileName(this)" />
                <svg class="w-10 h-10 mx-auto text-slate-500 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
                <div id="selectedFileName" class="text-sm text-slate-300 font-medium">Click or drag & drop a file here</div>
                <div class="text-xs text-slate-500 mt-1">Supports any file size (auto-chunked)</div>
              </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Encryption Protocol</label>
                <select id="protocolSelect" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500">
                  <option value="CP2">Protocol 2 (CP2): Hybrid AES-256-GCM + RSA (Recommended)</option>
                  <option value="CP1">Protocol 1 (CP1): Pure RSA Asymmetric Chunked</option>
                </select>
              </div>
              <div>
                <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Target Storage</label>
                <div class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2.5 text-sm text-emerald-400">
                  Firebase Cloud Firestore (100% Free)
                </div>
              </div>
            </div>

            <button type="submit" id="uploadBtn" class="w-full py-3 bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white font-medium rounded-xl shadow-lg shadow-indigo-600/30 transition-all">
              Encrypt & Upload to Cloud Vault
            </button>
          </form>

          <div id="uploadResult" class="hidden mt-6 p-4 rounded-xl bg-slate-950 border border-slate-800"></div>
        </div>

        <!-- Quick Sample Files -->
        <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
          <h3 class="text-sm font-bold text-white uppercase tracking-wider mb-4">Assignment Test Files</h3>
          <p class="text-xs text-slate-400 mb-4">Original benchmark files located in <code class="text-indigo-300">NSProgrammingAssignment2/</code>:</p>
          <div class="space-y-3">
            <div class="p-3 bg-slate-950 rounded-lg border border-slate-800 flex justify-between items-center">
              <div>
                <div class="text-sm font-medium text-slate-200">smallFile.txt</div>
                <div class="text-xs text-slate-500">1.18 KB</div>
              </div>
              <button onclick="benchmarkSample('smallFile.txt')" class="px-2.5 py-1 text-xs bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 rounded hover:bg-indigo-600/30">Benchmark</button>
            </div>
            <div class="p-3 bg-slate-950 rounded-lg border border-slate-800 flex justify-between items-center">
              <div>
                <div class="text-sm font-medium text-slate-200">medianFile.txt</div>
                <div class="text-xs text-slate-500">1.54 MB</div>
              </div>
              <button onclick="benchmarkSample('medianFile.txt')" class="px-2.5 py-1 text-xs bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 rounded hover:bg-indigo-600/30">Benchmark</button>
            </div>
            <div class="p-3 bg-slate-950 rounded-lg border border-slate-800 flex justify-between items-center">
              <div>
                <div class="text-sm font-medium text-slate-200">largeFile.txt</div>
                <div class="text-xs text-slate-500">3.45 MB</div>
              </div>
              <button onclick="benchmarkSample('largeFile.txt')" class="px-2.5 py-1 text-xs bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 rounded hover:bg-indigo-600/30">Benchmark</button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Tab 2: Cloud Vault Explorer -->
    <div id="tabVault" class="tab-content hidden">
      <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
        <div class="flex items-center justify-between mb-6">
          <div>
            <h2 class="text-lg font-bold text-white">Firebase Encrypted Vault</h2>
            <p class="text-sm text-slate-400">All files are stored as encrypted ciphertext. Only someone with your RSA Private Key can decrypt them.</p>
          </div>
          <button onclick="loadVaultFiles()" class="px-3 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700">
            Refresh List
          </button>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead class="text-xs uppercase bg-slate-950/60 text-slate-400 border-b border-slate-800">
              <tr>
                <th class="p-3">File Name</th>
                <th class="p-3">Protocol</th>
                <th class="p-3">Plain Size</th>
                <th class="p-3">Cipher Size</th>
                <th class="p-3">SHA-256 Digest</th>
                <th class="p-3">Uploaded At</th>
                <th class="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="vaultTableBody" class="divide-y border-slate-800">
              <tr><td colspan="7" class="p-6 text-center text-slate-500">Loading files...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Tab 3: Benchmark -->
    <div id="tabBenchmark" class="tab-content hidden">
      <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 mb-6">
        <h2 class="text-lg font-bold text-white mb-2">Cryptographic Protocol Benchmark</h2>
        <p class="text-sm text-slate-400 mb-6">Empirical comparison between <strong>Protocol 1 (Pure RSA Chunked)</strong> and <strong>Protocol 2 (Hybrid AES+RSA)</strong>.</p>

        <div class="flex gap-3 mb-6">
          <button onclick="benchmarkSample('smallFile.txt')" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl text-sm font-medium text-slate-200">
            Benchmark smallFile.txt (1.2 KB)
          </button>
          <button onclick="benchmarkSample('medianFile.txt')" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl text-sm font-medium text-slate-200">
            Benchmark medianFile.txt (1.5 MB)
          </button>
          <button onclick="benchmarkSample('largeFile.txt')" class="px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-xl text-sm font-medium text-slate-200">
            Benchmark largeFile.txt (3.4 MB)
          </button>
        </div>

        <div id="benchmarkLoading" class="hidden p-6 text-center text-slate-400">
          <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500 mb-3"></div>
          <div>Running encryption and decryption trials...</div>
        </div>

        <div id="benchmarkResults" class="hidden"></div>
      </div>
    </div>

    <!-- Tab 4: Keys -->
    <div id="tabKeys" class="tab-content hidden">
      <div class="bg-slate-900/80 border border-slate-800 rounded-2xl p-6">
        <div class="flex items-center justify-between mb-4">
          <div>
            <h2 class="text-lg font-bold text-white">RSA-2048 Asymmetric Key Pair</h2>
            <p class="text-sm text-slate-400">Used for envelope encryption (encrypting symmetric AES keys) and authentication.</p>
          </div>
          <button onclick="generateNewKeys()" class="px-4 py-2 bg-rose-600/20 hover:bg-rose-600/30 text-rose-400 border border-rose-500/30 rounded-xl text-xs font-semibold">
            Generate New Keypair
          </button>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
          <div>
            <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Public Key (SubjectPublicKeyInfo PEM)</label>
            <textarea id="pubKeyArea" readonly class="w-full h-64 bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs text-indigo-300 font-mono focus:outline-none"></textarea>
          </div>
          <div>
            <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Private Key (PKCS#8 PEM - KEEP SECRET)</label>
            <textarea id="privKeyArea" readonly class="w-full h-64 bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs text-rose-300 font-mono focus:outline-none"></textarea>
          </div>
        </div>
      </div>
    </div>

  </main>

  <script>
    function switchTab(tabId) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
      document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('border-indigo-500', 'text-indigo-400');
        btn.classList.add('border-transparent', 'text-slate-400');
      });

      const targetTab = document.getElementById('tab' + tabId.charAt(0).toUpperCase() + tabId.slice(1));
      const targetBtn = document.getElementById('tabBtn' + tabId.charAt(0).toUpperCase() + tabId.slice(1));
      if (targetTab && targetBtn) {
        targetTab.classList.remove('hidden');
        targetBtn.classList.add('border-indigo-500', 'text-indigo-400');
        targetBtn.classList.remove('border-transparent', 'text-slate-400');
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
          <div class="text-sm font-semibold text-emerald-400 mb-2">✔ File Successfully Encrypted and Stored in Firebase!</div>
          <div class="text-xs text-slate-300 space-y-1 font-mono">
            <div><strong class="text-slate-400">File ID:</strong> ${data.file_id}</div>
            <div><strong class="text-slate-400">Protocol:</strong> ${data.protocol}</div>
            <div><strong class="text-slate-400">Original Size:</strong> ${data.original_size_bytes} bytes</div>
            <div><strong class="text-slate-400">Encrypted Size:</strong> ${data.encrypted_size_bytes} bytes</div>
            <div><strong class="text-slate-400">SHA-256 Digest:</strong> ${data.sha256}</div>
            <div><strong class="text-slate-400">Encryption Time:</strong> ${data.encrypt_time_ms} ms</div>
          </div>
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
      tbody.innerHTML = '<tr><td colspan="7" class="p-6 text-center text-slate-500">Fetching files from Firestore...</td></tr>';
      try {
        const res = await fetch('/api/files');
        const files = await res.json();
        if (!files.length) {
          tbody.innerHTML = '<tr><td colspan="7" class="p-6 text-center text-slate-500">No files found in Firebase Vault.</td></tr>';
          return;
        }

        tbody.innerHTML = files.map(f => `
          <tr class="hover:bg-slate-900/40">
            <td class="p-3 font-medium text-slate-200">${f.file_name}</td>
            <td class="p-3 text-xs text-indigo-400">${f.protocol ? f.protocol.split(' ')[0] : 'CP2'}</td>
            <td class="p-3 text-xs text-slate-400">${(f.original_size_bytes / 1024).toFixed(1)} KB</td>
            <td class="p-3 text-xs text-amber-400">${(f.encrypted_size_bytes / 1024).toFixed(1)} KB</td>
            <td class="p-3 text-xs font-mono text-slate-500" title="${f.sha256}">${f.sha256 ? f.sha256.substring(0, 12) + '...' : '-'}</td>
            <td class="p-3 text-xs text-slate-400">${f.uploaded_at || '-'}</td>
            <td class="p-3 text-right space-x-2">
              <a href="/api/download/${f.file_id}" target="_blank" class="px-2.5 py-1 text-xs bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 rounded hover:bg-emerald-600/30 inline-block">
                Decrypt & Download
              </a>
              <button onclick="deleteFile('${f.file_id}')" class="px-2.5 py-1 text-xs bg-rose-600/20 text-rose-400 border border-rose-500/30 rounded hover:bg-rose-600/30">
                Delete
              </button>
            </td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" class="p-6 text-center text-rose-400">Failed to load files from Firebase.</td></tr>';
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
            <div class="p-4 bg-slate-950 border border-slate-800 rounded-xl">
              <div class="text-xs uppercase font-semibold text-rose-400">CP1 Pure RSA Chunked</div>
              <div class="text-sm font-bold text-slate-300 mt-2">SKIPPED</div>
              <div class="text-xs text-slate-400 mt-2">${cp1.reason}</div>
            </div>
          `;
        } else {
          const speedup = (cp1.total_time_ms / Math.max(cp2.total_time_ms, 0.01)).toFixed(1);
          cp1Html = `
            <div class="p-4 bg-slate-950 border border-slate-800 rounded-xl">
              <div class="text-xs uppercase font-semibold text-amber-400">CP1 Pure RSA Chunked</div>
              <div class="text-xl font-bold text-white mt-1">${cp1.total_time_ms} ms</div>
              <div class="text-xs text-slate-400 mt-2 space-y-1">
                <div>Encrypt: <strong>${cp1.encrypt_time_ms} ms</strong></div>
                <div>Decrypt: <strong>${cp1.decrypt_time_ms} ms</strong></div>
                <div>Integrity: <span class="text-emerald-400 font-bold">${cp1.verified ? 'VERIFIED' : 'FAILED'}</span></div>
              </div>
              <div class="mt-3 text-xs font-semibold text-indigo-400">
                AES-Hybrid is ${speedup}x FASTER
              </div>
            </div>
          `;
        }

        resultsDiv.innerHTML = `
          <h3 class="text-md font-bold text-white mb-4">Results for ${data.file_name} (${(data.file_size_bytes / 1024).toFixed(1)} KB)</h3>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="p-4 bg-slate-950 border border-slate-800 rounded-xl">
              <div class="text-xs uppercase font-semibold text-emerald-400">CP2 Hybrid (AES-256-GCM + RSA)</div>
              <div class="text-xl font-bold text-white mt-1">${cp2.total_time_ms} ms</div>
              <div class="text-xs text-slate-400 mt-2 space-y-1">
                <div>Encrypt: <strong>${cp2.encrypt_time_ms} ms</strong></div>
                <div>Decrypt: <strong>${cp2.decrypt_time_ms} ms</strong></div>
                <div>Integrity: <span class="text-emerald-400 font-bold">${cp2.verified ? 'VERIFIED' : 'FAILED'}</span></div>
              </div>
              <div class="mt-3 text-xs font-semibold text-emerald-400">
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
</html>
    """

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
