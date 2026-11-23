# CNS Secure File Encryption System (with Firebase Cloud Vault)

A Cryptography and Network Security (CNS) end-to-end file encryption and secure cloud transfer system. 
This project modernizes the classic **Confidentiality Protocol 1 (CP1: Pure RSA)** and **Confidentiality Protocol 2 (CP2: Hybrid AES + RSA Envelope Encryption)** by integrating **Firebase Cloud (100% Free Spark Tier)** for Zero-Knowledge cloud storage.

Repository: [https://github.com/AkashJanawad/CNS_File_Encryption_System.git](https://github.com/AkashJanawad/CNS_File_Encryption_System.git)

---

## Architecture & Cryptographic Design

```
[ Client / Web UI ]
       │
       ├── 1. Generate local 256-bit AES-GCM symmetric session key & 96-bit nonce
       ├── 2. Client-side File Encryption:
       │       - Encrypt file with AES-256-GCM (Authenticated Encryption)
       │       - Calculate SHA-256 integrity checksum
       │       - Encrypt the AES session key using recipient's RSA-2048 Public Key (Envelope Encryption)
       │
       └── 3. Upload to Firebase (Zero-Knowledge)
               ├── Ciphertext Chunks ──► Cloud Firestore Vault (100% Free Tier, No Credit Card)
               └── Metadata ───────────► { fileId, fileName, sha256, encryptedAesKey, nonce, protocol }
```

### Protocol Comparison

| Feature | Protocol 1 (CP1) - Pure RSA | Protocol 2 (CP2) - Hybrid AES + RSA |
| :--- | :--- | :--- |
| **Cipher** | RSA-2048 OAEP (Asymmetric) | AES-256-GCM + RSA-2048 OAEP (Hybrid) |
| **Chunking** | 190-byte plain text blocks | Stream/authenticated block encryption |
| **Encryption Speed** | Slow for files > 100 KB ($O(N)$ modular exponentiations) | **Ultra Fast** (~1.5 ms for 1.5 MB file) |
| **Integrity Check** | SHA-256 | AES-GCM Authentication Tag + SHA-256 |
| **Best Used For** | Small payloads, key exchanges, certificates | Bulk files, cloud storage, multimedia |

---

## Firebase Setup (100% Free Spark Tier - No Credit Card Required)

1. Open [Firebase Console](https://console.firebase.google.com/) and create a project (e.g. `cns-file-encryption`).
2. Go to **Build** -> **Firestore Database** -> Click **Create database** -> Choose region -> Select **Start in test mode**.
3. In **Project settings** -> **Service accounts** tab, click **Generate new private key**.
4. Save the downloaded JSON file as:
   ```
   Z:\CNS\serviceAccountKey.json
   ```
   *(Note: This key is protected by `.gitignore` and must never be committed to Git).*

---

## Multi-User Authentication & Privacy Isolation

The system now enforces strict **Multi-Tenancy and Access Control**:
1. **Firebase Email/Password Authentication**: Each user registers with their email and password.
2. **Personalized Keypairs**: Every user automatically receives their own dedicated **RSA-2048 Keypair** on signup.
3. **Database-Level Isolation**: Files uploaded by User A are tagged with `owner_uid` and are **completely invisible** to User B in the Cloud Vault.
4. **Access Control Verification**: Downloading or decrypting verifies user ownership; unauthorized users attempting to access another user's file receive a `403 Access Denied` response.

---

## Quickstart Guide

### 1. Launch Interactive Web Dashboard
Run the local web dashboard:
```powershell
python app.py
```
Open your browser at **`http://localhost:8000`**.

Features available in Web UI:
- **Key Manager**: Generate RSA-2048 keypairs, inspect and copy public/private keys.
- **Upload & Encrypt**: Select files, choose CP1 or CP2, encrypt client-side and store in Firebase.
- **Cloud Vault Explorer**: View encrypted files in Firebase, decrypt and download with automatic SHA-256 integrity checks.
- **Protocol Benchmark**: Benchmark `smallFile.txt`, `medianFile.txt`, and `largeFile.txt` with real-time performance graphs.

---

### 2. Command Line Interface (CLI)

#### Generate RSA Keypair
```powershell
python cns_cli.py genkeys
```

#### Encrypt and Upload File to Firebase
```powershell
python cns_cli.py upload NSProgrammingAssignment2/smallFile.txt --protocol CP2
```

#### List Files in Firebase Vault
```powershell
python cns_cli.py list
```

#### Download and Decrypt File (with SHA-256 Integrity Verification)
```powershell
python cns_cli.py download <FILE_ID>
```

#### Run CP1 vs CP2 Benchmark
```powershell
python cns_cli.py benchmark
```

---

## Benchmark Results (Empirical Performance)

Benchmarked on Windows with Intel/AMD CPU using assignment test files:

```
[*] smallFile.txt (1.18 KB):
  ├── CP2 Hybrid (AES-256-GCM + RSA): 1.83 ms
  └── CP1 Pure RSA:                   0.50 ms

[*] medianFile.txt (1.54 MB):
  ├── CP2 Hybrid (AES-256-GCM + RSA): 1.51 ms (Ultra-fast)
  └── CP1 Pure RSA:                   SKIPPED (Requires > 8,000 RSA modular exponentiations!)

[*] largeFile.txt (3.45 MB):
  ├── CP2 Hybrid (AES-256-GCM + RSA): 2.65 ms
  └── CP1 Pure RSA:                   SKIPPED (Requires > 18,000 RSA modular exponentiations!)
```

---

## Legacy Java Socket System (`NSProgrammingAssignment2`)

The original Java socket implementation has been updated to be fully compatible with **Java 21** (upgraded from deprecated `javax.xml.bind.DatatypeConverter` to `java.util.Base64`):

- **Compile**:
  ```powershell
  javac -d "NSProgrammingAssignment2/bin" (Get-ChildItem -Path "NSProgrammingAssignment2/src" -Filter *.java -Recurse | Select-Object -ExpandProperty FullName)
  ```
- **Run Server**:
  ```powershell
  java -cp "NSProgrammingAssignment2/bin" Server.CP1Server
  ```
- **Run Client**:
  ```powershell
  java -cp "NSProgrammingAssignment2/bin" Client.CP2Client smallFile.txt
  ```

---

## Security & `.gitignore`

The following sensitive files are strictly excluded from git tracking:
- `serviceAccountKey.json` (Firebase Admin Private Key)
- `keys/*.pem` (User RSA Private Keys)
- `*.der` / `*.crt` (Local certificates)
- Compiled `.class` binaries & build artifacts
