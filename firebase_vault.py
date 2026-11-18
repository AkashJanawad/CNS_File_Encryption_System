"""
Firebase Cloud Vault
Provides Zero-Knowledge Encrypted File Storage on Firebase Cloud Firestore (100% Free Tier - Spark Plan).
Features:
- Direct byte encryption storage for files under 750 KB.
- Automatic chunked subcollection storage for larger files (e.g. multi-MB files).
- Metadata tracking (SHA-256 integrity, encryption timestamps, protocol, encrypted keys).
"""

import os
import math
import uuid
import time
from typing import Dict, Any, List, Optional, Tuple

import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore import Client

import crypto_engine

# Chunk size for Firestore document safety (Firestore max doc size is 1 MiB)
CHUNK_SIZE = 700 * 1024  # 700 KB per chunk

class FirebaseCloudVault:
    def __init__(self, key_path: str = "serviceAccountKey.json"):
        if not os.path.isabs(key_path):
            key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), key_path)

        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Firebase Service Account Key not found at {key_path}")

        self.key_path = key_path
        self._initialize_app()
        self.db: Client = firestore.client()
        self.collection_name = "cns_encrypted_vault"

    def _initialize_app(self):
        try:
            firebase_admin.get_app()
        except ValueError:
            cred = credentials.Certificate(self.key_path)
            firebase_admin.initialize_app(cred)

    def upload_file(self, file_path: str, public_key_pem: str, protocol: str = "CP2") -> Dict[str, Any]:
        """
        Encrypts a local file and stores the ciphertext + metadata in Firebase Firestore.
        Zero-Knowledge: The cloud only receives encrypted bytes.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_name = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            plain_bytes = f.read()

        # 1. Perform Client-Side Encryption
        if protocol.upper() == "CP1":
            enc_result = crypto_engine.encrypt_cp1_rsa(plain_bytes, public_key_pem)
        else:
            enc_result = crypto_engine.encrypt_cp2_hybrid(plain_bytes, public_key_pem)

        ciphertext = enc_result["ciphertext"]
        cipher_len = len(ciphertext)
        file_id = str(uuid.uuid4())
        num_chunks = math.ceil(cipher_len / CHUNK_SIZE)

        # 2. Prepare Base Metadata Document
        metadata = {
            "file_id": file_id,
            "file_name": file_name,
            "original_size_bytes": len(plain_bytes),
            "encrypted_size_bytes": cipher_len,
            "sha256": enc_result["sha256"],
            "protocol": enc_result["protocol"],
            "encrypted_key_b64": enc_result["encrypted_key_b64"],
            "nonce_b64": enc_result["nonce_b64"],
            "encrypt_time_ms": enc_result["encrypt_time_ms"],
            "uploaded_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "timestamp": time.time(),
            "num_chunks": num_chunks,
            "is_chunked": (num_chunks > 1)
        }

        doc_ref = self.db.collection(self.collection_name).document(file_id)

        # 3. Store Ciphertext (Single Doc or Subcollection Chunks)
        if num_chunks == 1:
            metadata["ciphertext"] = ciphertext
            doc_ref.set(metadata)
        else:
            # Save metadata first without huge payload
            doc_ref.set(metadata)
            chunks_coll = doc_ref.collection("chunks")
            for i in range(num_chunks):
                chunk_data = ciphertext[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
                chunks_coll.document(f"chunk_{i}").set({
                    "index": i,
                    "data": chunk_data
                })

        return metadata

    def download_file(self, file_id: str, private_key_pem: str, output_dir: Optional[str] = None) -> Tuple[str, bool, Dict[str, Any]]:
        """
        Downloads encrypted file from Firebase, decrypts it locally, and verifies SHA-256 integrity.
        Returns: (saved_path, integrity_verified, metadata)
        """
        doc_ref = self.db.collection(self.collection_name).document(file_id)
        doc = doc_ref.get()

        if not doc.exists:
            raise KeyError(f"File ID {file_id} not found in Firebase Vault.")

        metadata = doc.to_dict()

        # 1. Fetch Ciphertext
        if not metadata.get("is_chunked", False):
            ciphertext = metadata["ciphertext"]
        else:
            num_chunks = metadata.get("num_chunks", 1)
            chunks_coll = doc_ref.collection("chunks")
            chunk_bytes = []
            for i in range(num_chunks):
                chunk_doc = chunks_coll.document(f"chunk_{i}").get()
                if not chunk_doc.exists:
                    raise IOError(f"Missing chunk {i} for file {file_id}")
                chunk_bytes.append(chunk_doc.to_dict()["data"])
            ciphertext = b"".join(chunk_bytes)

        # 2. Perform Client-Side Decryption
        protocol_name = metadata.get("protocol", "")
        if "CP1" in protocol_name:
            plaintext, dec_time = crypto_engine.decrypt_cp1_rsa(ciphertext, private_key_pem)
        else:
            plaintext, dec_time = crypto_engine.decrypt_cp2_hybrid(
                ciphertext,
                metadata["encrypted_key_b64"],
                metadata["nonce_b64"],
                private_key_pem
            )

        metadata["decrypt_time_ms"] = dec_time

        # 3. Verify SHA-256 Integrity
        computed_hash = crypto_engine.compute_sha256(plaintext)
        integrity_ok = (computed_hash == metadata.get("sha256"))

        # 4. Save to Disk
        if not output_dir:
            output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decrypted_files")
        os.makedirs(output_dir, exist_ok=True)

        output_path = os.path.join(output_dir, metadata["file_name"])
        with open(output_path, "wb") as f:
            f.write(plaintext)

        return output_path, integrity_ok, metadata

    def list_files(self) -> List[Dict[str, Any]]:
        """Lists all files stored in the Firebase Vault with metadata."""
        docs = self.db.collection(self.collection_name).order_by("timestamp", direction=firestore.Query.DESCENDING).stream()
        results = []
        for doc in docs:
            d = doc.to_dict()
            # Do not return large binary blobs in listing
            d.pop("ciphertext", None)
            results.append(d)
        return results

    def delete_file(self, file_id: str) -> bool:
        """Deletes file metadata and chunks from Firebase Vault."""
        doc_ref = self.db.collection(self.collection_name).document(file_id)
        doc = doc_ref.get()
        if not doc.exists:
            return False

        # Delete chunks subcollection if present
        chunks = doc_ref.collection("chunks").stream()
        for c in chunks:
            c.reference.delete()

        doc_ref.delete()
        return True

    def get_vault_status(self) -> Dict[str, Any]:
        """Returns health and cloud connectivity metrics."""
        files = self.list_files()
        total_orig_bytes = sum(f.get("original_size_bytes", 0) for f in files)
        total_enc_bytes = sum(f.get("encrypted_size_bytes", 0) for f in files)

        return {
            "status": "ONLINE",
            "tier": "Firebase Spark (100% Free Plan - No Credit Card)",
            "database": "Cloud Firestore",
            "collection": self.collection_name,
            "total_files": len(files),
            "total_original_bytes": total_orig_bytes,
            "total_encrypted_bytes": total_enc_bytes,
            "storage_allowance": "1 GB Free Tier"
        }
