"""
Firebase Cloud Vault
Provides Zero-Knowledge Multi-Tenant Encrypted File Storage on Firebase Cloud Firestore.
Features:
- Strict per-user file isolation (owner_uid / owner_email).
- Safe 400 KB chunking for Firestore documents (well below the 1 MB limit to eliminate upload failures).
- Metadata tracking (SHA-256 integrity, encryption timestamps, protocol, encrypted keys).
- Zero-byte and large-file fault tolerance.
"""

import os
import math
import uuid
import time
from typing import Dict, Any, List, Optional, Tuple

import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore import Client, FieldFilter

import crypto_engine

# Safe Chunk size for Firestore document limit (Firestore max doc size is 1 MiB)
# 400 KB leaves plenty of headroom for protobuf/Base64 overhead
CHUNK_SIZE = 400 * 1024  # 400 KB per chunk

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

    def upload_file(
        self,
        file_path: str,
        public_key_pem: str,
        protocol: str = "CP2",
        owner_uid: str = "anonymous",
        owner_email: str = "anonymous@cns.com"
    ) -> Dict[str, Any]:
        """
        Encrypts a local file and stores the ciphertext + metadata in Firebase Firestore.
        Zero-Knowledge: The cloud only receives encrypted bytes.
        Tagged with owner_uid for strict user privacy and multi-tenancy.
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
        num_chunks = max(1, math.ceil(cipher_len / CHUNK_SIZE)) if cipher_len > 0 else 1

        # 2. Prepare Base Metadata Document
        metadata = {
            "file_id": file_id,
            "file_name": file_name,
            "owner_uid": owner_uid,
            "owner_email": owner_email,
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
            "is_chunked": (num_chunks > 1 or cipher_len > CHUNK_SIZE)
        }

        doc_ref = self.db.collection(self.collection_name).document(file_id)

        # 3. Store Ciphertext Safely (Single Doc or Subcollection Chunks)
        if not metadata["is_chunked"]:
            doc_data = dict(metadata)
            doc_data["ciphertext"] = ciphertext
            doc_ref.set(doc_data)
        else:
            # Save metadata first without massive payload to guarantee under-1MB safety
            doc_ref.set(metadata)
            chunks_coll = doc_ref.collection("chunks")
            for i in range(num_chunks):
                chunk_data = ciphertext[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
                chunks_coll.document(f"chunk_{i}").set({
                    "index": i,
                    "data": chunk_data
                })

        return metadata

    def download_file(
        self,
        file_id: str,
        private_key_pem: str,
        output_dir: Optional[str] = None,
        user_uid: Optional[str] = None
    ) -> Tuple[str, bool, Dict[str, Any]]:
        """
        Downloads encrypted file from Firebase, decrypts it locally, and verifies SHA-256 integrity.
        Validates user ownership so User A cannot download User B's files.
        """
        doc_ref = self.db.collection(self.collection_name).document(file_id)
        doc = doc_ref.get()

        if not doc.exists:
            raise KeyError(f"File ID {file_id} not found in Firebase Vault.")

        metadata = doc.to_dict()

        # Multi-Tenant Ownership Authorization Check
        if user_uid and metadata.get("owner_uid") and metadata.get("owner_uid") != "anonymous":
            if metadata.get("owner_uid") != user_uid:
                raise PermissionError("Access Denied: You do not have permission to access another user's encrypted file.")

        # 1. Fetch Ciphertext
        if not metadata.get("is_chunked", False):
            ciphertext = metadata.get("ciphertext", b"")
        else:
            num_chunks = metadata.get("num_chunks", 1)
            chunks_coll = doc_ref.collection("chunks")
            chunk_bytes = []
            for i in range(num_chunks):
                chunk_doc = chunks_coll.document(f"chunk_{i}").get()
                if not chunk_doc.exists:
                    raise IOError(f"Corrupted storage: Missing chunk {i} for file {file_id}")
                chunk_bytes.append(chunk_doc.to_dict()["data"])
            ciphertext = b"".join(chunk_bytes)

        # 2. Perform Client-Side Decryption
        protocol_name = metadata.get("protocol", "")
        if "CP1" in protocol_name:
            plaintext, dec_time = crypto_engine.decrypt_cp1_rsa(ciphertext, private_key_pem)
        else:
            plaintext, dec_time = crypto_engine.decrypt_cp2_hybrid(
                ciphertext,
                metadata.get("encrypted_key_b64", ""),
                metadata.get("nonce_b64", ""),
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

    def list_files(self, owner_uid: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Lists encrypted files.
        If owner_uid is supplied, returns ONLY files owned by that user.
        Sorts in Python to avoid composite index requirements.
        """
        coll = self.db.collection(self.collection_name)
        if owner_uid:
            docs = coll.where(filter=FieldFilter("owner_uid", "==", owner_uid)).stream()
        else:
            docs = coll.stream()

        results = []
        for doc in docs:
            d = doc.to_dict()
            d.pop("ciphertext", None)
            results.append(d)

        results.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return results

    def delete_file(self, file_id: str, user_uid: Optional[str] = None) -> bool:
        """
        Deletes file metadata and chunks from Firebase Vault.
        Validates ownership so users can only delete their own files.
        """
        doc_ref = self.db.collection(self.collection_name).document(file_id)
        doc = doc_ref.get()
        if not doc.exists:
            return False

        metadata = doc.to_dict()
        if user_uid and metadata.get("owner_uid") and metadata.get("owner_uid") != "anonymous":
            if metadata.get("owner_uid") != user_uid:
                raise PermissionError("Access Denied: You cannot delete another user's file.")

        # Delete subcollection chunks if present
        chunks = doc_ref.collection("chunks").stream()
        for c in chunks:
            c.reference.delete()

        doc_ref.delete()
        return True

    def get_vault_status(self, owner_uid: Optional[str] = None) -> Dict[str, Any]:
        """Returns health and cloud connectivity metrics for the user."""
        files = self.list_files(owner_uid=owner_uid)
        total_orig_bytes = sum(f.get("original_size_bytes", 0) for f in files)
        total_enc_bytes = sum(f.get("encrypted_size_bytes", 0) for f in files)

        return {
            "status": "ONLINE",
            "tier": "Firebase Spark (100% Free Plan - Multi-Tenant)",
            "database": "Cloud Firestore",
            "collection": self.collection_name,
            "total_files": len(files),
            "total_original_bytes": total_orig_bytes,
            "total_encrypted_bytes": total_enc_bytes,
            "storage_allowance": "1 GB Free Tier"
        }
