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

    # -----------------------------------------------------------------------
    # Multi-Recipient Secure Sharing & Transfer Methods
    # -----------------------------------------------------------------------

    def share_file(
        self,
        file_id: str,
        sender_uid: str,
        sender_email: str,
        recipient_uid: str,
        recipient_email: str,
        recipient_public_key_pem: str,
        sender_private_key_pem: str
    ) -> Dict[str, Any]:
        """
        Securely shares an encrypted file with a recipient using Asymmetric Envelope Re-Encryption.
        - Verifies sender owns the file.
        - Re-encrypts the AES-256 key with Recipient's RSA-2048 Public Key.
        - The ciphertext payload stays in Cloud Firestore; no plain data ever touches the network.
        - Only the recipient's private key can decrypt this transfer.
        """
        if sender_uid == recipient_uid:
            raise ValueError("You cannot share a file with yourself.")

        doc_ref = self.db.collection(self.collection_name).document(file_id)
        doc = doc_ref.get()
        if not doc.exists:
            raise KeyError(f"File ID {file_id} not found.")

        file_data = doc.to_dict()
        if file_data.get("owner_uid") and file_data.get("owner_uid") != sender_uid:
            raise PermissionError("Access Denied: You can only share files that you own.")

        protocol = file_data.get("protocol", "CP2")
        transfer_id = str(uuid.uuid4())

        # Perform Re-Encryption
        if "CP1" in protocol:
            if not file_data.get("is_chunked", False):
                ciphertext = file_data.get("ciphertext", b"")
            else:
                num_chunks = file_data.get("num_chunks", 1)
                chunk_bytes = []
                for i in range(num_chunks):
                    chunk_doc = doc_ref.collection("chunks").document(f"chunk_{i}").get()
                    chunk_bytes.append(chunk_doc.to_dict()["data"])
                ciphertext = b"".join(chunk_bytes)
            recip_cipher = crypto_engine.reencrypt_cp1_payload(ciphertext, sender_private_key_pem, recipient_public_key_pem)
            recipient_enc_key = ""
        else:
            # CP2: Envelope Re-encryption (Fast, Zero-overhead)
            orig_enc_key = file_data.get("encrypted_key_b64", "")
            recipient_enc_key = crypto_engine.reencrypt_envelope_key(
                orig_enc_key,
                sender_private_key_pem,
                recipient_public_key_pem
            )

        transfer_doc = {
            "transfer_id": transfer_id,
            "file_id": file_id,
            "file_name": file_data.get("file_name", "shared_file"),
            "sender_uid": sender_uid,
            "sender_email": sender_email,
            "recipient_uid": recipient_uid,
            "recipient_email": recipient_email,
            "protocol": protocol,
            "original_size_bytes": file_data.get("original_size_bytes", 0),
            "encrypted_size_bytes": file_data.get("encrypted_size_bytes", 0),
            "sha256": file_data.get("sha256", ""),
            "nonce_b64": file_data.get("nonce_b64", ""),
            "encrypted_key_b64": recipient_enc_key,
            "shared_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "timestamp": time.time(),
            "status": "ACTIVE"
        }

        # Store transfer in cns_shared_transfers
        self.db.collection("cns_shared_transfers").document(transfer_id).set(transfer_doc)
        return transfer_doc

    def list_incoming_transfers(self, recipient_uid: str) -> List[Dict[str, Any]]:
        """Lists all active files shared with this recipient."""
        coll = self.db.collection("cns_shared_transfers")
        docs = coll.where(filter=FieldFilter("recipient_uid", "==", recipient_uid)).stream()
        results = []
        for doc in docs:
            d = doc.to_dict()
            if d.get("status") == "ACTIVE":
                results.append(d)
        results.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return results

    def list_outgoing_transfers(self, sender_uid: str) -> List[Dict[str, Any]]:
        """Lists all files this user has shared with other recipients."""
        coll = self.db.collection("cns_shared_transfers")
        docs = coll.where(filter=FieldFilter("sender_uid", "==", sender_uid)).stream()
        results = [doc.to_dict() for doc in docs]
        results.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        return results

    def revoke_transfer(self, transfer_id: str, sender_uid: str) -> bool:
        """Revokes a shared transfer (only by the sender)."""
        doc_ref = self.db.collection("cns_shared_transfers").document(transfer_id)
        doc = doc_ref.get()
        if not doc.exists:
            return False
        d = doc.to_dict()
        if d.get("sender_uid") != sender_uid:
            raise PermissionError("Access Denied: You can only revoke your own shared transfers.")
        doc_ref.delete()
        return True

    def download_shared_file(
        self,
        transfer_id: str,
        recipient_uid: str,
        recipient_private_key_pem: str,
        output_dir: Optional[str] = None
    ) -> Tuple[str, bool, Dict[str, Any]]:
        """
        Decrypts and downloads a shared file using the Recipient's Private Key.
        Strict verification:
        - Recipient UID must match.
        - Status must be ACTIVE.
        - RSA decryption succeeds only if recipient's private key matches.
        """
        trans_ref = self.db.collection("cns_shared_transfers").document(transfer_id)
        trans_doc = trans_ref.get()
        if not trans_doc.exists:
            raise KeyError(f"Shared transfer {transfer_id} not found or was revoked.")

        transfer = trans_doc.to_dict()
        if transfer.get("status") != "ACTIVE":
            raise PermissionError("This transfer has been revoked by the sender.")

        if transfer.get("recipient_uid") != recipient_uid:
            raise PermissionError("Access Denied: You are not the authorized recipient of this transfer.")

        file_id = transfer["file_id"]
        doc_ref = self.db.collection(self.collection_name).document(file_id)
        doc = doc_ref.get()
        if not doc.exists:
            raise KeyError("Original file has been removed by the owner.")

        file_data = doc.to_dict()

        # 1. Fetch ciphertext bytes
        if not file_data.get("is_chunked", False):
            ciphertext = file_data.get("ciphertext", b"")
        else:
            num_chunks = file_data.get("num_chunks", 1)
            chunk_bytes = []
            for i in range(num_chunks):
                chunk_doc = doc_ref.collection("chunks").document(f"chunk_{i}").get()
                if not chunk_doc.exists:
                    raise IOError(f"Missing chunk {i} for file {file_id}")
                chunk_bytes.append(chunk_doc.to_dict()["data"])
            ciphertext = b"".join(chunk_bytes)

        # 2. Decrypt with Recipient's Private Key
        protocol = transfer.get("protocol", "CP2")
        if "CP1" in protocol:
            plaintext, dec_time = crypto_engine.decrypt_cp1_rsa(ciphertext, recipient_private_key_pem)
        else:
            plaintext, dec_time = crypto_engine.decrypt_cp2_hybrid(
                ciphertext,
                transfer.get("encrypted_key_b64", ""),
                transfer.get("nonce_b64", ""),
                recipient_private_key_pem
            )

        transfer["decrypt_time_ms"] = dec_time

        # 3. Verify SHA-256 integrity
        computed_hash = crypto_engine.compute_sha256(plaintext)
        integrity_ok = (computed_hash == transfer.get("sha256"))

        # 4. Save to Disk
        if not output_dir:
            output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "decrypted_files")
        os.makedirs(output_dir, exist_ok=True)

        output_path = os.path.join(output_dir, transfer["file_name"])
        with open(output_path, "wb") as f:
            f.write(plaintext)

        return output_path, integrity_ok, transfer

