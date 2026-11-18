"""
CNS File Encryption System - CLI
Command Line Interface for managing End-to-End Zero-Knowledge Encrypted Files on Firebase.
"""

import os
import sys
import argparse
import crypto_engine
from firebase_vault import FirebaseCloudVault

KEY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
DEFAULT_PRIV_KEY = os.path.join(KEY_DIR, "private_key.pem")
DEFAULT_PUB_KEY = os.path.join(KEY_DIR, "public_key.pem")

def ensure_keys():
    os.makedirs(KEY_DIR, exist_ok=True)
    if not os.path.exists(DEFAULT_PRIV_KEY) or not os.path.exists(DEFAULT_PUB_KEY):
        print("[*] Generating new default RSA-2048 Key Pair...")
        priv, pub = crypto_engine.generate_rsa_keypair(2048)
        with open(DEFAULT_PRIV_KEY, "w") as f:
            f.write(priv)
        with open(DEFAULT_PUB_KEY, "w") as f:
            f.write(pub)
        print(f"[+] Saved Private Key to: {DEFAULT_PRIV_KEY}")
        print(f"[+] Saved Public Key to:  {DEFAULT_PUB_KEY}")
    with open(DEFAULT_PRIV_KEY, "r") as f:
        priv = f.read()
    with open(DEFAULT_PUB_KEY, "r") as f:
        pub = f.read()
    return priv, pub

def cmd_genkeys(args):
    priv, pub = crypto_engine.generate_rsa_keypair(2048)
    os.makedirs(KEY_DIR, exist_ok=True)
    out_priv = args.private if args.private else DEFAULT_PRIV_KEY
    out_pub = args.public if args.public else DEFAULT_PUB_KEY
    with open(out_priv, "w") as f:
        f.write(priv)
    with open(out_pub, "w") as f:
        f.write(pub)
    print(f"[+] Successfully generated RSA-2048 Keypair!")
    print(f"    Private Key: {out_priv}")
    print(f"    Public Key:  {out_pub}")

def cmd_upload(args):
    priv, pub = ensure_keys()
    vault = FirebaseCloudVault()
    print(f"[*] Encrypting and uploading '{args.file}' using {args.protocol}...")
    meta = vault.upload_file(args.file, pub, protocol=args.protocol)
    print("\n[+] File successfully encrypted and uploaded to Firebase Vault!")
    print(f"    File ID:         {meta['file_id']}")
    print(f"    File Name:       {meta['file_name']}")
    print(f"    Original Size:   {meta['original_size_bytes']} bytes")
    print(f"    Encrypted Size:  {meta['encrypted_size_bytes']} bytes")
    print(f"    Protocol:        {meta['protocol']}")
    print(f"    SHA-256 Digest:  {meta['sha256']}")
    print(f"    Encryption Time: {meta['encrypt_time_ms']} ms")

def cmd_download(args):
    priv, pub = ensure_keys()
    vault = FirebaseCloudVault()
    print(f"[*] Fetching and decrypting File ID: {args.file_id}...")
    saved_path, verified, meta = vault.download_file(args.file_id, priv, output_dir=args.output_dir)
    print("\n[+] Download & Decryption complete!")
    print(f"    Saved to:           {saved_path}")
    print(f"    Integrity Verified: {verified} {'(MATCH)' if verified else '(CORRUPTED)'}")
    print(f"    SHA-256 Digest:     {meta.get('sha256')}")
    print(f"    Decryption Time:    {meta.get('decrypt_time_ms')} ms")

def cmd_list(args):
    vault = FirebaseCloudVault()
    files = vault.list_files()
    print(f"\n=== Firebase Encrypted Cloud Vault ({len(files)} files) ===")
    if not files:
        print("  Vault is currently empty.")
        return

    print(f"{'FILE ID':<38} | {'FILE NAME':<20} | {'ORIG SIZE':<10} | {'PROTOCOL':<30} | {'UPLOADED AT'}")
    print("-" * 125)
    for f in files:
        print(f"{f['file_id']:<38} | {f['file_name']:<20} | {f.get('original_size_bytes', 0):<10} | {f.get('protocol', ''):<30} | {f.get('uploaded_at', '')}")

def cmd_delete(args):
    vault = FirebaseCloudVault()
    success = vault.delete_file(args.file_id)
    if success:
        print(f"[+] Deleted file ID: {args.file_id}")
    else:
        print(f"[-] File ID not found: {args.file_id}")

def cmd_benchmark(args):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    test_files = [
        os.path.join(base_dir, "NSProgrammingAssignment2", "smallFile.txt"),
        os.path.join(base_dir, "NSProgrammingAssignment2", "medianFile.txt"),
        os.path.join(base_dir, "NSProgrammingAssignment2", "largeFile.txt")
    ]

    print("\n" + "=" * 80)
    print("      CNS Cryptographic Benchmark: Protocol 1 (RSA) vs Protocol 2 (AES)")
    print("=" * 80)

    for tf in test_files:
        if not os.path.exists(tf):
            continue
        with open(tf, "rb") as f:
            data = f.read()

        fname = os.path.basename(tf)
        print(f"\n[*] Benchmarking on {fname} ({len(data):,} bytes / {len(data)/1024:.1f} KB):")
        result = crypto_engine.run_crypto_benchmark(data, fname)

        # CP2 Results
        cp2 = result["cp2_hybrid"]
        print(f"  ├── [CP2 Hybrid AES-GCM + RSA]:")
        print(f"  │   ├── Encryption Time: {cp2['encrypt_time_ms']} ms")
        print(f"  │   ├── Decryption Time: {cp2['decrypt_time_ms']} ms")
        print(f"  │   └── Total Time:      {cp2['total_time_ms']} ms (Integrity: {'OK' if cp2['verified'] else 'FAILED'})")

        # CP1 Results
        cp1 = result["cp1_rsa"]
        if cp1.get("skipped"):
            print(f"  └── [CP1 Pure RSA Chunked]: SKIPPED ({cp1['reason']})")
        else:
            print(f"  └── [CP1 Pure RSA Chunked]:")
            print(f"      ├── Encryption Time: {cp1['encrypt_time_ms']} ms")
            print(f"      ├── Decryption Time: {cp1['decrypt_time_ms']} ms")
            print(f"      └── Total Time:      {cp1['total_time_ms']} ms (Integrity: {'OK' if cp1['verified'] else 'FAILED'})")
            speedup = cp1['total_time_ms'] / max(cp2['total_time_ms'], 0.001)
            print(f"      ★ Speedup of AES-Hybrid over Pure RSA: {speedup:.1f}x FASTER!")

    print("\n" + "=" * 80)

def main():
    parser = argparse.ArgumentParser(description="CNS File Encryption System CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # genkeys
    p_gen = subparsers.add_parser("genkeys", help="Generate RSA-2048 key pair")
    p_gen.add_argument("--private", help="Private key output path")
    p_gen.add_argument("--public", help="Public key output path")

    # upload
    p_up = subparsers.add_parser("upload", help="Encrypt and upload file to Firebase")
    p_up.add_argument("file", help="Path to file to upload")
    p_up.add_argument("--protocol", choices=["CP1", "CP2"], default="CP2", help="Protocol: CP1 (Pure RSA) or CP2 (Hybrid AES+RSA)")

    # download
    p_down = subparsers.add_parser("download", help="Download and decrypt file from Firebase")
    p_down.add_argument("file_id", help="UUID of file to download")
    p_down.add_argument("--output-dir", help="Directory to save decrypted file")

    # list
    subparsers.add_parser("list", help="List all encrypted files in Firebase Vault")

    # delete
    p_del = subparsers.add_parser("delete", help="Delete file from Firebase Vault")
    p_del.add_argument("file_id", help="UUID of file to delete")

    # benchmark
    subparsers.add_parser("benchmark", help="Run CP1 vs CP2 performance benchmark")

    args = parser.parse_args()

    if args.command == "genkeys":
        cmd_genkeys(args)
    elif args.command == "upload":
        cmd_upload(args)
    elif args.command == "download":
        cmd_download(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "delete":
        cmd_delete(args)
    elif args.command == "benchmark":
        cmd_benchmark(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
