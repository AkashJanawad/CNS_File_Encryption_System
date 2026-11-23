"""
CNS Authentication Manager
Handles User Authentication via Firebase Authentication and User Profile / RSA Key Management in Cloud Firestore.
"""

import os
import json
import requests
from typing import Dict, Any, Optional, Tuple

import firebase_admin
from firebase_admin import credentials, auth, firestore
from google.cloud.firestore import Client

import crypto_engine

FIREBASE_WEB_API_KEY = "AIzaSyC5aQnCybc4DsZ5lYL98uMHtetY__s8dxc"

class AuthManager:
    def __init__(self, key_path: str = "serviceAccountKey.json"):
        if not os.path.isabs(key_path):
            key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), key_path)

        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Firebase Service Account Key not found at {key_path}")

        if not firebase_admin._apps:
            cred = credentials.Certificate(key_path)
            firebase_admin.initialize_app(cred)

        self.db: Client = firestore.client()
        self.users_coll = "cns_users"

    def register_user(self, email: str, password: str) -> Dict[str, Any]:
        """
        1. Registers user in Firebase Authentication.
        2. Generates a unique RSA-2048 Keypair for this user.
        3. Stores user profile and keys in Firestore (cns_users collection).
        4. Logs user in and returns session tokens.
        """
        # Step 1: Sign up user via Firebase Auth REST API
        signup_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={FIREBASE_WEB_API_KEY}"
        resp = requests.post(signup_url, json={
            "email": email,
            "password": password,
            "returnSecureToken": True
        })

        data = resp.json()
        if resp.status_code != 200:
            error_msg = data.get("error", {}).get("message", "Registration failed")
            if "EMAIL_EXISTS" in error_msg:
                raise ValueError("This email is already registered. Please sign in instead.")
            elif "WEAK_PASSWORD" in error_msg:
                raise ValueError("Password is too weak. Please use at least 6 characters.")
            elif "INVALID_EMAIL" in error_msg:
                raise ValueError("Invalid email format.")
            else:
                raise ValueError(f"Registration error: {error_msg}")

        uid = data["localId"]
        id_token = data["idToken"]

        # Step 2: Generate personal RSA-2048 keypair for this specific user
        priv_pem, pub_pem = crypto_engine.generate_rsa_keypair(2048)

        # Step 3: Save user profile in Firestore
        user_doc = {
            "uid": uid,
            "email": email,
            "public_key": pub_pem,
            "private_key": priv_pem,
            "created_at": firestore.SERVER_TIMESTAMP
        }
        self.db.collection(self.users_coll).document(uid).set(user_doc)

        return {
            "uid": uid,
            "email": email,
            "id_token": id_token,
            "public_key": pub_pem,
            "private_key": priv_pem,
            "message": "User registered successfully with personalized RSA keys!"
        }

    def login_user(self, email: str, password: str) -> Dict[str, Any]:
        """
        1. Authenticates against Firebase Auth REST API.
        2. Retrieves user's profile and personalized RSA keys from Firestore.
        3. Returns user info, token, and keys.
        """
        login_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"
        resp = requests.post(login_url, json={
            "email": email,
            "password": password,
            "returnSecureToken": True
        })

        data = resp.json()
        if resp.status_code != 200:
            error_msg = data.get("error", {}).get("message", "Login failed")
            if "EMAIL_NOT_FOUND" in error_msg or "INVALID_PASSWORD" in error_msg or "INVALID_LOGIN_CREDENTIALS" in error_msg:
                raise ValueError("Invalid email or password.")
            elif "USER_DISABLED" in error_msg:
                raise ValueError("This user account has been disabled.")
            else:
                raise ValueError(f"Authentication error: {error_msg}")

        uid = data["localId"]
        id_token = data["idToken"]

        # Fetch user's RSA keys from Firestore
        doc = self.db.collection(self.users_coll).document(uid).get()
        if not doc.exists:
            # Generate and backfill keys if missing
            priv_pem, pub_pem = crypto_engine.generate_rsa_keypair(2048)
            self.db.collection(self.users_coll).document(uid).set({
                "uid": uid,
                "email": email,
                "public_key": pub_pem,
                "private_key": priv_pem,
                "created_at": firestore.SERVER_TIMESTAMP
            })
        else:
            user_data = doc.to_dict()
            priv_pem = user_data.get("private_key")
            pub_pem = user_data.get("public_key")

        return {
            "uid": uid,
            "email": email,
            "id_token": id_token,
            "public_key": pub_pem,
            "private_key": priv_pem
        }

    def verify_token(self, id_token: str) -> Dict[str, Any]:
        """
        Verifies Firebase ID token and returns decoded claims (uid, email).
        """
        try:
            decoded = auth.verify_id_token(id_token)
            return {
                "uid": decoded["uid"],
                "email": decoded.get("email", "")
            }
        except Exception as e:
            raise PermissionError(f"Invalid or expired authentication session: {e}")

    def get_user_keys(self, uid: str) -> Tuple[str, str]:
        """Returns (private_key_pem, public_key_pem) for a given user UID."""
        doc = self.db.collection(self.users_coll).document(uid).get()
        if not doc.exists:
            raise KeyError("User record not found.")
        data = doc.to_dict()
        return data.get("private_key", ""), data.get("public_key", "")
