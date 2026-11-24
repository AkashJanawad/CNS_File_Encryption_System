"""
CNS Authentication Manager
Handles User Authentication via Firebase Authentication and User Profile / RSA Key Management in Cloud Firestore.
"""

import os
import json
import requests
from typing import Dict, Any, Optional, Tuple, List

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

    def get_or_create_user_profile(self, uid: str, email: str) -> Tuple[str, str]:
        """
        Retrieves user's RSA keys from Firestore, or generates and saves them if first time (e.g. Google Sign-In).
        Returns (private_key_pem, public_key_pem).
        """
        doc = self.db.collection(self.users_coll).document(uid).get()
        if not doc.exists:
            priv_pem, pub_pem = crypto_engine.generate_rsa_keypair(2048)
            self.db.collection(self.users_coll).document(uid).set({
                "uid": uid,
                "email": email,
                "public_key": pub_pem,
                "private_key": priv_pem,
                "created_at": firestore.SERVER_TIMESTAMP,
                "provider": "google"
            })
            return priv_pem, pub_pem
        else:
            user_data = doc.to_dict()
            return user_data.get("private_key", ""), user_data.get("public_key", "")

    def get_all_registered_users(self, exclude_uid: Optional[str] = None) -> List[Dict[str, str]]:
        """
        Retrieves all registered users across Firebase Auth and Firestore.
        Ensures public keys are available for cryptographic envelope re-encryption.
        """
        users_map: Dict[str, Dict[str, Any]] = {}

        # 1. Gather all users registered in Firestore cns_users
        for doc in self.db.collection(self.users_coll).stream():
            d = doc.to_dict()
            if d.get("uid"):
                users_map[d["uid"]] = d

        # 2. Check Firebase Auth to discover all accounts (e.g. direct auth users)
        try:
            page = auth.list_users()
            for u in page.users:
                if u.uid not in users_map and u.email:
                    priv, pub = crypto_engine.generate_rsa_keypair(2048)
                    profile = {
                        "uid": u.uid,
                        "email": u.email,
                        "public_key": pub,
                        "private_key": priv,
                        "provider": "firebase_auth"
                    }
                    self.db.collection(self.users_coll).document(u.uid).set(profile)
                    users_map[u.uid] = profile
        except Exception as e:
            print(f"Warning syncing Auth users: {e}")

        # 3. Return clean list of candidates (excluding requesting user)
        result = []
        for uid, data in users_map.items():
            if exclude_uid and uid == exclude_uid:
                continue
            email = data.get("email")
            if email:
                result.append({
                    "uid": uid,
                    "email": email,
                    "public_key": data.get("public_key", "")
                })

        result.sort(key=lambda x: x["email"].lower())
        return result

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Finds user by email and returns their profile with public key."""
        clean_email = email.strip().lower()
        query = self.db.collection(self.users_coll).where("email", "==", clean_email).limit(1).stream()
        for doc in query:
            return doc.to_dict()

        # Check Firebase Auth directly
        try:
            u = auth.get_user_by_email(clean_email)
            if u:
                priv, pub = crypto_engine.generate_rsa_keypair(2048)
                profile = {
                    "uid": u.uid,
                    "email": u.email,
                    "public_key": pub,
                    "private_key": priv,
                    "provider": "firebase_auth"
                }
                self.db.collection(self.users_coll).document(u.uid).set(profile)
                return profile
        except Exception:
            pass

        return None

