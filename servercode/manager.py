import os
import asyncio
import base64
import secrets
import string
import time
from typing import Optional

from fastapi import HTTPException
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
import pyotp

from database import DatabaseConnector

class DynamicPasswordManager:
    def __init__(self, username: str):
        self.username = username
        self.db = DatabaseConnector()
        self.ph = PasswordHasher(
            time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, salt_len=16
        )
        self.fer = None

    # ───────────────────────────── account setup ───────────────────────────
    async def create_key(self, master_password: str):
        return self.ph.hash(master_password)

    async def create_account(self, master_password: str, recovery_pin: str):
        hash_value = await self.create_key(master_password)
        pin_hash = self.ph.hash(recovery_pin)
        await self.db.execute_with_retry(
            "INSERT INTO users (uname, pass, secret_pin, salt_phrase) "
            "VALUES (?, ?, ?, '')",
            [self.username, hash_value, pin_hash],
        )
        salt = os.urandom(16)
        await self.db.execute_with_retry(
            "UPDATE users SET salt_phrase = ? WHERE uname = ?",
            [salt.hex(), self.username],
        )
        kdf = hash_secret_raw(
            secret=master_password.encode(),
            salt=salt,
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            type=Type.ID,
        )
        self.fer = Fernet(base64.urlsafe_b64encode(kdf))

    # ────────────────────────────── auth flow ──────────────────────────────
    async def verify_master_password(
        self,
        master_password: str,
        totp_code: Optional[str] = None,
        recovery_pin: Optional[str] = None,
    ) -> bool:
        lo = await self.db.get_lockout_data(self.username)
        now = int(time.time())

        # A) if PIN already verified, skip lock-out checks
        if not lo["pin_verified"]:
            if now < lo["lockout_until"]:
                rem = lo["lockout_until"] - now
                raise HTTPException(403, f"User locked out. Try again in {rem}s")

        # B) verify stored hash
        stored = await self.db.get_user_password(self.username)
        if not stored:
            await self.inc_login_failure()
            raise HTTPException(401, "Invalid credentials.")

        try:
            self.ph.verify(stored, master_password)
        except VerifyMismatchError:
            fa = lo["failed_attempts"] + 1
            if lo["pin_verified"] or fa <= 5:
                await self.db.set_lockout_data(
                    self.username, fa, lo["lockout_until"], lo["pin_verified"]
                )
                raise HTTPException(401, "Invalid credentials.")
            # 6th wrong attempt → full lock-out (15 min) unless recovery PIN used
            if not recovery_pin:
                await self.db.set_lockout_data(
                    self.username, fa, now + 900, lo["pin_verified"]
                )
                raise HTTPException(
                    403,
                    "Too many failed attempts. Account locked for 15 minutes "
                    "or provide your recovery PIN.",
                )
            stored_pin = await self.db.get_recovery_pin(self.username)
            try:
                self.ph.verify(stored_pin, recovery_pin)
            except VerifyMismatchError:
                await self.db.set_lockout_data(
                    self.username, fa, now + 900, lo["pin_verified"]
                )
                raise HTTPException(403, "Invalid recovery PIN.")

        # C) optional TOTP
        totp_secret = await self.db.get_totp_secret(self.username)
        if totp_secret and (
            not totp_code or not pyotp.TOTP(totp_secret).verify(totp_code)
        ):
            raise HTTPException(403, "Invalid or missing TOTP code.")

        # D) success → reset lock-out & derive Fernet key
        await self.db.reset_lockout_data(self.username)
        salt_hex = (
            await self.db.execute_with_retry(
                "SELECT salt_phrase FROM users WHERE uname = ?", [self.username]
            )
        ).rows[0][0]
        kdf = hash_secret_raw(
            secret=master_password.encode(),
            salt=bytes.fromhex(salt_hex),
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            type=Type.ID,
        )
        self.fer = Fernet(base64.urlsafe_b64encode(kdf))
        return True

    async def inc_login_failure(self):
        lo = await self.db.get_lockout_data(self.username)
        await self.db.set_lockout_data(
            self.username, lo["failed_attempts"] + 1, lo["lockout_until"], lo["pin_verified"]
        )

    # ────────────────────────────── TOTP setup ─────────────────────────────
    async def enable_totp(self):
        secret = secrets.token_hex(10)
        await self.db.set_totp_secret(self.username, secret)
        return secret

    async def disable_totp(self):
        await self.db.delete_totp_secret(self.username)
        return {"message": "TOTP disabled."}

    # ────────────────────────── secure site vault ──────────────────────────
    async def add_site(
        self,
        site_name: str,
        site_username: str,
        site_password: str,
        master_password: str,
        pin: str,
    ):
        await self.verify_master_password(master_password, recovery_pin=pin)
        enc_u = self.fer.encrypt(site_username.encode())
        enc_p = self.fer.encrypt(site_password.encode())
        await self.db.store_site(self.username, site_name, enc_u, enc_p)
        return {"message": "Site credentials added."}

    async def get_site(
        self,
        site_name: str,
        master_password: str,
        pin: str,
    ):
        await self.verify_master_password(master_password, recovery_pin=pin)
        creds = await self.db.get_site_credentials(self.username, site_name)
        if not creds:
            raise HTTPException(404, "Site not found")
        username, password = (self.fer.decrypt(c).decode() for c in creds)
        return {"username": username, "password": password}

    async def get_all_sites(self, master_password: str, pin: str):
        await self.verify_master_password(master_password, recovery_pin=pin)
        return await self.db.get_all_sites(self.username)

    async def delete_site(self, site_name: str, pin: str):
        await self.db.delete_site(self.username, site_name)
        return {"message": "Site deleted successfully."}

    # ───────────────────────────── wallets vault ───────────────────────────
    async def add_wallet(
        self,
        wallet_name: str,
        wallet_username: str,
        wallet_password: str,
        recovery_phrase: str,
        master_password: str,
        pin: str,
    ):
        await self.verify_master_password(master_password, recovery_pin=pin)
        enc_u = self.fer.encrypt(wallet_username.encode())
        enc_p = self.fer.encrypt(wallet_password.encode())
        enc_r = self.fer.encrypt(recovery_phrase.encode())
        await self.db.store_wallet(self.username, wallet_name, enc_u, enc_p, enc_r)
        return {"message": "Wallet added."}

    async def get_wallet(
        self,
        wallet_name: str,
        master_password: str,
        pin: str,
    ):
        await self.verify_master_password(master_password, recovery_pin=pin)
        cred = await self.db.get_wallet(self.username, wallet_name)
        if not cred:
            raise HTTPException(404, "Wallet not found")
        u, p, r = (self.fer.decrypt(c).decode() for c in cred)
        return {"username": u, "password": p, "recovery_phrase": r}

    async def get_all_wallets(self, master_password: str, pin: str):
        await self.verify_master_password(master_password, recovery_pin=pin)
        return await self.db.get_all_wallets(self.username)

    async def delete_wallet(self, wallet_name: str, pin: str):
        await self.db.delete_wallet(self.username, wallet_name)
        return {"message": "Wallet deleted successfully."}

    # ─────────────────────────── secure documents ──────────────────────────
    async def add_secure_doc(
        self,
        doc_name: str,
        contents: str,
        master_password: str,
        pin: str,
    ):
        await self.verify_master_password(master_password, recovery_pin=pin)
        enc = self.fer.encrypt(contents.encode())
        await self.db.store_doc(self.username, doc_name, enc)
        return {"message": "Document stored."}

    async def get_secure_doc(
        self,
        doc_name: str,
        master_password: str,
        pin: str,
    ):
        await self.verify_master_password(master_password, recovery_pin=pin)
        doc = await self.db.get_doc(self.username, doc_name)
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
        name, enc = doc
        contents = self.fer.decrypt(enc).decode()
        return {"doc_name": name, "contents": contents}

    async def get_all_secure_docs(self, master_password: str, pin: str):
        await self.verify_master_password(master_password, recovery_pin=pin)
        return await self.db.get_all_docs(self.username)

    async def update_secure_doc(
        self,
        doc_name: str,
        new_contents: str,
        master_password: str,
        pin: str,
    ):
        await self.verify_master_password(master_password, recovery_pin=pin)
        enc = self.fer.encrypt(new_contents.encode())
        await self.db.update_doc(self.username, doc_name, enc)
        return {"message": "Document updated."}

    async def delete_secure_doc(self, doc_name: str, pin: str):
        await self.db.delete_doc(self.username, doc_name)
        return {"message": "Document deleted successfully."}
