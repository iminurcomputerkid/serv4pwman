import os
import asyncio
import base64
import secrets
import string
import time
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
import pyotp
import pyqrcode
from aiohttp import ClientError
from libsql_client import create_client

load_dotenv()

# ----- Database Connector -----
class DatabaseConnector:
    def __init__(self):
        db_url = os.getenv('TURSO_DATABASE_URL', '').replace('libsql://', 'https://')
        self.client = create_client(
            url=db_url,
            auth_token=os.getenv('TURSO_AUTH_TOKEN')
        )

    async def execute_with_retry(self, query, params=None, max_retries=3):
        for attempt in range(max_retries):
            try:
                return await self.client.execute(query, params)
            except ClientError:
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(1 * (attempt + 1))

    async def get_lockout_data(self, username):
        result = await self.execute_with_retry(
            "SELECT failed_attempts, lockout_until FROM users WHERE uname = ?", [username]
        )
        if result.rows:
            failed, until = result.rows[0]
            return {'failed_attempts': failed, 'lockout_until': until}
        return {'failed_attempts': 0, 'lockout_until': 0}

    async def set_lockout_data(self, username, failed_attempts, lockout_until):
        await self.execute_with_retry(
            "UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE uname = ?",
            [failed_attempts, lockout_until, username]
        )

    async def reset_lockout_data(self, username):
        await self.execute_with_retry(
            "UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE uname = ?",
            [username]
        )

    async def get_totp_secret(self, username):
        result = await self.execute_with_retry(
            "SELECT totp_secret FROM users WHERE uname = ?", [username]
        )
        return result.rows[0][0] if result.rows and result.rows[0][0] else ""

    async def set_totp_secret(self, username, totp_secret):
        await self.execute_with_retry(
            "UPDATE users SET totp_secret = ? WHERE uname = ?", [totp_secret, username]
        )

    async def delete_totp_secret(self, username):
        await self.execute_with_retry(
            "UPDATE users SET totp_secret = '' WHERE uname = ?", [username]
        )

    async def store_site(self, username, site_name, encrypted_username, encrypted_password):
        await self.execute_with_retry(
            "INSERT INTO site (uname, site_name, username, passw) VALUES (?, ?, ?, ?)",
            [username, site_name, encrypted_username, encrypted_password]
        )

    async def get_site_credentials(self, username, site_name):
        result = await self.execute_with_retry(
            "SELECT username, passw FROM site WHERE uname = ? AND site_name = ?",
            [username, site_name]
        )
        return result.rows[0] if result.rows else None

    async def get_all_sites(self, username):
        result = await self.execute_with_retry(
            "SELECT site_name FROM site WHERE uname = ?", [username]
        )
        return [row[0] for row in result.rows]

    async def delete_site(self, username, site_name):
        await self.execute_with_retry(
            "DELETE FROM site WHERE uname = ? AND site_name = ?",
            [username, site_name]
        )

    async def store_wallet(self, username, wallet_name, encrypted_username, encrypted_password, encrypted_recovery):
        await self.execute_with_retry(
            "INSERT INTO wallets (uname, wallet_name, username, passw, recover_phrase) VALUES (?, ?, ?, ?, ?)",
            [username, wallet_name, encrypted_username, encrypted_password, encrypted_recovery]
        )

    async def get_wallet(self, username, wallet_name):
        result = await self.execute_with_retry(
            "SELECT username, passw, recover_phrase FROM wallets WHERE uname = ? AND wallet_name = ?",
            [username, wallet_name]
        )
        return result.rows[0] if result.rows else None
    
    async def get_recovery_pin(self, username: str) -> Optional[str]:
        result = await self.execute_with_retry(
            "SELECT secret_pin FROM users WHERE uname = ?",
            [username]
        )
        return result.rows[0][0] if result.rows else None

    async def get_all_wallets(self, username):
        result = await self.execute_with_retry(
            "SELECT wallet_name FROM wallets WHERE uname = ?", [username]
        )
        return [row[0] for row in result.rows]

    async def delete_wallet(self, username, wallet_name):
        await self.execute_with_retry(
            "DELETE FROM wallets WHERE uname = ? AND wallet_name = ?",
            [username, wallet_name]
        )

    async def delete_user_data(self, username):
        await self.execute_with_retry("DELETE FROM site WHERE uname = ?", [username])
        await self.execute_with_retry("DELETE FROM wallets WHERE uname = ?", [username])
        await self.execute_with_retry("DELETE FROM secure_docs WHERE uname = ?", [username])

    async def store_doc(self, username, doc_name, encrypted_contents):
        await self.execute_with_retry(
            "INSERT INTO secure_docs (uname, doc_name, doc_contents) VALUES (?, ?, ?)",
            [username, doc_name, encrypted_contents]
        )

    async def get_doc(self, username, doc_name):
        result = await self.execute_with_retry(
            "SELECT doc_name, doc_contents FROM secure_docs WHERE uname = ? AND doc_name = ?",
            [username, doc_name]
        )
        return (result.rows[0][0], result.rows[0][1]) if result.rows else None

    async def get_all_docs(self, username):
        result = await self.execute_with_retry(
            "SELECT doc_name FROM secure_docs WHERE uname = ?", [username]
        )
        return [row[0] for row in result.rows]

    async def update_doc(self, username, doc_name, new_contents):
        await self.execute_with_retry(
            "UPDATE secure_docs SET doc_contents = ? WHERE uname = ? AND doc_name = ?",
            [new_contents, username, doc_name]
        )

    async def delete_doc(self, username, doc_name):
        await self.execute_with_retry(
            "DELETE FROM secure_docs WHERE uname = ? AND doc_name = ?",
            [username, doc_name]
        )

    async def close(self):
        await self.client.close()


# ----- Dynamic Password Manager -----
class DynamicPasswordManager:
    def __init__(self, username: str):
        self.username = username
        self.db = DatabaseConnector()
        self.ph = PasswordHasher(
            time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, salt_len=16
        )
        self.fer = None

    async def create_key(self, master_password: str):
        return self.ph.hash(master_password)

    async def create_account(self, master_password: str, recovery_pin: str):
        hash_value = await self.create_key(master_password)
        pin_hash = self.ph.hash(recovery_pin)
        await self.db.execute_with_retry(
            "INSERT INTO users (uname, pass, secret_pin, salt_phrase) VALUES (?, ?, ?, '')",
            [self.username, hash_value, pin_hash]
        )
        salt = os.urandom(16)
        await self.db.execute_with_retry(
            "UPDATE users SET salt_phrase = ? WHERE uname = ?",
            [salt.hex(), self.username]
        )
        kdf = hash_secret_raw(
            secret=master_password.encode(),
            salt=salt,
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            type=Type.ID
        )
        self.fer = Fernet(base64.urlsafe_b64encode(kdf))
        return {"message": "Account created successfully."}

    async def verify_master_password(self, master_password: str, totp_code: Optional[str] = None):
        lock = await self.db.get_lockout_data(self.username)
        if time.time() < lock['lockout_until']:
            raise HTTPException(status_code=403, detail="User locked out")

        result = await self.db.execute_with_retry(
            "SELECT pass FROM users WHERE uname = ?", [self.username]
        )
        if not result.rows:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        try:
            self.ph.verify(result.rows[0][0], master_password)
        except VerifyMismatchError:
            await self.inc_login_failure()
            raise HTTPException(status_code=401, detail="Invalid credentials")

        totp_secret = await self.db.get_totp_secret(self.username)
        if totp_secret:
            if not totp_code or not pyotp.TOTP(totp_secret).verify(totp_code):
                raise HTTPException(status_code=403, detail="Invalid TOTP code")

        await self.db.reset_lockout_data(self.username)
        salt_hex = (await self.db.execute_with_retry(
            "SELECT salt_phrase FROM users WHERE uname = ?", [self.username]
        )).rows[0][0]
        salt = bytes.fromhex(salt_hex)
        kdf = hash_secret_raw(
            secret=master_password.encode(),
            salt=salt,
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            type=Type.ID
        )
        self.fer = Fernet(base64.urlsafe_b64encode(kdf))
        return True

    async def inc_login_failure(self):
        lock = await self.db.get_lockout_data(self.username)
        fa = lock['failed_attempts'] + 1
        until = int(time.time()) + (3 * (2 ** (fa - 5)) * 60 if fa >= 5 else 0)
        await self.db.set_lockout_data(self.username, fa, until)

    async def enable_2fa(self):
        totp_secret = pyotp.random_base32()
        await self.db.set_totp_secret(self.username, totp_secret)
        totp = pyotp.TOTP(totp_secret)
        uri = totp.provisioning_uri(name=self.username, issuer_name="SecureASF")
        print(f"Your new TOTP secret is: {totp_secret}")
        return {"totp_secret": totp_secret, "provisioning_uri": uri}

    async def disable_2fa(self):
        await self.db.delete_totp_secret(self.username)
        return {"message": "2FA disabled successfully."}

    async def verify_recovery_pin(self, recovery_pin: str):
        stored_pin = await self.db.get_recovery_pin(self.username)
        if not stored_pin:
            return False
        try:
            return self.ph.verify(stored_pin, recovery_pin)
        except VerifyMismatchError:
            return False

    async def reset_master_password(self, new_password: str):
        hash_value = await self.create_key(new_password)
        await self.db.execute_with_retry(
            "UPDATE users SET pass = ? WHERE uname = ?",
            [hash_value, self.username]
        )
        salt_hex = (await self.db.execute_with_retry(
            "SELECT salt_phrase FROM users WHERE uname = ?", [self.username]
        )).rows[0][0]
        salt = bytes.fromhex(salt_hex)
        kdf = hash_secret_raw(
            secret=new_password.encode(),
            salt=salt,
            time_cost=2,
            memory_cost=102400,
            parallelism=8,
            hash_len=32,
            type=Type.ID
        )
        self.fer = Fernet(base64.urlsafe_b64encode(kdf))
        return {"message": "Master password reset successfully."}

    async def delete_all_data(self, pin: str):
        if not await self.verify_recovery_pin(pin):
            raise HTTPException(status_code=401, detail="Invalid PIN")
        await self.db.delete_user_data(self.username)
        return {"message": "All data permanently deleted."}

    async def delete_credentials(self, site: str):
        await self.db.delete_site(self.username, site)
        return {"message": "Credentials deleted successfully."}

    async def delete_wallet(self, wallet: str):
        await self.db.delete_wallet(self.username, wallet)
        return {"message": "Wallet deleted successfully."}

    async def add_credentials(self, site, user, pwd):
        if pwd.strip().lower() == 'gen':
            pwd = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(25))
        eu = self.fer.encrypt(user.encode()).decode()
        ep = self.fer.encrypt(pwd.encode()).decode()
        await self.db.store_site(self.username, site, eu, ep)
        return {"message": "Credentials added successfully."}

    async def get_credentials(self, site, master_password):
        if not await self.verify_master_password(master_password):
            raise HTTPException(status_code=401, detail="Invalid master password")
        creds = await self.db.get_site_credentials(self.username, site)
        if not creds:
            raise HTTPException(status_code=404, detail="Site not found")
        du = self.fer.decrypt(creds[0].encode()).decode()
        dp = self.fer.decrypt(creds[1].encode()).decode()
        return {"username": du or "No username", "password": dp or "No password"}

    async def add_wallet(self, wallet, user, pwd, phrase, master_password, pin):
        if not await self.verify_master_password(master_password):
            raise HTTPException(status_code=401, detail="Invalid master password")
        if pwd.strip().lower() == 'gen':
            pwd = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(25))
        eu = self.fer.encrypt(user.encode()).decode()
        ep = self.fer.encrypt(pwd.encode()).decode()
        er = self.fer.encrypt(phrase.encode()).decode()
        await self.db.store_wallet(self.username, wallet, eu, ep, er)
        return {"message": "Wallet added successfully."}

    async def get_wallet(self, wallet, master_password, pin):
        await self.verify_master_password(master_password)
        if not await self.verify_recovery_pin(pin):
            raise HTTPException(status_code=401, detail="Invalid PIN")
        cred = await self.db.get_wallet(self.username, wallet)
        if not cred:
            raise HTTPException(status_code=404, detail="Wallet not found")
        du = self.fer.decrypt(cred[0].encode()).decode() if cred[0] else ""
        dp = self.fer.decrypt(cred[1].encode()).decode() if cred[1] else ""
        dr = self.fer.decrypt(cred[2].encode()).decode() if cred[2] else ""
        return {
            "username": du or "No username",
            "password": dp or "No password",
            "recovery_phrase": dr or "No recovery phrase"
        }

    async def add_secure_doc(self, name, contents):
        ec = self.fer.encrypt(contents.encode()).decode()
        await self.db.store_doc(self.username, name, ec)
        return {"message": "Document added successfully."}

    async def get_secure_doc(self, name, master_password):
        if not await self.verify_master_password(master_password):
            raise HTTPException(status_code=401, detail="Invalid master password")
        doc = await self.db.get_doc(self.username, name)
        if not doc:
            raise HTTPException(status_code=404, detail="Document not found")
        dc = self.fer.decrypt(doc[1].encode()).decode()
        return {"name": name, "contents": dc}

    async def get_all_docs(self):
        docs = await self.db.get_all_docs(self.username)
        return {"documents": docs}

    async def update_secure_doc(self, name, new_contents):
        ec = self.fer.encrypt(new_contents.encode()).decode()
        await self.db.update_doc(self.username, name, ec)
        return {"message": "Document updated successfully."}

    async def delete_secure_doc(self, name):
        await self.db.delete_doc(self.username, name)
        return {"message": "Document deleted successfully."}


# ----- FastAPI Application Setup -----
app = FastAPI(title="SecureASF API")
sessions = {}

# Pydantic models
class RegisterRequest(BaseModel):
    username: str
    master_password: str
    confirm_master_password: str
    recovery_pin: str
    confirm_recovery_pin: str

class LoginRequest(BaseModel):
    username: str
    master_password: str
    totp_code: Optional[str] = None

class CredentialsRequest(BaseModel):
    username: str
    master_password: str
    site: str
    s_username: str
    s_password: str

class GetCredentialsRequest(BaseModel):
    username: str
    master_password: str
    site: str

class Disable2FARequest(BaseModel):
    username: str
    pin: str

class WalletRequest(BaseModel):
    username: str
    master_password: str
    wallet_name: str
    w_username: str
    w_password: str
    recovery_phrase: str
    pin: str

class GetWalletRequest(BaseModel):
    username: str
    master_password: str
    wallet_name: str
    pin: str

class ResetMasterPasswordRequest(BaseModel):
    username: str
    old_master_password: str
    new_master_password: str
    totp_code: Optional[str] = None

class DeleteDataRequest(BaseModel):
    username: str
    pin: str

class DeleteCredentialsRequest(BaseModel):
    username: str
    site: str

class DeleteWalletRequest(BaseModel):
    username: str
    wallet_name: str

class SecureDocAddRequest(BaseModel):
    username: str
    master_password: str
    doc_name: str
    doc_contents: str

class ViewDocRequest(BaseModel):
    username: str
    master_password: str
    doc_name: str

class UpdateSecureDocRequest(BaseModel):
    username: str
    master_password: str
    doc_name: str
    new_contents: str

class DeleteDocRequest(BaseModel):
    username: str
    doc_name: str

class TwoFARequest(BaseModel):
    username: str

class GetAllSitesRequest(BaseModel):
    username: str

class GetAllWalletsRequest(BaseModel):
    username: str


# Endpoints
@app.post("/register")
async def register(req: RegisterRequest):
    if req.master_password != req.confirm_master_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    if req.recovery_pin != req.confirm_recovery_pin:
        raise HTTPException(status_code=400, detail="Recovery PINs do not match")
    mgr = DynamicPasswordManager(req.username)
    return await mgr.create_account(req.master_password, req.recovery_pin)

@app.post("/login")
async def login(req: LoginRequest):
    mgr = DynamicPasswordManager(req.username)
    if await mgr.verify_master_password(req.master_password, req.totp_code):
        sessions[req.username] = {"manager": mgr, "master_password": req.master_password}
        return {"message": "Login successful"}
    raise HTTPException(status_code=401, detail="Invalid credentials or TOTP code")

@app.post("/get_all_sites")
async def get_all_sites(req: GetAllSitesRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    sites = await sessions[req.username]["manager"].db.get_all_sites(req.username)
    return {"sites": sites}

@app.post("/add_credentials")
async def add_credentials(req: CredentialsRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[req.username]["manager"].add_credentials(req.site, req.s_username, req.s_password)

@app.post("/get_credentials")
async def get_credentials(req: GetCredentialsRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[req.username]["manager"].get_credentials(req.site, req.master_password)

@app.post("/delete_credentials")
async def delete_credentials(req: DeleteCredentialsRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[req.username]["manager"].delete_credentials(req.site)

@app.post("/get_all_wallets")
async def get_all_wallets(req: GetAllWalletsRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    wallets = await sessions[req.username]["manager"].db.get_all_wallets(req.username)
    return {"wallets": wallets}

@app.post("/add_wallet")
async def add_wallet(req: WalletRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[req.username]["manager"].add_wallet(
        req.wallet_name, req.w_username, req.w_password, req.recovery_phrase, req.master_password, req.pin
    )

@app.post("/get_wallet")
async def get_wallet(req: GetWalletRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[req.username]["manager"].get_wallet(req.wallet_name, req.master_password, req.pin)

@app.post("/delete_wallet")
async def delete_wallet(req: DeleteWalletRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[req.username]["manager"].delete_wallet(req.wallet_name)

@app.post("/reset_master_password")
async def reset_master_password(req: ResetMasterPasswordRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    mgr = sessions[req.username]["manager"]
    if not await mgr.verify_master_password(req.old_master_password, req.totp_code):
        raise HTTPException(status_code=401, detail="Invalid current password or 2FA code")
    result = await mgr.reset_master_password(req.new_master_password)
    sessions[req.username]["master_password"] = req.new_master_password
    return result

@app.post("/enable_2fa")
async def enable_2fa(req: TwoFARequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[req.username]["manager"].enable_2fa()

@app.post("/disable_2fa")
async def disable_2fa(req: Disable2FARequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    manager = sessions[req.username]["manager"]
    #verify the recovery PIN before disabling 2FA
    if not await manager.verify_recovery_pin(req.pin):
        raise HTTPException(status_code=401, detail="Invalid recovery PIN")
    return await manager.disable_2fa()

@app.post("/delete_all_data")
async def delete_all_data(req: DeleteDataRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[req.username]["manager"].delete_all_data(req.pin)

@app.post("/add_secure_doc")
async def add_secure_doc(req: SecureDocAddRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[req.username]["manager"].add_secure_doc(req.doc_name, req.doc_contents)

@app.post("/get_secure_doc")
async def get_secure_doc(req: ViewDocRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[req.username]["manager"].get_secure_doc(req.doc_name, req.master_password)

@app.get("/get_all_docs")
async def get_all_docs(username: str):
    if username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[username]["manager"].get_all_docs()

@app.post("/update_secure_doc")
async def update_secure_doc(req: UpdateSecureDocRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[req.username]["manager"].update_secure_doc(req.doc_name, req.new_contents)

@app.post("/delete_secure_doc")
async def delete_secure_doc(req: DeleteDocRequest):
    if req.username not in sessions:
        raise HTTPException(status_code=401, detail="User not logged in")
    return await sessions[req.username]["manager"].delete_secure_doc(req.doc_name)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "443")),
        ssl_keyfile=os.getenv("SSL_KEY_FILE", "key.pem"),
        ssl_certfile=os.getenv("SSL_CERT_FILE", "cert.pem"),
        reload=True
    )
