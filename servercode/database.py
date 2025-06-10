import asyncio
from typing import Optional

from aiohttp import ClientError
from libsql_client import create_client

from config import TURSO_DATABASE_URL, TURSO_AUTH_TOKEN

class DatabaseConnector:
    def __init__(self):
        self.client = create_client(
            url=TURSO_DATABASE_URL,
            auth_token= TURSO_AUTH_TOKEN
        )

    async def execute_with_retry(self, query, params=None, max_retries: int = 3):
        for attempt in range(max_retries):
            try:
                return await self.client.execute(query, params)
            except ClientError:
                if attempt == max_retries - 1:
                    raise
                await asyncio.sleep(1 * (attempt + 1))

    async def close(self):
        await self.client.close()

    # ──────────────────────── lock-out / 2FA data ──────────────────────────
    async def get_lockout_data(self, username):
        result = await self.execute_with_retry(
            "SELECT failed_attempts, lockout_until, pin_verified "
            "FROM users WHERE uname = ?",
            [username],
        )
        if result.rows:
            fa, until, pv = result.rows[0]
            return {
                "failed_attempts": fa,
                "lockout_until": until,
                "pin_verified": bool(pv),
            }
        return {"failed_attempts": 0, "lockout_until": 0, "pin_verified": False}

    async def set_lockout_data(
        self, username, failed_attempts, lockout_until, pin_verified
    ):
        await self.execute_with_retry(
            "UPDATE users SET failed_attempts = ?, lockout_until = ?, "
            "pin_verified = ? WHERE uname = ?",
            [failed_attempts, lockout_until, int(pin_verified), username],
        )

    async def reset_lockout_data(self, username):
        await self.execute_with_retry(
            "UPDATE users SET failed_attempts = 0, lockout_until = 0, "
            "pin_verified = 0 WHERE uname = ?",
            [username],
        )

    async def get_totp_secret(self, username):
        result = await self.execute_with_retry(
            "SELECT totp_secret FROM users WHERE uname = ?", [username]
        )
        return result.rows[0][0] if result.rows and result.rows[0][0] else ""

    async def set_totp_secret(self, username, totp_secret):
        await self.execute_with_retry(
            "UPDATE users SET totp_secret = ? WHERE uname = ?",
            [totp_secret, username],
        )

    async def delete_totp_secret(self, username):
        await self.execute_with_retry(
            "UPDATE users SET totp_secret = '' WHERE uname = ?", [username]
        )

    async def get_recovery_pin(self, username: str) -> Optional[str]:
        result = await self.execute_with_retry(
            "SELECT secret_pin FROM users WHERE uname = ?", [username]
        )
        return result.rows[0][0] if result.rows else None

    async def get_user_password(self, username: str) -> Optional[str]:
        result = await self.execute_with_retry(
            "SELECT pass FROM users WHERE uname = ?", [username]
        )
        return result.rows[0][0] if result.rows else None

    # ───────────────────────── site credentials ────────────────────────────
    async def store_site(
        self, username, site_name, encrypted_username, encrypted_password
    ):
        await self.execute_with_retry(
            "INSERT INTO site (uname, site_name, username, passw) "
            "VALUES (?, ?, ?, ?)",
            [username, site_name, encrypted_username, encrypted_password],
        )

    async def get_site_credentials(self, username, site_name):
        result = await self.execute_with_retry(
            "SELECT username, passw FROM site WHERE uname = ? AND site_name = ?",
            [username, site_name],
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
            [username, site_name],
        )

    # ───────────────────────────── wallets ─────────────────────────────────
    async def store_wallet( self, username, wallet_name, encrypted_username, encrypted_password, encrypted_recovery):
        await self.execute_with_retry(
            "INSERT INTO wallets (uname, wallet_name, username, passw, "
            "recover_phrase) VALUES (?, ?, ?, ?, ?)",
            [
                username,
                wallet_name,
                encrypted_username,
                encrypted_password,
                encrypted_recovery,
            ],
        )

    async def get_wallet(self, username, wallet_name):
        result = await self.execute_with_retry(
            "SELECT username, passw, recover_phrase FROM wallets "
            "WHERE uname = ? AND wallet_name = ?",
            [username, wallet_name],
        )
        return result.rows[0] if result.rows else None

    async def get_all_wallets(self, username):
        result = await self.execute_with_retry(
            "SELECT wallet_name FROM wallets WHERE uname = ?", [username]
        )
        return [row[0] for row in result.rows]

    async def delete_wallet(self, username, wallet_name):
        await self.execute_with_retry(
            "DELETE FROM wallets WHERE uname = ? AND wallet_name = ?",
            [username, wallet_name],
        )

    # ───────────────────────── secure documents ────────────────────────────
    async def store_doc(self, username, doc_name, encrypted_contents):
        await self.execute_with_retry(
            "INSERT INTO secure_docs (uname, doc_name, doc_contents) "
            "VALUES (?, ?, ?)",
            [username, doc_name, encrypted_contents],
        )

    async def get_doc(self, username, doc_name):
        result = await self.execute_with_retry(
            "SELECT doc_name, doc_contents FROM secure_docs "
            "WHERE uname = ? AND doc_name = ?",
            [username, doc_name],
        )
        return (result.rows[0][0], result.rows[0][1]) if result.rows else None

    async def get_all_docs(self, username):
        result = await self.execute_with_retry(
            "SELECT doc_name FROM secure_docs WHERE uname = ?", [username]
        )
        return [row[0] for row in result.rows]

    async def update_doc(self, username, doc_name, new_contents):
        await self.execute_with_retry(
            "UPDATE secure_docs SET doc_contents = ? "
            "WHERE uname = ? AND doc_name = ?",
            [new_contents, username, doc_name],
        )

    async def delete_doc(self, username, doc_name):
        await self.execute_with_retry(
            "DELETE FROM secure_docs WHERE uname = ? AND doc_name = ?",
            [username, doc_name],
        )

    # ────────────────────────── clear data ───────────────────────────────
    async def delete_user_data(self, username):
        await self.execute_with_retry("DELETE FROM site WHERE uname = ?", [username])
        await self.execute_with_retry("DELETE FROM wallets WHERE uname = ?", [username])
        await self.execute_with_retry(
            "DELETE FROM secure_docs WHERE uname = ?", [username]
        )