from typing import Optional
from pydantic import BaseModel


# ──────────────────────────── auth / account ──────────────────────────────
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
    recovery_pin: Optional[str] = None


class TwoFARequest(BaseModel):
    username: str


class Disable2FARequest(BaseModel):
    username: str
    pin: str


class ResetMasterPasswordRequest(BaseModel):
    username: str
    old_master_password: str
    new_master_password: str
    totp_code: Optional[str] = None


class DeleteDataRequest(BaseModel):
    username: str
    pin: str


# ───────────────────────────── site vault ─────────────────────────────────
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


class DeleteCredentialsRequest(BaseModel):
    username: str
    site: str
    pin: str


class GetAllSitesRequest(BaseModel):
    username: str


# ───────────────────────────── wallets vault ──────────────────────────────
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


class DeleteWalletRequest(BaseModel):
    username: str
    wallet_name: str
    pin: str


class GetAllWalletsRequest(BaseModel):
    username: str


# ─────────────────────────── secure documents ─────────────────────────────
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
    pin: str
