from typing import Dict, Optional
from fastapi import APIRouter, HTTPException, status
from manager import DynamicPasswordManager
from schemas import (
    RegisterRequest,
    LoginRequest,
    TwoFARequest,
    Disable2FARequest,
    DeleteDataRequest,
    CredentialsRequest,
    GetCredentialsRequest,
    DeleteCredentialsRequest,
    GetAllSitesRequest,
    WalletRequest,
    GetWalletRequest,
    DeleteWalletRequest,
    GetAllWalletsRequest,
    SecureDocAddRequest,
    ViewDocRequest,
    UpdateSecureDocRequest,
    DeleteDocRequest,
)

router = APIRouter(prefix="/api", tags=["secure-asf"])

# Simple in-memory “sessions” map  (username ➜ DynamicPasswordManager)
sessions: Dict[str, DynamicPasswordManager] = {}

# ───────────────────────────── auth / account ─────────────────────────────


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest):
    if req.master_password != req.confirm_master_password:
        raise HTTPException(400, "Passwords do not match.")
    if req.recovery_pin != req.confirm_recovery_pin:
        raise HTTPException(400, "Recovery PINs do not match.")

    mgr = DynamicPasswordManager(req.username)
    await mgr.create_account(req.master_password, req.recovery_pin)
    return {"message": "Account created."}


@router.post("/login")
async def login(req: LoginRequest):
    mgr = sessions.get(req.username) or DynamicPasswordManager(req.username)
    await mgr.verify_master_password(
        req.master_password, totp_code=req.totp_code, recovery_pin=req.recovery_pin
    )
    sessions[req.username] = mgr
    return {"message": "Login successful."}


# ──────────────────────── two-factor authentication ───────────────────────


@router.post("/enable-totp")
async def enable_totp(req: TwoFARequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    secret = await mgr.enable_totp()
    return {"totp_secret": secret}


@router.post("/disable-totp")
async def disable_totp(req: Disable2FARequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    res = await mgr.disable_totp()
    return res


# ───────────────────────────── site vault ─────────────────────────────────


@router.post("/site")
async def add_site(req: CredentialsRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    pin: Optional[str] = getattr(req, "pin", None)
    return await mgr.add_site(
        req.site, req.s_username, req.s_password, req.master_password, pin
    )


@router.post("/site/get")
async def get_site(req: GetCredentialsRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    pin: Optional[str] = getattr(req, "pin", None)
    return await mgr.get_site(req.site, req.master_password, pin)


@router.post("/site/all")
async def get_all_sites(req: GetAllSitesRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    pin: Optional[str] = getattr(req, "pin", None)
    return await mgr.get_all_sites(req.master_password, pin)


@router.delete("/site")
async def delete_site(req: DeleteCredentialsRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    return await mgr.delete_site(req.site, req.pin)


# ───────────────────────────── wallets vault ──────────────────────────────


@router.post("/wallet")
async def add_wallet(req: WalletRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    return await mgr.add_wallet(
        req.wallet_name,
        req.w_username,
        req.w_password,
        req.recovery_phrase,
        req.master_password,
        req.pin,
    )


@router.post("/wallet/get")
async def get_wallet(req: GetWalletRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    return await mgr.get_wallet(req.wallet_name, req.master_password, req.pin)


@router.post("/wallet/all")
async def get_all_wallets(req: GetAllWalletsRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    pin: Optional[str] = getattr(req, "pin", None)
    return await mgr.get_all_wallets(req.master_password, pin)


@router.delete("/wallet")
async def delete_wallet(req: DeleteWalletRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    return await mgr.delete_wallet(req.wallet_name, req.pin)


# ─────────────────────────── secure documents ─────────────────────────────


@router.post("/doc")
async def add_secure_doc(req: SecureDocAddRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    pin: Optional[str] = getattr(req, "pin", None)
    return await mgr.add_secure_doc(
        req.doc_name, req.doc_contents, req.master_password, pin
    )


@router.post("/doc/get")
async def view_secure_doc(req: ViewDocRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    pin: Optional[str] = getattr(req, "pin", None)
    return await mgr.get_secure_doc(req.doc_name, req.master_password, pin)


@router.post("/doc/update")
async def update_secure_doc(req: UpdateSecureDocRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    pin: Optional[str] = getattr(req, "pin", None)
    return await mgr.update_secure_doc(
        req.doc_name, req.new_contents, req.master_password, pin
    )


@router.delete("/doc")
async def delete_doc(req: DeleteDocRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    return await mgr.delete_secure_doc(req.doc_name, req.pin)


# ───────────────────────── housekeeping / nuke all ────────────────────────


@router.delete("/user")
async def delete_all_user_data(req: DeleteDataRequest):
    mgr = sessions.get(req.username)
    if not mgr:
        raise HTTPException(401, "User not logged in.")
    # Validate PIN via manager’s master-password check so lock-out rules apply
    await mgr.verify_master_password(
        master_password="dummy",  # not needed for delete
        recovery_pin=req.pin,
    )
    await mgr.db.delete_user_data(req.username)
    return {"message": "All user data erased."}
