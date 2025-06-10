# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import (
    ALLOW_ORIGINS,
    PORT,
    SSL_KEY_FILE,
    SSL_CERT_FILE,
)
from routes import router

# ───────────────────────────── app factory ────────────────────────────────
app = FastAPI(title="Secure-ASF API")

# CORS – keep permissive for now; tighten once you know your front-end origin(s)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Bring in every endpoint defined in routes.py
app.include_router(router)

# ──────────────────────────── entry-point ─────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        ssl_keyfile=SSL_KEY_FILE,
        ssl_certfile=SSL_CERT_FILE,
        reload=False,  # switch to True during local dev if you like
    )
