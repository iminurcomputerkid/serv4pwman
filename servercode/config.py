# config.py
import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

TURSO_DATABASE_URL: str = os.getenv("TURSO_DATABASE_URL", "").replace("libsql://", "https://")
TURSO_AUTH_TOKEN: str = os.getenv("TURSO_AUTH_TOKEN")

# TLS settings, not needed as API server defaults traffic to HTTPS
PORT: int            = int(os.getenv("PORT", "443"))
SSL_KEY_FILE: str    = os.getenv("SSL_KEY_FILE", "key.pem")
SSL_CERT_FILE: str   = os.getenv("SSL_CERT_FILE", "cert.pem")

# CORS 
# change later to proper origin rathre than everything
ALLOW_ORIGINS = ["*"]