import os
import base64
import hashlib
import secrets
import sqlite3
import smtplib
from datetime import datetime
from email.message import EmailMessage
from typing import List, Optional, Tuple

from fastapi import FastAPI, Header, HTTPException, UploadFile, File, Form
from pydantic import BaseModel, Field

DB_PATH = os.getenv("API_DB_PATH", "api.db")
MAX_ATTACHMENT_BYTES = int(os.getenv("MAX_ATTACHMENT_BYTES", "20000000"))  # 20MB

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
FROM_EMAIL = os.getenv("FROM_EMAIL")

ADMIN_KEY = os.getenv("ADMIN_KEY")  


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with db_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT NOT NULL UNIQUE,
                name TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def verify_api_key(raw_key: str) -> bool:
    if not raw_key:
        return False
    h = hash_key(raw_key)
    with db_conn() as conn:
        row = conn.execute(
            "SELECT id FROM api_keys WHERE key_hash=? AND is_active=1",
            (h,),
        ).fetchone()
    return row is not None


def require_admin(x_admin_key: Optional[str]) -> None:
    if not ADMIN_KEY:
        raise HTTPException(status_code=503, detail="ADMIN_KEY not configured on server.")
    if not x_admin_key or not secrets.compare_digest(x_admin_key, ADMIN_KEY):
        raise HTTPException(status_code=401, detail="Unauthorized (admin).")


def require_client_key(x_api_key: Optional[str]) -> None:
    if not x_api_key or not verify_api_key(x_api_key):
        raise HTTPException(status_code=401, detail="Unauthorized (missing/invalid X-API-Key).")



def _decode_base64(data: str) -> bytes:
    # supports raw base64 OR data URLs (data:...;base64,AAA)
    if data and data.strip().lower().startswith("data:") and "," in data:
        data = data.split(",", 1)[1]
    return base64.b64decode(data, validate=False)


def smtp_send(
    to_addrs: List[str],
    cc_addrs: List[str],
    subject: str,
    html_body: str,
    attachments: List[Tuple[str, str, bytes]],
) -> None:
    if not SMTP_HOST or not FROM_EMAIL:
        raise HTTPException(status_code=500, detail="SMTP_HOST and FROM_EMAIL must be set on server.")

    msg = EmailMessage()
    msg["From"] = FROM_EMAIL
    msg["To"] = ", ".join(to_addrs)
    msg["Subject"] = subject
    if cc_addrs:
        msg["Cc"] = ", ".join(cc_addrs)

    msg.set_content("This email contains HTML content.")
    msg.add_alternative(html_body, subtype="html")

    for filename, content_type, raw in attachments:
        if len(raw) > MAX_ATTACHMENT_BYTES:
            raise HTTPException(status_code=400, detail=f"Attachment too large: {filename}")

        if "/" in content_type:
            maintype, subtype = content_type.split("/", 1)
        else:
            maintype, subtype = "application", "octet-stream"

        msg.add_attachment(raw, maintype=maintype, subtype=subtype, filename=filename)

    # Send
    if SMTP_USER and SMTP_PASS:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            if SMTP_USE_TLS:
                s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            s.send_message(msg)



app = FastAPI(
    title="Email Sender API",
    version="1.0.0",
    description="SMTP-based email sender with API keys, file upload (local testing), and base64 attachments (automation).",
)

init_db()



# Models
class AttachmentB64(BaseModel):
    name: str = Field(..., description="Filename e.g. report.mhtml")
    contentType: str = Field("application/octet-stream", description="MIME type e.g. application/x-mhtml")
    contentBase64: str = Field(..., description="Base64 content (may also be data URL)")


class SendJsonRequest(BaseModel):
    to: List[str]
    cc: List[str] = []
    subject: str
    htmlBody: str
    attachments: List[AttachmentB64] = []


class CreateKeyRequest(BaseModel):
    name: Optional[str] = None



# Routes

@app.get("/health")
def health():
    return {"ok": True}


@app.post("/send-json")
def send_json(payload: SendJsonRequest, x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")):
    """
    Send email with base64 attachments (for automation e.g., Logic Apps).
    Requires X-API-Key header.
    """
    require_client_key(x_api_key)

    attachments: List[Tuple[str, str, bytes]] = []
    for a in payload.attachments:
        raw = _decode_base64(a.contentBase64)
        attachments.append((a.name, a.contentType, raw))

    smtp_send(payload.to, payload.cc, payload.subject, payload.htmlBody, attachments)
    return {"ok": True, "sent": True, "attachments": [x[0] for x in attachments]}


@app.post("/send-upload")
async def send_upload(
    to: str = Form(..., description="Comma-separated emails"),
    subject: str = Form(...),
    htmlBody: str = Form(...),
    cc: str = Form("", description="Comma-separated emails"),
    files: List[UploadFile] = File(...),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    """
    Send email with file upload attachments (great for local/manual testing).
    Requires X-API-Key header.
    """
    require_client_key(x_api_key)

    to_addrs = [e.strip() for e in to.split(",") if e.strip()]
    cc_addrs = [e.strip() for e in cc.split(",") if e.strip()]

    attachments: List[Tuple[str, str, bytes]] = []
    for f in files:
        raw = await f.read()
        ctype = f.content_type or "application/octet-stream"
        attachments.append((f.filename or "attachment.bin", ctype, raw))

    smtp_send(to_addrs, cc_addrs, subject, htmlBody, attachments)
    return {"ok": True, "sent": True, "attachments": [x[0] for x in attachments]}


# API key management (admin-only)

@app.post("/keys")
def create_key(
    req: CreateKeyRequest,
    x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
):
    """
    Admin: Create a new client API key.
    Returns the raw key ONCE.
    """
    require_admin(x_admin_key)

    raw_key = secrets.token_urlsafe(32)
    h = hash_key(raw_key)

    with db_conn() as conn:
        conn.execute(
            "INSERT INTO api_keys (key_hash, name, is_active, created_at) VALUES (?, ?, 1, ?)",
            (h, req.name, datetime.utcnow().isoformat() + "Z"),
        )
        conn.commit()

    return {"ok": True, "apiKey": raw_key, "name": req.name}


@app.get("/keys")
def list_keys(x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    """
    Admin: List keys (does NOT return raw keys).
    """
    require_admin(x_admin_key)
    with db_conn() as conn:
        rows = conn.execute("SELECT id, name, is_active, created_at FROM api_keys ORDER BY id DESC").fetchall()
    return {"ok": True, "keys": [dict(r) for r in rows]}


@app.delete("/keys/{key_id}")
def revoke_key(key_id: int, x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key")):
    """
    Admin: Revoke a key.
    """
    require_admin(x_admin_key)
    with db_conn() as conn:
        conn.execute("UPDATE api_keys SET is_active=0 WHERE id=?", (key_id,))
        conn.commit()
    return {"ok": True, "revoked": key_id}
