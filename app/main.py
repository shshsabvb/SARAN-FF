import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="SARAN FF Licence API")

DB = os.getenv("DB_PATH", "saran.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")

def connect():
    return sqlite3.connect(DB)

with connect() as con:
    con.execute("""
    CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_hash TEXT UNIQUE,
        duration INTEGER,
        activated TEXT,
        expires TEXT,
        device TEXT,
        revoked INTEGER DEFAULT 0
    )
    """)

def digest(key):
    return hashlib.sha256(key.strip().upper().encode()).hexdigest()

def admin_check(token):
    if not ADMIN_TOKEN or token != "Bearer " + ADMIN_TOKEN:
        raise HTTPException(401, "Invalid admin token")

class CreateRequest(BaseModel):
    duration: str
    quantity: int = 1

class ActivateRequest(BaseModel):
    key: str
    device: str

DURATIONS = {
    "1h": 3600,
    "1d": 86400,
    "7d": 604800,
    "15d": 1296000,
    "30d": 2592000
}

@app.get("/")
def home():
    return {"service": "SARAN FF", "status": "online"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/admin/create")
def create_keys(data: CreateRequest,
                authorization: str = Header(default="")):
    admin_check(authorization)

    if data.duration not in DURATIONS:
        raise HTTPException(400, "Invalid duration")

    if not 1 <= data.quantity <= 100:
        raise HTTPException(400, "Quantity must be 1 to 100")

    created = []

    with connect() as con:
        for _ in range(data.quantity):
            key = "SARAN-" + secrets.token_hex(8).upper()
            con.execute(
                "INSERT INTO keys (key_hash, duration) VALUES (?, ?)",
                (digest(key), DURATIONS[data.duration])
            )
            created.append(key)

    return {"created": len(created), "keys": created}

@app.post("/admin/revoke/{key_id}")
def revoke_key(key_id: int,
               authorization: str = Header(default="")):
    admin_check(authorization)

    with connect() as con:
        cur = con.execute(
            "UPDATE keys SET revoked=1 WHERE id=?", (key_id,)
        )
        if cur.rowcount == 0:
            raise HTTPException(404, "Key not found")

    return {"status": "revoked"}

@app.post("/activate")
def activate(data: ActivateRequest):
    now = datetime.now(timezone.utc)

    with connect() as con:
        row = con.execute(
            "SELECT id,duration,activated,expires,device,revoked "
            "FROM keys WHERE key_hash=?",
            (digest(data.key),)
        ).fetchone()

        if not row:
            raise HTTPException(401, "Invalid licence key")

        key_id, duration, activated, expires, device, revoked = row

        if revoked:
            raise HTTPException(403, "Licence revoked")

        if expires and now >= datetime.fromisoformat(expires):
            raise HTTPException(403, "Licence expired. Enter a new key.")

        if activated:
            if device != data.device:
                raise HTTPException(403, "Key belongs to another device")
        else:
            expiry = now + timedelta(seconds=duration)
            activated = now.isoformat()
            expires = expiry.isoformat()

            con.execute(
                "UPDATE keys SET activated=?, expires=?, device=? "
                "WHERE id=?",
                (activated, expires, data.device, key_id)
            )

    return {
        "valid": True,
        "message": "Access granted",
        "expires": expires
    }
