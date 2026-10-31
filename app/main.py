import os
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="SARAN FF Licence API")

DB = os.getenv("DB_PATH", "saran.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")


# DATABASE

def connect():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


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


# HELPERS

def digest(key):
    return hashlib.sha256(
        key.strip().upper().encode()
    ).hexdigest()


def admin_check(token):
    if not ADMIN_TOKEN or token != "Bearer " + ADMIN_TOKEN:
        raise HTTPException(401, "Invalid admin token")


def key_status(row):
    if row["revoked"]:
        return "Revoked"

    if not row["activated"]:
        return "Unused"

    if row["expires"]:
        expiry = datetime.fromisoformat(row["expires"])
        if datetime.now(timezone.utc) >= expiry:
            return "Expired"

    return "Active"


# REQUEST MODELS

class CreateRequest(BaseModel):
    duration: str
    quantity: int = 1
    custom_hours: int = 0


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


# PUBLIC ROUTES

@app.get("/")
def home():
    return {
        "service": "SARAN FF",
        "status": "online"
    }


@app.get("/health")
def health():
    return {"status": "ok"}


# ADMIN DASHBOARD

@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard():
    return """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SARAN FF Admin</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0;
    padding: 20px;
    background: #090909;
    color: white;
    font-family: Arial, sans-serif;
}
.container {
    max-width: 950px;
    margin: auto;
}
h1 { color: #ed1717; }
.card {
    background: #171717;
    border: 1px solid #383838;
    border-radius: 12px;
    padding: 18px;
    margin: 15px 0;
}
input, select, button {
    width: 100%;
    padding: 12px;
    margin: 7px 0;
    border-radius: 7px;
    border: 1px solid #444;
    background: #242424;
    color: white;
}
button {
    background: #d90000;
    border: none;
    font-weight: bold;
    cursor: pointer;
}
button:hover { background: #a90000; }
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
th, td {
    padding: 10px 6px;
    border-bottom: 1px solid #333;
    text-align: left;
    overflow-wrap: anywhere;
}
.small {
    color: #aaa;
    font-size: 12px;
}
#message { white-space: pre-wrap; }
.key {
    color: #ff5555;
    font-weight: bold;
}
@media(max-width:600px) {
    body { padding: 10px; }
    table { font-size: 11px; }
    th, td { padding: 7px 3px; }
}
</style>
</head>
<body>
<div class="container">

<h1>SARAN FF</h1>
<p class="small">LICENCE CONTROL PANEL</p>

<div class="card">
<h3>Admin Login</h3>
<input id="token" type="password"
placeholder="Enter ADMIN_TOKEN">
<button onclick="login()">LOGIN</button>
<p id="loginStatus" class="small"></p>
</div>

<div id="panel" style="display:none">

<div class="card">
<h3>Generate Licences</h3>

<label>Licence Duration</label>
<select id="duration">
<option value="1h">1 Hour</option>
<option value="1d">1 Day</option>
<option value="7d">7 Days</option>
<option value="15d">15 Days</option>
<option value="30d">30 Days</option>
<option value="custom">Custom Hours</option>
</select>

<input id="customHours" type="number"
min="1" max="8760"
placeholder="Custom duration in hours"
style="display:none">

<label>Quantity</label>
<input id="quantity" type="number"
min="1" max="100" value="1">

<button onclick="createKeys()">GENERATE KEYS</button>
<div id="created"></div>
</div>

<div class="card">
<h3>Licence Management</h3>
<button onclick="loadKeys()">REFRESH LICENCES</button>

<div style="overflow-x:auto">
<table>
<thead>
<tr>
<th>ID</th>
<th>Key</th>
<th>Status</th>
<th>Expiry</th>
<th>Action</th>
</tr>
</thead>
<tbody id="keys"></tbody>
</table>
</div>
</div>

</div>
<p id="message" class="small"></p>
</div>

<script>
let adminToken = "";

document.getElementById("duration").onchange = function() {
    document.getElementById("customHours").style.display =
        this.value === "custom" ? "block" : "none";
};

function headers() {
    return {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + adminToken
    };
}

async function login() {
    adminToken = document.getElementById("token").value.trim();

    if (!adminToken) {
        document.getElementById("loginStatus").innerText =
            "Enter your admin token.";
        return;
    }

    try {
        const response = await fetch("/admin/keys", {
            headers: headers()
        });

        if (!response.ok) throw new Error("Invalid token");

        document.getElementById("panel").style.display = "block";
        document.getElementById("loginStatus").innerText =
            "Login successful.";

        loadKeys();
    } catch (error) {
        adminToken = "";
        document.getElementById("loginStatus").innerText =
            "Login failed. Check your admin token.";
    }
}

async function createKeys() {
    const duration = document.getElementById("duration").value;
    const quantity = Number(document.getElementById("quantity").value);
    const customHours = Number(
        document.getElementById("customHours").value
    );

    const body = {
        duration: duration,
        quantity: quantity,
        custom_hours: customHours
    };

    try {
        const response = await fetch("/admin/create", {
            method: "POST",
            headers: headers(),
            body: JSON.stringify(body)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Generation failed");
        }

        document.getElementById("created").innerHTML =
            "<p>Created " + data.created + " licences:</p>" +
            data.keys.map(k =>
                '<p class="key">' + k + '</p>'
            ).join("");

        loadKeys();
    } catch (error) {
        alert(error.message);
    }
}

async function loadKeys() {
    try {
        const response = await fetch("/admin/keys", {
            headers: headers()
        });

        const data = await response.json();

        if (!response.ok) throw new Error(
            data.detail || "Could not load licences"
        );

        document.getElementById("keys").innerHTML =
            data.keys.map(k => `
            <tr>
                <td>${k.id}</td>
                <td>${k.key}</td>
                <td>${k.status}</td>
                <td>${k.expires || "Not activated"}</td>
                <td>
                    ${k.revoked ? "Revoked" :
                    '<button onclick="revokeKey(' + k.id + ')">REVOKE</button>'}
                </td>
            </tr>
            `).join("");
    } catch (error) {
        document.getElementById("message").innerText =
            error.message;
    }
}

async function revokeKey(id) {
    if (!confirm("Revoke this licence?")) return;

    try {
        const response = await fetch(
            "/admin/revoke/" + id,
            {
                method: "POST",
                headers: headers()
            }
        );

        const data = await response.json();
        if (!response.ok) throw new Error(
            data.detail || "Revoke failed"
        );

        loadKeys();
    } catch (error) {
        alert(error.message);
    }
}
</script>
</body>
</html>
"""


# ADMIN: CREATE KEYS

@app.post("/admin/create")
def create_keys(
    data: CreateRequest,
    authorization: str = Header(default="")
):
    admin_check(authorization)

    if data.duration == "custom":
        if not 1 <= data.custom_hours <= 8760:
            raise HTTPException(
                400, "Custom hours must be between 1 and 8760"
            )
        duration_seconds = data.custom_hours * 3600

    elif data.duration in DURATIONS:
        duration_seconds = DURATIONS[data.duration]

    else:
        raise HTTPException(400, "Invalid duration")

    if not 1 <= data.quantity <= 100:
        raise HTTPException(
            400, "Quantity must be 1 to 100"
        )

    created = []

    with connect() as con:
        for _ in range(data.quantity):
            key = "SARAN-" + secrets.token_hex(8).upper()

            con.execute(
                "INSERT INTO keys (key_hash, duration) VALUES (?, ?)",
                (digest(key), duration_seconds)
            )

            created.append(key)

    return {
        "created": len(created),
        "keys": created
    }


# ADMIN: LIST KEYS
# Original keys are stored as hashes, so the full key is
# shown only once, immediately after generation.

@app.get("/admin/keys")
def list_keys(
    authorization: str = Header(default="")
):
    admin_check(authorization)

    with connect() as con:
        rows = con.execute(
            "SELECT id, duration, activated, expires, device, revoked "
            "FROM keys ORDER BY id DESC"
        ).fetchall()

    return {
        "keys": [
            {
                "id": row["id"],
                "duration": row["duration"],
                "activated": row["activated"],
                "expires": row["expires"],
                "device": row["device"],
                "revoked": row["revoked"],
                "status": key_status(row),
                "key": "Hidden (hash stored)"
            }
            for row in rows
        ]
    }


# ADMIN: REVOKE KEY

@app.post("/admin/revoke/{key_id}")
def revoke_key(
    key_id: int,
    authorization: str = Header(default="")
):
    admin_check(authorization)

    with connect() as con:
        cur = con.execute(
            "UPDATE keys SET revoked=1 WHERE id=?",
            (key_id,)
        )

        if cur.rowcount == 0:
            raise HTTPException(404, "Key not found")

    return {"status": "revoked"}


# APP: ACTIVATE LICENCE

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

        key_id = row["id"]
        duration = row["duration"]
        activated = row["activated"]
        expires = row["expires"]
        device = row["device"]
        revoked = row["revoked"]

        if revoked:
            raise HTTPException(403, "Licence revoked")

        if expires and now >= datetime.fromisoformat(expires):
            raise HTTPException(
                403, "Licence expired. Enter a new key."
            )

        if activated:
            if device != data.device:
                raise HTTPException(
                    403, "Key belongs to another device"
                )
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
