from pathlib import Path
import sqlite3

import jwt
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

DB_PATH = Path(__file__).with_name("secuscan.db")
# INTENTIONAL VULNERABILITY: hardcoded weak JWT secret.
JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"

app = FastAPI(title="SecuScan Vulnerable Lab")


class LoginRequest(BaseModel):
    username: str
    password: str


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            bio TEXT NOT NULL
        );
        """
    )
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        conn.executemany(
            "INSERT INTO users (id, username, password, email, bio) VALUES (?, ?, ?, ?, ?)",
            [
                (1, "alice", "password123", "alice@example.com", "Security student"),
                (2, "bob", "password123", "bob@example.com", "Backend learner"),
                (3, "carol", "password123", "carol@example.com", "Python enthusiast"),
                (4, "dave", "password123", "dave@example.com", "API tinkerer"),
            ],
        )
    conn.commit()
    conn.close()


@app.on_event("startup")
def startup():
    init_db()


@app.get("/")
def root():
    return {
        "name": "SecuScan vulnerable lab",
        "warning": "Intentionally vulnerable. Run only on localhost or an isolated lab network.",
    }


@app.get("/search")
def search(q: str = Query(default="")):
    conn = get_db()
    # INTENTIONAL VULNERABILITY: SQL injection through string concatenation.
    sql = f"SELECT id, username, email, bio FROM users WHERE username LIKE '%{q}%'"
    try:
        rows = conn.execute(sql).fetchall()
        return {"query": q, "results": [dict(row) for row in rows]}
    except sqlite3.Error as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})
    finally:
        conn.close()


@app.post("/login")
def login(payload: LoginRequest):
    conn = get_db()
    user = conn.execute(
        "SELECT id, username, password FROM users WHERE username = ?",
        (payload.username,),
    ).fetchone()
    conn.close()

    # INTENTIONAL VULNERABILITY: weak shared password for the lab.
    if not user or payload.password != "password123":
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # INTENTIONAL VULNERABILITY: JWT has no exp claim and uses a hardcoded weak secret.
    token = jwt.encode(
        {"sub": str(user["id"]), "username": user["username"], "role": "user"},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )
    return {"access_token": token, "token_type": "bearer"}


def get_current_user(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.get("/users/{user_id}/profile")
def profile(user_id: int, authorization: str | None = None):
    # INTENTIONAL VULNERABILITY: the supplied user_id is trusted; ownership is never checked.
    # A token is accepted if present, but it is not compared with the requested user_id.
    if authorization and authorization.lower().startswith("bearer "):
        get_current_user(authorization[7:])

    conn = get_db()
    row = conn.execute(
        "SELECT id, username, email, bio FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(row)
