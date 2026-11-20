"""Demo RAG chatbot. DELIBERATELY NON-COMPLIANT — used to demo PrivTrace."""

import logging

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from .cache import cache_profile
from .config import DEBUG
from .db import Base, Memory, User, engine, get_db
from .llm import ask, embed
from .schemas import ChatRequest, SignupRequest

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("demo")

app = FastAPI(debug=DEBUG)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def create_tables():
    with engine.begin() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    Base.metadata.create_all(engine)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    body = await request.body()
    logger.info("request %s %s body=%s", request.method, request.url.path, body)
    return await call_next(request)


@app.post("/signup")
def signup(req: SignupRequest, db: Session = Depends(get_db)):
    user = User(name=req.name, email=req.email, phone=req.phone, pan=req.pan, password=req.password)
    db.add(user)
    db.commit()
    cache_profile(user.id, req.name, req.email, req.phone)
    logger.info("new signup email=%s phone=%s pan=%s", req.email, req.phone, req.pan)
    return {"id": user.id}


@app.post("/chat")
def chat(req: ChatRequest, db: Session = Depends(get_db)):
    user = db.get(User, req.user_id)
    vector = embed(req.message)
    rows = db.execute(
        text("SELECT content FROM memories WHERE user_id = :uid ORDER BY embedding <-> CAST(:v AS vector) LIMIT 3"),
        {"uid": req.user_id, "v": str(vector)},
    ).fetchall()
    context = "\n".join(r.content for r in rows)
    prompt = f"You are a helpful assistant for {user.name} (email {user.email}, phone {user.phone}).\nContext:\n{context}\nUser: {req.message}"
    answer = ask(prompt)
    db.add(Memory(user_id=user.id, content=f"{user.name} ({user.email}): {req.message}", embedding=vector))
    db.commit()
    return {"answer": answer}


@app.get("/users/search")
def search_users(email: str, db: Session = Depends(get_db)):
    rows = db.execute(text(f"SELECT id, name FROM users WHERE email = '{email}'")).fetchall()
    return [{"id": r.id, "name": r.name} for r in rows]


@app.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    # Only removes the Postgres row: embeddings, the Redis profile and logs remain.
    db.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
    db.commit()
    return {"deleted": user_id}
