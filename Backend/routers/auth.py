"""
routers/auth.py  –  Signup / Login / Logout routes
Integrates with users + login_history tables.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from datetime import datetime, timezone

from database.db import get_db
from database.models import User, LoginHistory

router = APIRouter(prefix="/auth", tags=["auth"])

# ── password hashing ──────────────────────────────────────────────────────────
pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── Pydantic schemas ──────────────────────────────────────────────────────────
class SignupRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── helpers ───────────────────────────────────────────────────────────────────
def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0] if forwarded else (request.client.host if request.client else "unknown")


# ── routes ────────────────────────────────────────────────────────────────────
@router.post("/signup", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def signup(payload: SignupRequest, db: Session = Depends(get_db)):
    """Register a new user."""
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=pwd_ctx.hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=UserResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Authenticate user and log the attempt."""
    user = db.query(User).filter(User.username == payload.username).first()
    success = bool(user and pwd_ctx.verify(payload.password, user.password_hash))

    # always record the attempt
    if user:
        log = LoginHistory(
            user_id=user.id,
            ip_address=_get_client_ip(request),
            user_agent=request.headers.get("User-Agent", "")[:256],
            success=success,
        )
        db.add(log)
        db.commit()

    if not success:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return user


@router.get("/me/{user_id}", response_model=UserResponse)
def get_me(user_id: int, db: Session = Depends(get_db)):
    """Fetch user profile by ID."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user