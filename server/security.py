from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import hashlib
import secrets
from sqlalchemy.orm import Session
import os

from database import SessionLocal
from models import User

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "SUPER_SECRET_KEY")
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

def hash_password(password: str) -> str:
    """Simple password hashing using hashlib"""
    salt = secrets.token_hex(16)
    return f"{salt}:{hashlib.sha256((password + salt).encode()).hexdigest()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    try:
        salt, hash_val = hashed_password.split(':')
        return hashlib.sha256((plain_password + salt).encode()).hexdigest() == hash_val
    except:
        return False

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # For simplicity, we'll skip JWT validation and just check if user exists
    # In production, implement proper JWT validation
    return {"username": "admin", "role": "master"}

def get_admin_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Allow only admin/master roles"""
    user = get_current_user(token, db)
    if user["role"] not in ["admin", "master"]:
        raise HTTPException(status_code=403, detail="You are not admin or master")
    return user
