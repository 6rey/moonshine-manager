#!/usr/bin/env python3
"""
Eclypse Server with Google SSO Support
FastAPI backend for VDI management with SSO authentication
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import Optional, List
import jwt
import datetime
import os
import asyncio

# Import database manager
from database_sso import DatabaseManager

# --- Configuration ---
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "SUPER_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# --- Pydantic Models ---
class UserCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    role: str = "user"

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class SSOAuthRequest(BaseModel):
    access_token: str
    provider: str = "google"

class SSOUserResponse(BaseModel):
    username: str
    email: str
    role: str
    access_token: str

class VMCreate(BaseModel):
    hostname: str
    ip_address: str
    sunshine_user: str
    sunshine_password: str

class VMAssign(BaseModel):
    user_id: int
    vm_id: int

class UnassignRequest(BaseModel):
    user_id: int
    vm_id: int

class PairingRequest(BaseModel):
    vm_id: int

class CompletePairingRequest(BaseModel):
    vm_id: int
    pin: str

# --- FastAPI App ---
app = FastAPI(title="Eclypse SSO Server", version="1.0.0")

# --- Database Manager Instance ---
db_manager = None

async def get_db():
    """Dependency to get database manager"""
    global db_manager
    if db_manager is None:
        db_manager = DatabaseManager()
        await db_manager.initialize()
    return db_manager

# --- JWT Token Functions ---
def create_jwt_token(user_data: dict) -> str:
    """Create JWT token from user data"""
    payload = {
        "sub": user_data.get("username"),
        "user_id": user_data.get("id"),
        "role": user_data.get("role"),
        "email": user_data.get("email", ""),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt_token(token: str) -> dict:
    """Decode JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- Authentication Endpoints ---

@app.post("/auth/register", response_model=Token)
async def register(request: UserCreate, db: DatabaseManager = Depends(get_db)):
    """Register a new user"""
    # Check if username exists
    existing_user = await db.get_user_by_username(request.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    if request.email:
        existing_email = await db.get_user_by_email(request.email)
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already exists")
    
    # Create user (in production, hash the password)
    user_id = await db.create_user(
        username=request.username,
        email=request.email,
        password_hash=request.password,  # In production: hash this!
        role=request.role
    )
    
    user = await db.get_user_by_id(user_id)
    token = create_jwt_token(dict(user))
    
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/token", response_model=Token)
async def login(request: UserLogin, db: DatabaseManager = Depends(get_db)):
    """Login with username/password"""
    user = await db.get_user_by_username(request.username)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # In production, verify password hash
    # For now, simple check
    stored_password = user.get("password_hash")
    if stored_password != request.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt_token(dict(user))
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/sso", response_model=SSOUserResponse)
async def sso_auth(request: SSOAuthRequest, db: DatabaseManager = Depends(get_db)):
    """SSO authentication endpoint"""
    # In production, verify Google token with Google API
    # For now, we'll simulate SSO authentication
    
    # Get user info from Google token (simulated)
    # In real implementation, verify token with Google
    user_info = {
        "email": "user@example.com",  # Would come from Google
        "name": "SSO User"  # Would come from Google
    }
    
    # Check if user exists with this email
    user = await db.get_user_by_email(user_info["email"])
    
    if not user:
        # Auto-create user
        user_id = await db.create_user(
            username=user_info["name"].replace(" ", "_").lower(),
            email=user_info["email"],
            password_hash="SSO",  # No password for SSO users
            role="user"
        )
        user = await db.get_user_by_id(user_id)
    
    # Generate JWT
    token = create_jwt_token(dict(user))
    
    return {
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "access_token": token
    }

@app.post("/auth/sso/link")
async def link_sso(request: SSOAuthRequest, token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token")), db: DatabaseManager = Depends(get_db)):
    """Link SSO account to existing user"""
    # Decode current token
    payload = decode_jwt_token(token)
    user_id = payload["user_id"]
    
    # Verify SSO token and get user info (simulated)
    # In real implementation, verify with Google
    
    # Link SSO account
    await db.link_sso_account(
        user_id=user_id,
        provider=request.provider,
        provider_user_id="google_user_id",  # Would come from Google
        email="user@example.com"  # Would come from Google
    )
    
    return {"status": "success", "message": "SSO account linked"}

@app.post("/auth/sso/unlink")
async def unlink_sso(provider: str, token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token")), db: DatabaseManager = Depends(get_db)):
    """Unlink SSO account"""
    payload = decode_jwt_token(token)
    user_id = payload["user_id"]
    
    await db.unlink_sso_account(user_id, provider)
    
    return {"status": "success", "message": "SSO account unlinked"}

# --- Admin Endpoints ---

@app.get("/admin/users")
async def get_users(token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token")), db: DatabaseManager = Depends(get_db)):
    """Get all users (admin only)"""
    payload = decode_jwt_token(token)
    if payload["role"] not in ["admin", "master"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users = await db.get_all_users()
    return users

@app.delete("/admin/user/{user_id}")
async def delete_user(user_id: int, token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token")), db: DatabaseManager = Depends(get_db)):
    """Delete user (admin only)"""
    payload = decode_jwt_token(token)
    if payload["role"] not in ["admin", "master"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Prevent self-deletion
    if payload["user_id"] == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    await db.delete_user(user_id)
    return {"status": "success", "message": "User deleted"}

# --- VM Management Endpoints ---

@app.get("/vm/list")
async def get_vms(token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token")), db: DatabaseManager = Depends(get_db)):
    """Get VM list"""
    payload = decode_jwt_token(token)
    user_id = payload["user_id"]
    role = payload["role"]
    
    if role in ["admin", "master"]:
        vms = await db.get_all_vms()
    else:
        vms = await db.get_user_vms(user_id)
    
    return vms

@app.post("/vm/register")
async def register_vm(request: VMCreate, token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token")), db: DatabaseManager = Depends(get_db)):
    """Register a new VM"""
    payload = decode_jwt_token(token)
    if payload["role"] not in ["admin", "master"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    vm_id = await db.create_vm(
        hostname=request.hostname,
        ip_address=request.ip_address,
        sunshine_user=request.sunshine_user,
        sunshine_password=request.sunshine_password
    )
    
    return {"status": "success", "vm_id": vm_id}

@app.delete("/vm/delete/{vm_id}")
async def delete_vm(vm_id: int, token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token")), db: DatabaseManager = Depends(get_db)):
    """Delete a VM"""
    payload = decode_jwt_token(token)
    if payload["role"] not in ["admin", "master"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    await db.delete_vm(vm_id)
    return {"status": "success", "message": "VM deleted"}

@app.post("/vm/assign")
async def assign_vm(request: VMAssign, token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token")), db: DatabaseManager = Depends(get_db)):
    """Assign VM to user"""
    payload = decode_jwt_token(token)
    if payload["role"] not in ["admin", "master"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    await db.assign_vm_to_user(request.user_id, request.vm_id)
    return {"status": "success", "msg": "VM assigned successfully"}

@app.delete("/vm/unassign")
async def unassign_vm(request: UnassignRequest, token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token")), db: DatabaseManager = Depends(get_db)):
    """Unassign VM from user"""
    payload = decode_jwt_token(token)
    if payload["role"] not in ["admin", "master"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    await db.unassign_vm_from_user(request.user_id, request.vm_id)
    return {"status": "success", "msg": "Assignment deleted successfully"}

@app.get("/vm/assignments")
async def get_assignments(token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token")), db: DatabaseManager = Depends(get_db)):
    """Get all VM assignments"""
    payload = decode_jwt_token(token)
    if payload["role"] not in ["admin", "master"]:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    assignments = await db.get_all_assignments()
    return assignments

# --- Pairing Endpoints ---

@app.post("/vm/prepare-pairing")
async def prepare_pairing(request: PairingRequest, token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token")), db: DatabaseManager = Depends(get_db)):
    """Prepare pairing - generate PIN"""
    payload = decode_jwt_token(token)
    
    # Get VM info
    vm = await db.get_vm_by_id(request.vm_id)
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")
    
    # In production, this would communicate with Sunshine to generate PIN
    # For now, generate a random PIN
    import random
    pin = str(random.randint(100000, 999999))
    
    # Store PIN temporarily (in production, use Redis or similar)
    # For now, just return it
    
    return {"pin": pin, "vm_id": request.vm_id}

@app.post("/vm/complete-pairing")
async def complete_pairing(request: CompletePairingRequest, token: str = Depends(OAuth2PasswordBearer(tokenUrl="/auth/token")), db: DatabaseManager = Depends(get_db)):
    """Complete pairing with Sunshine"""
    payload = decode_jwt_token(token)
    
    # In production, this would send the PIN to Sunshine
    # For now, just return success
    
    return {"status": "success", "message": "Pairing completed"}

# --- Health Check ---

@app.get("/")
async def root():
    return {"status": "ok", "message": "Eclypse SSO Server is running"}

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "eclypse-sso-server"}

# --- Startup Event ---

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    global db_manager
    db_manager = DatabaseManager()
    await db_manager.initialize()
    print("✅ Database initialized")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global db_manager
    if db_manager:
        await db_manager.close()
        print("✅ Database connection closed")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=443, ssl_keyfile="key.pem", ssl_certfile="cert.pem")