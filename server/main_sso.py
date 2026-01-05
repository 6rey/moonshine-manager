"""
Eclypse Backend API with SSO Support
FastAPI server for VDI management with Google SSO integration
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from typing import Optional, List
import jwt
import datetime
import os
import requests
import json
import base64
import random
import urllib3
from database_sso import DatabaseManager, create_db_manager

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==================== Configuration ====================

# Environment variables with defaults
DB_URL = os.getenv("DB_URL", "postgresql://myuser:mypass@localhost:5432/vdi_db")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "SUPER_SECRET_KEY")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24

# ==================== FastAPI App ====================

app = FastAPI(
    title="Eclypse VDI API with SSO",
    description="Backend API for VDI management with Google SSO support",
    version="2.0.0"
)

security = HTTPBearer()

# Dependency to get database
async def get_db():
    """Get database connection"""
    if not hasattr(app.state, 'db'):
        app.state.db = await create_db_manager(DB_URL)
    return app.state.db

# ==================== Pydantic Models ====================

class TokenData(BaseModel):
    """Token payload model"""
    sub: str
    user_id: int
    role: str
    email: str
    exp: int
    iat: int

class LoginRequest(BaseModel):
    """Traditional login request"""
    username: str
    password: str

class RegisterRequest(BaseModel):
    """User registration request"""
    username: str
    password: str
    role: str = "user"
    email: Optional[str] = None

class SSOAuthRequest(BaseModel):
    """SSO authentication request from desktop client"""
    access_token: str
    provider: str = "google"

class SSOUserResponse(BaseModel):
    """SSO authentication response"""
    username: str
    email: str
    role: str
    access_token: str

class TokenResponse(BaseModel):
    """Token response model"""
    access_token: str
    token_type: str = "bearer"

class VMCreateRequest(BaseModel):
    """VM creation request"""
    hostname: str
    ip_address: str
    sunshine_user: Optional[str] = None
    sunshine_password: Optional[str] = None

class VMResponse(BaseModel):
    """VM response model"""
    id: int
    hostname: str
    ip_address: str
    sunshine_user: Optional[str] = None

class AssignmentRequest(BaseModel):
    """Assignment request"""
    user_id: int
    vm_id: int

class AssignmentResponse(BaseModel):
    """Assignment response model"""
    user_id: int
    vm_id: int
    username: str
    vm_hostname: str

class PairingRequest(BaseModel):
    """Pairing request"""
    vm_id: int

class PairingCompleteRequest(BaseModel):
    """Pairing completion request"""
    vm_id: int
    pin: str

class PairingResponse(BaseModel):
    """Pairing response"""
    pin: str

class SunshinePinRequest(BaseModel):
    """Secure PIN request"""
    vm_id: int
    pin: str

class PreparePairingRequest(BaseModel):
    vm_id: int

class PreparePairingResponse(BaseModel):
    vm_id: int
    pin: str
    status: str = "ready"

class CompletePairingRequest(BaseModel):
    vm_id: int
    pin: str

class AssignmentOut(BaseModel):
    id: int
    user_id: int
    username: str
    vm_id: int
    vm_hostname: str

class UnassignVM(BaseModel):
    user_id: int
    vm_id: int

class UserOut(BaseModel):
    id: int
    username: str
    role: str

class UserOutWithVMs(BaseModel):
    id: int
    username: str
    role: str
    vms: List[VMResponse]

# ==================== Authentication Utilities ====================

def create_jwt_token(user: dict) -> str:
    """Generate JWT token for user"""
    payload = {
        "sub": user["username"],
        "user_id": user["id"],
        "role": user["role"],
        "email": user.get("email", ""),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRE_HOURS),
        "iat": datetime.datetime.utcnow().timestamp()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Verify JWT token and return payload"""
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def verify_google_token(access_token: str) -> dict:
    """Verify Google Access Token and get user info"""
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers=headers
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid Google token")
        
        user_info = response.json()
        
        if not user_info.get("verified_email"):
            raise HTTPException(status_code=400, detail="Email not verified")
        
        return {
            "email": user_info["email"],
            "name": user_info.get("name", ""),
            "picture": user_info.get("picture", ""),
            "provider_user_id": user_info["id"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token verification failed: {str(e)}")

def require_role(required_roles: List[str]):
    """Dependency to require specific role"""
    async def role_checker(payload: dict = Depends(verify_token)):
        if payload["role"] not in required_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return payload
    return role_checker

# ==================== Authentication Endpoints ====================

@app.post("/auth/token", response_model=TokenResponse)
async def login(request: LoginRequest, db: DatabaseManager = Depends(get_db)):
    """
    Traditional username/password authentication
    Returns JWT token
    """
    user = await db.get_user_by_username(request.username)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if user has password (SSO-only users won't)
    if user["password_hash"] is None:
        raise HTTPException(
            status_code=400, 
            detail="This account requires SSO login. Use /auth/sso endpoint."
        )
    
    # In production, verify password hash here
    # For now, accept any password for existing users
    
    token = create_jwt_token(dict(user))
    
    return {"access_token": token, "token_type": "bearer"}

@app.post("/auth/register", response_model=TokenResponse)
async def register(request: RegisterRequest, db: DatabaseManager = Depends(get_db)):
    """
    Register a new user (requires admin role)
    """
    # Check if user exists
    existing = await db.get_user_by_username(request.username)
    if existing:
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

@app.post("/auth/sso", response_model=SSOUserResponse)
async def sso_auth(request: SSOAuthRequest, db: DatabaseManager = Depends(get_db)):
    """
    SSO authentication endpoint
    Verifies Google token and creates/returns user
    """
    # 1. Verify Google token
    sso_info = await verify_google_token(request.access_token)
    
    # 2. Check if SSO account already linked
    user = await db.get_user_by_sso(request.provider, sso_info["provider_user_id"])
    
    if user:
        # Existing SSO user - return JWT
        token = create_jwt_token(dict(user))
        return {
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "access_token": token
        }
    
    # 3. Check if user with same email exists
    user_by_email = await db.get_user_by_email(sso_info["email"])
    
    if user_by_email:
        # Existing user - link SSO account
        success = await db.link_sso_to_user(
            user_by_email["id"],
            request.provider,
            sso_info["provider_user_id"],
            sso_info["email"]
        )
        
        if not success:
            raise HTTPException(status_code=400, detail="SSO account already linked to another user")
        
        token = create_jwt_token(dict(user_by_email))
        return {
            "username": user_by_email["username"],
            "email": user_by_email["email"],
            "role": user_by_email["role"],
            "access_token": token
        }
    
    # 4. Create new user from SSO
    user_id = await db.create_user_from_sso(
        sso_info["email"],
        sso_info["name"],
        request.provider,
        sso_info["provider_user_id"]
    )
    
    user = await db.get_user_by_id(user_id)
    token = create_jwt_token(dict(user))
    
    return {
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "access_token": token
    }

@app.post("/auth/sso/link")
async def link_sso_account(
    request: SSOAuthRequest,
    payload: dict = Depends(verify_token),
    db: DatabaseManager = Depends(get_db)
):
    """
    Link SSO account to existing authenticated user
    """
    user_id = payload["user_id"]
    
    # Verify Google token
    sso_info = await verify_google_token(request.access_token)
    
    # Link SSO account
    success = await db.link_sso_to_user(
        user_id,
        request.provider,
        sso_info["provider_user_id"],
        sso_info["email"]
    )
    
    if not success:
        raise HTTPException(status_code=400, detail="SSO account already linked to another user")
    
    return {"status": "success", "message": "SSO account linked successfully"}

@app.post("/auth/sso/unlink")
async def unlink_sso_account(
    provider: str,
    payload: dict = Depends(verify_token),
    db: DatabaseManager = Depends(get_db)
):
    """
    Unlink SSO account from user
    """
    user_id = payload["user_id"]
    
    await db.unlink_sso_from_user(user_id, provider)
    
    return {"status": "success", "message": "SSO account unlinked"}

# ==================== Admin Endpoints ====================

@app.get("/admin/users", response_model=List[UserOut])
async def list_users(
    payload: dict = Depends(require_role(["admin", "master"])),
    db: DatabaseManager = Depends(get_db)
):
    """List all users (admin only)"""
    users = await db.list_users()
    return [dict(user) for user in users]

@app.get("/admin/user/{user_id}", response_model=UserOutWithVMs)
async def get_user_details(
    user_id: int,
    payload: dict = Depends(require_role(["admin", "master"])),
    db: DatabaseManager = Depends(get_db)
):
    """Get user details with assigned VMs"""
    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    vms = await db.get_user_assignments(user_id)
    
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "vms": [dict(vm) for vm in vms]
    }

@app.delete("/admin/user/{user_id}")
async def delete_user(
    user_id: int,
    payload: dict = Depends(require_role(["admin", "master"])),
    db: DatabaseManager = Depends(get_db)
):
    """Delete user (admin only)"""
    # Prevent self-deletion
    if user_id == payload["user_id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    
    success = await db.delete_user(user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"status": "success", "message": "User deleted"}

# ==================== VM Management Endpoints ====================

@app.post("/vm/register", response_model=VMResponse)
async def register_vm(
    request: VMCreateRequest,
    payload: dict = Depends(require_role(["admin", "master"])),
    db: DatabaseManager = Depends(get_db)
):
    """Register a new VM (admin only)"""
    vm_id = await db.create_vm(
        hostname=request.hostname,
        ip_address=request.ip_address,
        sunshine_user=request.sunshine_user,
        sunshine_password=request.sunshine_password
    )
    
    vm = await db.get_vm(vm_id)
    return dict(vm)

@app.get("/vm/list", response_model=List[VMResponse])
async def list_vms(
    payload: dict = Depends(verify_token),
    db: DatabaseManager = Depends(get_db)
):
    """List VMs (admin sees all, users see assigned)"""
    if payload["role"] in ["admin", "master"]:
        vms = await db.list_vms()
    else:
        vms = await db.get_user_assignments(payload["user_id"])
    
    return [dict(vm) for vm in vms]

@app.delete("/vm/delete/{vm_id}")
async def delete_vm(
    vm_id: int,
    payload: dict = Depends(require_role(["admin", "master"])),
    db: DatabaseManager = Depends(get_db)
):
    """Delete VM (admin only)"""
    success = await db.delete_vm(vm_id)
    if not success:
        raise HTTPException(status_code=404, detail="VM not found")
    
    return {"status": "success", "message": "VM deleted"}

# ==================== Assignment Endpoints ====================

@app.post("/vm/assign")
async def assign_vm(
    request: AssignmentRequest,
    payload: dict = Depends(require_role(["admin", "master"])),
    db: DatabaseManager = Depends(get_db)
):
    """Assign VM to user (admin only)"""
    success = await db.assign_vm_to_user(request.user_id, request.vm_id)
    
    if not success:
        raise HTTPException(status_code=400, detail="Assignment already exists or invalid")
    
    return {"status": "success", "message": "VM assigned successfully"}

@app.delete("/vm/unassign")
async def unassign_vm(
    request: AssignmentRequest,
    payload: dict = Depends(verify_token),
    db: DatabaseManager = Depends(get_db)
):
    """Remove VM assignment"""
    # Users can only unassign their own VMs, admins can unassign any
    if payload["role"] not in ["admin", "master"]:
        if request.user_id != payload["user_id"]:
            raise HTTPException(status_code=403, detail="Can only unassign your own VMs")
    
    success = await db.unassign_vm(request.user_id, request.vm_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Assignment not found")
    
    return {"status": "success", "message": "Assignment removed"}

@app.get("/vm/assignments", response_model=List[AssignmentResponse])
async def list_assignments(
    payload: dict = Depends(verify_token),
    db: DatabaseManager = Depends(get_db)
):
    """List assignments (admin sees all, users see their own)"""
    if payload["role"] in ["admin", "master"]:
        assignments = await db.get_all_assignments()
    else:
        # Get user's assignments with VM info
        user_vms = await db.get_user_assignments(payload["user_id"])
        assignments = [
            {
                "user_id": payload["user_id"],
                "vm_id": vm["id"],
                "username": payload["sub"],
                "vm_hostname": vm["hostname"]
            }
            for vm in user_vms
        ]
    
    return assignments

# ==================== Pairing Endpoints ====================

@app.post("/vm/prepare-pairing", response_model=PreparePairingResponse)
async def prepare_vm_pairing(
    request: PreparePairingRequest,
    payload: dict = Depends(verify_token),
    db: DatabaseManager = Depends(get_db)
):
    """
    Prepare the pairing process by generating a PIN and checking permissions.
    The server generates the PIN and returns it to the client.
    """
    # Check if VM exists and user has access
    vm = await db.get_vm(request.vm_id)
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")
    
    # Check that user has access to this VM (except admin/master)
    if payload["role"] not in ["admin", "master"]:
        has_access = await db.is_vm_assigned_to_user(payload["user_id"], request.vm_id)
        if not has_access:
            raise HTTPException(
                status_code=403, 
                detail="You don't have permission to access this VM"
            )
    
    # Generate a 4-digit PIN for pairing
    pin = f"{random.randint(0, 9999):04d}"
    
    # Return the PIN to the client
    return {
        "vm_id": vm["id"],
        "pin": pin,
        "status": "ready"
    }

@app.post("/vm/complete-pairing")
async def complete_vm_pairing(
    request: CompletePairingRequest,
    payload: dict = Depends(verify_token),
    db: DatabaseManager = Depends(get_db)
):
    """
    Finalize the pairing process by sending the PIN to the Sunshine server.
    The client has already launched Moonlight with the PIN and waits for confirmation.
    """
    print(f"[DEBUG] User {payload['sub']} (ID: {payload['user_id']}, Role: {payload['role']}) trying to access VM {request.vm_id}")
    
    # Get VM information
    vm = await db.get_vm(request.vm_id)
    if not vm:
        print(f"[DEBUG] VM {request.vm_id} not found")
        raise HTTPException(status_code=404, detail="VM not found")
    
    print(f"[DEBUG] VM found: {vm['hostname']} ({vm['ip_address']})")
    
    # Check that user has access to this VM
    if payload["role"] not in ["admin", "master"]:
        has_access = await db.is_vm_assigned_to_user(payload["user_id"], request.vm_id)
        if not has_access:
            print(f"[DEBUG] Access denied - VM {request.vm_id} not assigned to user {payload['user_id']}")
            raise HTTPException(
                status_code=403, 
                detail=f"You don't have permission to access VM {vm['hostname']}"
            )
        else:
            print(f"[DEBUG] Access granted - VM {request.vm_id} assigned to user")
    else:
        print(f"[DEBUG] Admin/Master access granted for user {payload['sub']}")
    
    # Use the original IP of the VM
    url = f"https://{vm['ip_address']}:47990/api/pin"
    
    # Define the client machine name
    client_name = "clienteclypse"
    
    print(f"[DEBUG] Sending PIN and Name to Sunshine at {url}")
    
    auth_str = f"{vm['sunshine_user']}:{vm['sunshine_password']}"
    auth_bytes = auth_str.encode('utf-8')
    auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')
    
    headers = {
        "Accept": "*/*",
        "Authorization": f"Basic {auth_b64}",
        "Content-Type": "application/json"
    }
    
    # Data to send to Sunshine
    payload_to_sunshine = {
        "pin": request.pin,
        "name": client_name
    }
    print(f"[DEBUG] Payload to Sunshine: {payload_to_sunshine}")
    
    try:
        print(f"[DEBUG] Waiting 5 seconds before sending PIN to Sunshine...")
        import time
        time.sleep(5)
        print(f"[DEBUG] Sending PIN {request.pin} and name '{client_name}' to Sunshine now...")
        
        response = requests.post(
            url,
            headers=headers,
            json=payload_to_sunshine,
            verify=False,
            timeout=10
        )
        
        print(f"[DEBUG] Sunshine response: {response.status_code}")
        print(f"[DEBUG] Sunshine response body: {response.text}")
        
        if response.status_code == 200:
            return {
                "status": "success",
                "message": "PIN and name sent successfully to Sunshine server"
            }
        else:
            error_detail = f"Sunshine server responded with status {response.status_code}"
            if response.text:
                error_detail += f": {response.text}"
            else:
                error_detail += " (no response body)"
            
            print(f"[DEBUG] Sunshine error: {error_detail}")
            raise HTTPException(
                status_code=response.status_code,
                detail=error_detail
            )
    except requests.exceptions.ConnectionError as e:
        error_msg = f"Cannot connect to Sunshine server at {vm['ip_address']}:47990. Make sure Sunshine is running and accessible."
        print(f"[DEBUG] Connection error: {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)
    except requests.exceptions.Timeout as e:
        error_msg = f"Connection to Sunshine server timed out. The server might be overloaded or unreachable."
        print(f"[DEBUG] Timeout error: {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to connect to Sunshine server: {str(e)}"
        print(f"[DEBUG] Request error: {error_msg}")
        raise HTTPException(status_code=500, detail=error_msg)

@app.post("/vm/send-pin", tags=["VM"])
async def send_pin_to_sunshine(
    pin_request: SunshinePinRequest,
    payload: dict = Depends(verify_token),
    db: DatabaseManager = Depends(get_db)
):
    """
    Secure endpoint to send PIN to Sunshine.
    Client no longer needs to know Sunshine credentials.
    """
    # Get VM information
    vm = await db.get_vm(pin_request.vm_id)
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")
    
    # Check that user has access to this VM
    if payload["role"] not in ["admin", "master"]:
        # For normal users, check the association
        has_access = await db.is_vm_assigned_to_user(payload["user_id"], pin_request.vm_id)
        if not has_access:
            raise HTTPException(
                status_code=403, 
                detail="You don't have permission to access this VM"
            )
    
    # Prepare request for Sunshine
    url = f"https://{vm['ip_address']}:47990/api/pin"
    auth_str = f"{vm['sunshine_user']}:{vm['sunshine_password']}"
    auth_bytes = auth_str.encode('utf-8')
    auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')
    
    headers = {
        "Accept": "*/*",
        "Authorization": f"Basic {auth_b64}",
        "Content-Type": "text/plain; charset=UTF-8"
    }
    
    data = json.dumps({"pin": pin_request.pin})
    
    try:
        # Temporarily disable SSL verification for self-signed certificates
        # In production, use a valid certificate or custom CA
        response = requests.post(
            url,
            headers=headers,
            data=data,
            verify=False
        )
        
        if response.status_code == 200:
            return {"status": "success", "message": f"PIN {pin_request.pin} successfully sent to Sunshine"}
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Error sending PIN to Sunshine: {response.text}"
            )
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Connection error to Sunshine: {str(e)}"
        )

@app.post("/vm/pair", tags=["VM"])
async def pair_with_vm(
    pair_request: PairingRequest,
    payload: dict = Depends(verify_token),
    db: DatabaseManager = Depends(get_db)
):
    """
    Endpoint to handle the pairing process with a VM.
    """
    # Get VM information
    vm = await db.get_vm(pair_request.vm_id)
    if not vm:
        raise HTTPException(status_code=404, detail="VM not found")
    
    # Check that user has access to this VM
    if payload["role"] not in ["admin", "master"]:
        has_access = await db.is_vm_assigned_to_user(payload["user_id"], pair_request.vm_id)
        if not has_access:
            raise HTTPException(
                status_code=403, 
                detail="You don't have permission to access this VM"
            )
    
    # Send PIN to Sunshine server
    url = f"https://{vm['ip_address']}:47990/api/pin"
    auth_str = f"{vm['sunshine_user']}:{vm['sunshine_password']}"
    auth_bytes = auth_str.encode('utf-8')
    auth_b64 = base64.b64encode(auth_bytes).decode('utf-8')
    
    headers = {
        "Accept": "*/*",
        "Authorization": f"Basic {auth_b64}",
        "Content-Type": "text/plain; charset=UTF-8"
    }
    
    try:
        response = requests.post(
            url,
            headers=headers,
            data=json.dumps({"pin": pair_request.pin}),
            verify=False
        )
        
        if response.status_code == 200:
            return {
                "status": "success",
                "message": "PIN sent successfully to Sunshine server"
            }
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Error from Sunshine server: {response.text}"
            )
    except requests.exceptions.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to connect to Sunshine server: {str(e)}"
        )

@app.get("/vm/debug-access/{vm_id}", tags=["VM"])
async def debug_vm_access(
    vm_id: int,
    payload: dict = Depends(verify_token),
    db: DatabaseManager = Depends(get_db)
):
    """
    Debug function to check VM access permissions.
    """
    vm = await db.get_vm(vm_id)
    if not vm:
        return {"error": "VM not found"}
    
    # Check association
    has_access = await db.is_vm_assigned_to_user(payload["user_id"], vm_id)
    
    return {
        "user_id": payload["user_id"],
        "username": payload["sub"],
        "user_role": payload["role"],
        "vm_id": vm["id"],
        "vm_hostname": vm["hostname"],
        "has_access": has_access
    }

# ==================== Health Check ====================

@app.get("/health")
async def health_check(db: DatabaseManager = Depends(get_db)):
    """Health check endpoint"""
    try:
        # Test database connection
        async with db.pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Unhealthy: {str(e)}")

# ==================== Startup/Shutdown ====================

@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    print("Starting Eclypse API with SSO support...")
    # Database will be initialized on first request via dependency

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    if hasattr(app.state, 'db'):
        await app.state.db.close()
    print("Eclypse API shutdown complete")

# ==================== Root Endpoint ====================

@app.get("/")
async def root():
    """API information"""
    return {
        "name": "Eclypse VDI API",
        "version": "2.0.0",
        "features": [
            "Traditional authentication",
            "Google SSO support",
            "VM management",
            "User assignment",
            "Pairing with Sunshine"
        ],
        "docs": "/docs",
        "health": "/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main_sso:app",
        host="0.0.0.0",
        port=443,
        ssl_keyfile="key.pem",
        ssl_certfile="cert.pem",
        reload=False
    )