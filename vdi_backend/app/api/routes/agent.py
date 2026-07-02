from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.database import get_db
from app.models import Machine
from app.core.config import settings
from app.services.netbird_client import netbird

router = APIRouter(prefix="/agent", tags=["agent"])

class AgentEnrollRequest(BaseModel):
    hostname: str

def verify_agent_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Token")
    
    token = authorization.split(" ")[1]
    if token != settings.AGENT_SECRET_KEY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid Agent Token")
    return True

@router.post("/enroll")
async def enroll_agent(
    payload: AgentEnrollRequest, 
    db: Session = Depends(get_db), 
    _authorized: bool = Depends(verify_agent_token)
):
    # 1. Register or update PC in our DB
    machine = db.query(Machine).filter(Machine.hostname == payload.hostname).first()
    if not machine:
        machine = Machine(hostname=payload.hostname)
        db.add(machine)
        db.commit()
        db.refresh(machine)

    # 2. Create Netbird Group for this specific PC
    group_name = f"Host: {payload.hostname}"
    group_id = await netbird.create_group(group_name)
    if not group_id:
        raise HTTPException(status_code=500, detail="Failed to create Netbird group")

    # 3. Generate Setup Key bounded to this group
    key_name = f"Key for {payload.hostname}"
    setup_key = await netbird.create_setup_key(key_name, [group_id])
    if not setup_key:
        raise HTTPException(status_code=500, detail="Failed to generate Setup Key")

    # 4. Return to Agent
    return {
        "setup_key": setup_key,
        "machine_id": machine.id,
        "message": "Enrolled successfully"
    }
