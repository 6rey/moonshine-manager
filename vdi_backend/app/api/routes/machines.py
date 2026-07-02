from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models import Machine, User, Group, MachineStatus
from app.api.dependencies import get_admin_user
from pydantic import BaseModel
from app.services.netbird_client import netbird

router = APIRouter(prefix="/machines", tags=["machines"])

class MachineCreate(BaseModel):
    hostname: str
    netbird_ip: str | None = None
    user_id: int | None = None
    group_id: int | None = None

class MachineAssign(BaseModel):
    user_id: int | None = None
    group_id: int | None = None

@router.get("")
def list_machines(db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
    machines = db.query(Machine).all()
    return machines

@router.post("")
def create_machine(payload: MachineCreate, db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
    machine = Machine(
        hostname=payload.hostname,
        netbird_ip=payload.netbird_ip
    )
    db.add(machine)
    db.commit()
    db.refresh(machine)
    return machine

@router.put("/{machine_id}/assign")
async def assign_machine(machine_id: int, payload: MachineAssign, db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")

    # If reassigning, delete old policy
    if machine.netbird_policy_id:
        await netbird.delete_policy(machine.netbird_policy_id)
        machine.netbird_policy_id = None
        db.commit()

    if payload.user_id is None and payload.group_id is None:
        machine.user_id = None
        machine.group_id = None
        db.commit()
        return machine

    # Create host group in Netbird if not exists
    if not machine.netbird_host_group_id:
        host_group_id = await netbird.create_group(f"Host: {machine.hostname}")
        if host_group_id:
            machine.netbird_host_group_id = host_group_id
            db.commit()

    if payload.user_id:
        user = db.query(User).filter(User.id == payload.user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        if not user.netbird_user_id:
            user.netbird_user_id = await netbird.get_user_by_email(user.email)
            if not user.netbird_user_id:
                raise HTTPException(status_code=400, detail=f"User {user.email} not found in Netbird. Has the user logged into Netbird client?")
            db.commit()

        if not user.netbird_group_id:
            user.netbird_group_id = await netbird.create_group(f"User: {user.email}")
            db.commit()

        await netbird.update_user_auto_groups(user.netbird_user_id, [user.netbird_group_id])

        policy_id = await netbird.create_policy(f"Access: {user.email} -> {machine.hostname}", [user.netbird_group_id], [machine.netbird_host_group_id])
        machine.netbird_policy_id = policy_id
        machine.user_id = user.id
        machine.group_id = None
        db.commit()
        
    elif payload.group_id:
        group = db.query(Group).filter(Group.id == payload.group_id).first()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        if not group.netbird_group_id:
            group.netbird_group_id = await netbird.create_group(f"Pool: {group.name}")
            db.commit()

        policy_id = await netbird.create_policy(f"Access: Pool {group.name} -> {machine.hostname}", [group.netbird_group_id], [machine.netbird_host_group_id])
        machine.netbird_policy_id = policy_id
        machine.user_id = None
        machine.group_id = group.id
        db.commit()

    db.refresh(machine)
    return machine

@router.delete("/{machine_id}")
async def delete_machine(machine_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
    machine = db.query(Machine).filter(Machine.id == machine_id).first()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")
        
    if machine.netbird_policy_id:
        await netbird.delete_policy(machine.netbird_policy_id)
        
    db.delete(machine)
    db.commit()
    return {"message": "Machine deleted"}
