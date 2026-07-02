from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models import Group, User
from app.api.dependencies import get_admin_user
from pydantic import BaseModel

router = APIRouter(prefix="/groups", tags=["groups"])

class GroupCreate(BaseModel):
    name: str

@router.get("")
def list_groups(db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
    groups = db.query(Group).all()
    return groups

@router.post("")
def create_group(payload: GroupCreate, db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
    group = Group(name=payload.name)
    db.add(group)
    db.commit()
    db.refresh(group)
    return group

@router.delete("/{group_id}")
def delete_group(group_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    db.delete(group)
    db.commit()
    return {"message": "Group deleted"}
