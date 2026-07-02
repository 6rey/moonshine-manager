from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.models import User
from app.api.dependencies import get_admin_user
from pydantic import BaseModel

router = APIRouter(prefix="/users", tags=["users"])

class UserUpdateRole(BaseModel):
    role: str

class UserUpdateGroup(BaseModel):
    group_id: int | None

@router.get("")
def list_users(db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
    users = db.query(User).all()
    return users

@router.put("/{user_id}/role")
def update_user_role(user_id: int, payload: UserUpdateRole, db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.role = payload.role
    db.commit()
    return {"message": "Role updated"}

@router.put("/{user_id}/group")
def update_user_group(user_id: int, payload: UserUpdateGroup, db: Session = Depends(get_db), current_user: User = Depends(get_admin_user)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.group_id = payload.group_id
    db.commit()
    return {"message": "Group updated"}
