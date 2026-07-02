import enum
from sqlalchemy import Column, Integer, String, ForeignKey, Enum, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.db.base import Base

class UserRole(str, enum.Enum):
    admin = "admin"
    user = "user"

class MachineStatus(str, enum.Enum):
    online = "online"
    offline = "offline"
    in_use = "in_use"

class Group(Base):
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    netbird_group_id = Column(String, nullable=True)

    users = relationship("User", back_populates="group")
    machines = relationship("Machine", back_populates="group")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    google_sub = Column(String, unique=True, index=True, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.user)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    netbird_user_id = Column(String, nullable=True)
    netbird_group_id = Column(String, nullable=True)

    group = relationship("Group", back_populates="users")
    machines = relationship("Machine", back_populates="user")

class Machine(Base):
    __tablename__ = "machines"
    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, index=True, nullable=False)
    netbird_ip = Column(String, unique=True, index=True)
    status = Column(Enum(MachineStatus), default=MachineStatus.offline)
    
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True) # Personal PC
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=True) # Pool PC
    
    netbird_host_group_id = Column(String, nullable=True)
    netbird_policy_id = Column(String, nullable=True)
    
    sunshine_port = Column(Integer, default=47990)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="machines")
    group = relationship("Group", back_populates="machines")
