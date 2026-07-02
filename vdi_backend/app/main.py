from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from app.core.config import settings
from app.api.routes import auth
from app.db.database import engine
from app.db.base import Base
from app.models import __init__  # To ensure models are loaded before create_all

# Create DB tables (In production, use Alembic migrations instead)
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.PROJECT_NAME)

from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import auth, users, groups, machines, agent

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authlib requires session middleware to store the OAuth state
app.add_middleware(
    SessionMiddleware, 
    secret_key=settings.SESSION_SECRET
)

# Include Routers
app.include_router(auth.router)
app.include_router(users.router, prefix="/api")
app.include_router(groups.router, prefix="/api")
app.include_router(machines.router, prefix="/api")
app.include_router(agent.router, prefix="/api")

@app.get("/")
def read_root():
    return {"message": "Welcome to VDI Backend API. Go to /docs for Swagger UI."}
