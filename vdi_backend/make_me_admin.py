from app.db.database import SessionLocal
from app.models import User, UserRole

def make_admin():
    db = SessionLocal()
    # Find the first user (likely you)
    user = db.query(User).filter(User.email == "6rey6rey@gmail.com").first()
    
    if user:
        user.role = UserRole.admin
        db.commit()
        print(f"Success! User {user.email} is now an ADMIN.")
    else:
        print("User not found in DB.")
    
    db.close()

if __name__ == "__main__":
    make_admin()
