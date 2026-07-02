import requests
from app.db.database import SessionLocal
from app.models import User, UserRole
from app.core.security import create_access_token

# 1. Create a dummy admin user in DB
db = SessionLocal()
admin_user = db.query(User).filter(User.email == "test_admin@example.com").first()
if not admin_user:
    admin_user = User(email="test_admin@example.com", google_sub="test_sub_123", role=UserRole.admin)
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)

print(f"Admin User ID: {admin_user.id}")

# 2. Generate token
token = create_access_token(
    data={"sub": admin_user.email, "role": admin_user.role, "id": admin_user.id}
)
print(f"Generated Token: {token}")

# 3. Test API endpoint
cookies = {"access_token": f"Bearer {token}"}
response = requests.get("http://127.0.0.1:8000/api/users", cookies=cookies)
print(f"Response Status: {response.status_code}")
print(f"Response Body: {response.text}")
