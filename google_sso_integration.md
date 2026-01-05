# Google SSO/SAML интеграция с серверной частью

## 🎯 Ключевая проблема

Твое правильное замечание! **Google SSO должен интегрироваться с существующей базой данных пользователей**, а не создавать параллельную систему.

## 🏗️ Полная архитектура интеграции

```
┌─────────────────────────────────────────────────────────────┐
│                    Eclypse Ecosystem                        │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐          ┌──────────────────┐
│ Desktop App  │          │   Backend API    │
│ (eclypse_en) │          │   (FastAPI)      │
└──────┬───────┘          └────────┬─────────┘
       │                           │
       │ 1. Google SSO Login       │
       │    (OAuth2/PKCE)          │
       │                           │
       │ 2. Send token to API      │
       │                           │
       │                           │ 3. Verify token
       │                           │     with Google
       │                           │
       │                           │ 4. Check DB:
       │                           │    - User exists?
       │                           │    - Link accounts
       │                           │
       │ 5. Receive JWT            │
       │    (with user role)       │
       │                           │
       └───────────────────────────┘
```

## 📋 Backend API изменения

### 1. **Новая таблица в БД** (если нужно)

```sql
-- Таблица для связки SSO аккаунтов
CREATE TABLE sso_accounts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    provider VARCHAR(50), -- 'google', 'microsoft', etc.
    provider_user_id VARCHAR(255),
    email VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

-- Добавить в users таблицу:
ALTER TABLE users ADD COLUMN sso_linked BOOLEAN DEFAULT FALSE;
```

### 2. **Новые API endpoints** (`server/main.py`)

```python
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import requests
import jwt
from datetime import datetime, timedelta
import asyncpg

app = FastAPI()
security = HTTPBearer()

class SSOAuthRequest(BaseModel):
    """Запрос от desktop клиента после Google SSO"""
    access_token: str  # Токен от Google
    provider: str = "google"

class SSOUserResponse(BaseModel):
    """Ответ с информацией о пользователе"""
    username: str
    email: str
    role: str
    access_token: str

# --- Вспомогательные функции ---

async def verify_google_token(access_token: str) -> dict:
    """Верификация Google Access Token и получение user info"""
    try:
        # Получаем информацию о пользователе от Google
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers=headers
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid Google token")
        
        user_info = response.json()
        
        # Проверяем email верификацию
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

async def get_or_create_user(db, sso_info: dict, provider: str):
    """
    Основная логика интеграции с существующей БД:
    1. Ищет пользователя по email
    2. Если не найден - создает нового
    3. Связывает SSO аккаунт
    4. Возвращает user объект
    """
    
    # 1. Проверяем, есть ли связанный SSO аккаунт
    sso_account = await db.fetchrow(
        """
        SELECT u.* FROM users u
        JOIN sso_accounts s ON u.id = s.user_id
        WHERE s.provider = $1 AND s.provider_user_id = $2
        """,
        provider, sso_info["provider_user_id"]
    )
    
    if sso_account:
        # SSO аккаунт уже связан с существующим пользователем
        return dict(sso_account)
    
    # 2. Проверяем, есть ли пользователь с таким email
    existing_user = await db.fetchrow(
        "SELECT * FROM users WHERE email = $1",
        sso_info["email"]
    )
    
    if existing_user:
        # Пользователь существует, связываем SSO
        await db.execute(
            """
            INSERT INTO sso_accounts (user_id, provider, provider_user_id, email)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT DO NOTHING
            """,
            existing_user["id"], provider, sso_info["provider_user_id"], sso_info["email"]
        )
        
        # Обновляем флаг в пользователе
        await db.execute(
            "UPDATE users SET sso_linked = TRUE WHERE id = $1",
            existing_user["id"]
        )
        
        return dict(existing_user)
    
    # 3. Создаем нового пользователя (авто-регистрация)
    username = sso_info["email"].split("@")[0]
    
    # Проверяем уникальность username
    counter = 1
    base_username = username
    while await db.fetchrow("SELECT id FROM users WHERE username = $1", username):
        username = f"{base_username}{counter}"
        counter += 1
    
    new_user_id = await db.execute(
        """
        INSERT INTO users (username, email, role, sso_linked, created_at)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id
        """,
        username, sso_info["email"], "user", True, datetime.utcnow()
    )
    
    # Создаем SSO связь
    await db.execute(
        """
        INSERT INTO sso_accounts (user_id, provider, provider_user_id, email)
        VALUES ($1, $2, $3, $4)
        """,
        new_user_id, provider, sso_info["provider_user_id"], sso_info["email"]
    )
    
    # Возвращаем нового пользователя
    return await db.fetchrow("SELECT * FROM users WHERE id = $1", new_user_id)

def generate_jwt_token(user: dict) -> str:
    """Генерация JWT токена для пользователя"""
    payload = {
        "sub": user["username"],
        "user_id": user["id"],
        "role": user["role"],
        "email": user["email"],
        "exp": datetime.utcnow() + timedelta(hours=24),
        "iat": datetime.utcnow()
    }
    
    return jwt.encode(payload, "SUPER_SECRET_KEY", algorithm="HS256")

# --- API Endpoints ---

@app.post("/auth/sso", response_model=SSOUserResponse)
async def sso_auth(
    request: SSOAuthRequest,
    db: asyncpg.Connection = Depends(get_db)
):
    """
    Основной endpoint для SSO аутентификации
    Вызывается из desktop приложения после успешного Google SSO
    """
    
    # 1. Верифицируем Google токен
    sso_info = await verify_google_token(request.access_token)
    
    # 2. Получаем или создаем пользователя в БД
    user = await get_or_create_user(db, sso_info, request.provider)
    
    # 3. Генерируем JWT для desktop приложения
    access_token = generate_jwt_token(user)
    
    # 4. Логируем успешную аутентификацию
    print(f"SSO login: {user['username']} ({request.provider})")
    
    return {
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "access_token": access_token
    }

@app.post("/auth/sso/link")
async def link_sso_account(
    request: SSOAuthRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: asyncpg.Connection = Depends(get_db)
):
    """
    Привязать SSO аккаунт к существующему пользователю
    Вызывается из профиля пользователя
    """
    
    # Декодируем JWT текущего пользователя
    try:
        payload = jwt.decode(credentials.credentials, "SUPER_SECRET_KEY", algorithms=["HS256"])
        user_id = payload["user_id"]
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Верифицируем Google токен
    sso_info = await verify_google_token(request.access_token)
    
    # Проверяем, не привязан ли уже к другому пользователю
    existing = await db.fetchrow(
        """
        SELECT user_id FROM sso_accounts 
        WHERE provider = $1 AND provider_user_id = $2
        """,
        request.provider, sso_info["provider_user_id"]
    )
    
    if existing and existing["user_id"] != user_id:
        raise HTTPException(status_code=400, detail="SSO account already linked to another user")
    
    # Создаем связь
    await db.execute(
        """
        INSERT INTO sso_accounts (user_id, provider, provider_user_id, email)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT DO NOTHING
        """,
        user_id, request.provider, sso_info["provider_user_id"], sso_info["email"]
    )
    
    # Обновляем флаг в пользователе
    await db.execute(
        "UPDATE users SET sso_linked = TRUE WHERE id = $1",
        user_id
    )
    
    return {"status": "success", "message": "SSO account linked successfully"}

@app.post("/auth/sso/unlink")
async def unlink_sso_account(
    provider: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: asyncpg.Connection = Depends(get_db)
):
    """
    Отвязать SSO аккаунт
    """
    
    try:
        payload = jwt.decode(credentials.credentials, "SUPER_SECRET_KEY", algorithms=["HS256"])
        user_id = payload["user_id"]
    except:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Удаляем связь
    await db.execute(
        "DELETE FROM sso_accounts WHERE user_id = $1 AND provider = $2",
        user_id, provider
    )
    
    # Проверяем, остались ли SSO аккаунты
    remaining = await db.fetchrow(
        "SELECT COUNT(*) as count FROM sso_accounts WHERE user_id = $1",
        user_id
    )
    
    if remaining["count"] == 0:
        await db.execute(
            "UPDATE users SET sso_linked = FALSE WHERE id = $1",
            user_id
        )
    
    return {"status": "success", "message": "SSO account unlinked"}
```

### 3. **Миграция существующих пользователей**

```python
# migration_script.py
"""
Для существующих пользователей с паролями:
- Добавить флаг sso_linked = FALSE
- Позволить привязать SSO в профиле
- Не ломать существующую аутентификацию
"""

async def migrate_users(db):
    # Добавить колонку если нет
    try:
        await db.execute("ALTER TABLE users ADD COLUMN sso_linked BOOLEAN DEFAULT FALSE")
    except:
        pass
    
    # Добавить таблицу SSO если нет
    try:
        await db.execute("""
            CREATE TABLE sso_accounts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                provider VARCHAR(50),
                provider_user_id VARCHAR(255),
                email VARCHAR(255),
                created_at TIMESTAMP DEFAULT NOW(),
                UNIQUE(provider, provider_user_id)
            )
        """)
    except:
        pass
```

## 🔄 Desktop клиент - полная интеграция

### Модифицированный `eclypse_en.py`

```python
class EclypseApp:
    def __init__(self, root):
        # ... существующий код ...
        
        # Добавить SSO конфигурацию
        self.google_client_id = "your-client-id.apps.googleusercontent.com"
        self.sso_handler = None
    
    def google_sso_login(self):
        """Полный SSO flow с интеграцией в backend"""
        try:
            self.log("Starting Google SSO...")
            
            # 1. Запускаем локальный сервер и открываем браузер
            from sso_handler import GoogleSSOHandler
            sso = GoogleSSOHandler(self.google_client_id)
            
            result = sso.authenticate()
            
            if not result["success"]:
                messagebox.showerror("Error", f"SSO failed: {result.get('error')}")
                return
            
            # 2. Получаем Google access token
            google_token = result["token_data"]["access_token"]
            
            # 3. Отправляем на наш backend
            self.log("Verifying with backend...")
            
            response = requests.post(
                f"{self.api_url}/auth/sso",
                json={
                    "access_token": google_token,
                    "provider": "google"
                },
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                # 4. Получаем JWT от нашего backend
                data = response.json()
                self.token = data["access_token"]
                self.headers = {"Authorization": f"Bearer {self.token}"}
                
                # 5. Декодируем и сохраняем информацию
                token_info = jwt.decode(self.token, options={"verify_signature": False})
                self.current_user = token_info.get("sub")
                self.user_role = token_info.get("role")
                self.user_email = token_info.get("email")
                
                self.log(f"SSO login successful: {self.current_user} (role: {self.user_role})")
                
                # 6. Показываем интерфейс
                self.login_frame.destroy()
                if self.user_role in ["admin", "master"]:
                    self.setup_admin_interface()
                else:
                    self.setup_user_interface()
                    
            else:
                error = response.json().get("detail", "Unknown error")
                self.log(f"Backend SSO failed: {error}")
                messagebox.showerror("Error", f"Backend authentication failed: {error}")
                
        except Exception as e:
            self.log(f"SSO error: {str(e)}")
            messagebox.showerror("Error", f"SSO error: {str(e)}")
    
    def setup_profile_tab(self):
        """Добавить вкладку профиля для управления SSO"""
        if not hasattr(self, 'tabs'):
            return
            
        profile_tab = self.tabs.add("Profile")
        
        # Информация о пользователе
        info_frame = ctk.CTkFrame(profile_tab)
        info_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(info_frame, text=f"Username: {self.current_user}").pack(anchor="w")
        ctk.CTkLabel(info_frame, text=f"Email: {self.user_email}").pack(anchor="w")
        ctk.CTkLabel(info_frame, text=f"Role: {self.user_role}").pack(anchor="w")
        
        # SSO статус
        sso_frame = ctk.CTkFrame(profile_tab)
        sso_frame.pack(fill="x", padx=5, pady=5)
        
        ctk.CTkLabel(sso_frame, text="SSO Accounts:", font=("Arial", 12)).pack(anchor="w", pady=5)
        
        # Кнопки для SSO
        google_btn = ctk.CTkButton(
            sso_frame,
            text="Link Google Account",
            fg_color="#4285F4",
            command=self.link_google_sso
        )
        google_btn.pack(pady=5)
        
        unlink_btn = ctk.CTkButton(
            sso_frame,
            text="Unlink Google",
            fg_color="red",
            command=self.unlink_google_sso
        )
        unlink_btn.pack(pady=5)
    
    def link_google_sso(self):
        """Привязать Google SSO к текущему аккаунту"""
        try:
            from sso_handler import GoogleSSOHandler
            
            sso = GoogleSSOHandler(self.google_client_id)
            result = sso.authenticate()
            
            if not result["success"]:
                messagebox.showerror("Error", result.get("error"))
                return
            
            google_token = result["token_data"]["access_token"]
            
            # Отправляем на backend для привязки
            response = requests.post(
                f"{self.api_url}/auth/sso/link",
                headers=self.headers,
                json={
                    "access_token": google_token,
                    "provider": "google"
                },
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                messagebox.showinfo("Success", "Google account linked!")
                self.log("Google SSO linked successfully")
            else:
                error = response.json().get("detail", "Unknown error")
                messagebox.showerror("Error", f"Link failed: {error}")
                
        except Exception as e:
            messagebox.showerror("Error", str(e))
```

## 🎯 Сценарии использования

### Сценарий 1: Новый пользователь (первый вход)
```
1. Пользователь нажимает "Google Login"
2. Desktop app → Google OAuth → Backend API
3. Backend проверяет email в БД
4. Если нет → создает нового user + sso_accounts запись
5. Возвращает JWT с ролью "user"
6. Desktop получает доступ
```

### Сценарий 2: Существующий пользователь (уже с паролем)
```
1. Пользователь входит с паролем (как раньше)
2. В профиле нажимает "Link Google"
3. Проходит Google OAuth
4. Backend находит user по email
5. Создает запись в sso_accounts
6. Теперь можно входить через Google
```

### Сценарий 3: Существующий SSO пользователь
```
1. Пользователь нажимает "Google Login"
2. Backend находит запись в sso_accounts
3. Возвращает JWT для существующего user
4. Desktop получает доступ
```

## 🛡️ Безопасность и правила

### Правила связывания аккаунтов:
1. **Email должен совпадать** - SSO email должен совпадать с email в БД
2. **Один SSO аккаунт = один user** - нельзя привязать Google к двум user
3. **Роль сохраняется** - SSO не меняет роль пользователя
4. **Fallback на пароль** - можно отвязать SSO и использовать пароль

### Миграция существующих пользователей:
```python
# Для пользователей с паролями:
# - Добавить флаг sso_linked = FALSE
# - В UI показать "Link Google Account"
# - Не требовать SSO для входа
```

## 📊 Преимущества такого подхода

✅ **Совместимость** - существующие пользователи не ломаются  
✅ **Гибкость** - можно использовать пароль или SSO  
✅ **Безопасность** - все проверки на backend  
✅ **Масштабируемость** - легко добавить другие провайдеры  
✅ **Контроль** - админ видит всех пользователей в одной БД  

## 🚀 Рекомендуемый порядок внедрения

1. **Добавить таблицы** в БД
2. **Создать backend endpoints** (`/auth/sso`, `/auth/sso/link`)
3. **Добавить SSO кнопку** в desktop клиент
4. **Протестировать** с новыми пользователями
5. **Добавить привязку** для существующих пользователей
6. **Настроить Google Cloud Console**

Таким образом, **Google SSO становится дополнением к существующей системе**, а не заменой, и вся логика остается на backend.