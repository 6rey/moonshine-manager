# Google SSO / SAML для Eclypse Client

## 📋 Обзор решения

Для интеграции Google SSO/SAML в desktop приложение `eclypse_en.py` (CustomTkinter) требуется изменение архитектуры аутентификации.

## 🎯 Проблемы desktop SSO

1. **Desktop приложения не могут использовать OAuth2 напрямую** - нет браузера для редиректа
2. **Нужен локальный сервер** - для обработки callback от Google
3. **Безопасность** - хранение токенов в desktop приложении

## ✅ Рекомендуемое решение: OAuth2 с локальным сервером

### Архитектура

```
┌─────────────────┐
│ Desktop App     │
│ (eclypse_en.py) │
└────────┬────────┘
         │
         │ 1. Запускает локальный сервер
         │ 2. Открывает браузер для Google Auth
         │
┌────────▼────────┐
│ Local Server    │
│ (localhost:8080)│
└────────┬────────┘
         │
         │ 3. Получает callback от Google
         │ 4. Обменивает code на token
         │
┌────────▼────────┐
│ Google OAuth    │
│ (accounts.google│
│  .com)          │
└─────────────────┘
```

### Реализация

#### 1. Добавить зависимости

```python
# client/requirements.txt
customtkinter
requests
PyJWT
urllib3
zeroconf>=0.131.0
flask>=3.0.0          # NEW
google-auth-oauthlib>=0.8.0  # NEW
webbrowser            # NEW (built-in)
```

#### 2. Создать модуль SSO (`client/sso_handler.py`)

```python
import threading
import webbrowser
import requests
from flask import Flask, request, jsonify
import secrets
import time

class GoogleSSOHandler:
    def __init__(self, client_id, client_secret, redirect_uri="http://localhost:8080/callback"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.app = Flask(__name__)
        self.token = None
        self.error = None
        self.setup_routes()
        
    def setup_routes(self):
        @self.app.route('/callback')
        def callback():
            code = request.args.get('code')
            error = request.args.get('error')
            
            if error:
                self.error = error
                return jsonify({"status": "error", "error": error})
            
            if code:
                # Exchange code for token
                token_data = self.exchange_code_for_token(code)
                if token_data:
                    self.token = token_data
                    return jsonify({"status": "success", "message": "Authentication successful! You can close this window."})
                else:
                    self.error = "Token exchange failed"
                    return jsonify({"status": "error", "message": "Token exchange failed"})
            
            return jsonify({"status": "error", "message": "No code received"})
    
    def exchange_code_for_token(self, code):
        """Exchange authorization code for access token"""
        try:
            token_url = "https://oauth2.googleapis.com/token"
            data = {
                "code": code,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "redirect_uri": self.redirect_uri,
                "grant_type": "authorization_code"
            }
            
            response = requests.post(token_url, data=data)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"Token exchange error: {e}")
            return None
    
    def start_server(self):
        """Start Flask server in a thread"""
        def run():
            self.app.run(host='localhost', port=8080, debug=False, use_reloader=False)
        
        server_thread = threading.Thread(target=run, daemon=True)
        server_thread.start()
        time.sleep(1)  # Wait for server to start
    
    def get_auth_url(self):
        """Generate Google OAuth URL"""
        scope = "openid email profile"
        state = secrets.token_urlsafe(32)
        
        auth_url = (
            f"https://accounts.google.com/o/oauth2/v2/auth?"
            f"response_type=code&"
            f"client_id={self.client_id}&"
            f"redirect_uri={self.redirect_uri}&"
            f"scope={scope}&"
            f"state={state}&"
            f"access_type=offline"
        )
        return auth_url
    
    def authenticate(self):
        """Perform full authentication flow"""
        self.start_server()
        
        # Open browser
        auth_url = self.get_auth_url()
        webbrowser.open(auth_url)
        
        # Wait for callback (max 60 seconds)
        start_time = time.time()
        while time.time() - start_time < 60:
            if self.token:
                return {"success": True, "token_data": self.token}
            if self.error:
                return {"success": False, "error": self.error}
            time.sleep(0.5)
        
        return {"success": False, "error": "Timeout waiting for authentication"}

# Функция для получения user info из Google
def get_google_user_info(access_token):
    """Get user information from Google API"""
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers=headers
        )
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error getting user info: {e}")
        return None
```

#### 3. Модифицировать `eclypse_en.py`

```python
# Добавить импорты
from sso_handler import GoogleSSOHandler, get_google_user_info

# Добавить константы
GOOGLE_CLIENT_ID = "your-google-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "your-google-client-secret"

class EclypseApp:
    def __init__(self, root):
        # ... существующий код ...
        
    def setup_login_frame(self):
        # ... существующий код ...
        
        # Добавить SSO кнопку
        sso_frame = ctk.CTkFrame(self.login_frame)
        sso_frame.pack(pady=10)
        
        sso_label = ctk.CTkLabel(sso_frame, text="Or login with:")
        sso_label.pack(side="left", padx=5)
        
        google_btn = ctk.CTkButton(
            sso_frame, 
            text="Google", 
            fg_color="#4285F4",
            hover_color="#357ABD",
            command=self.google_sso_login
        )
        google_btn.pack(side="left", padx=5)
        
        # Добавить SAML кнопку (если нужно)
        saml_btn = ctk.CTkButton(
            sso_frame,
            text="SAML",
            fg_color="#6C757D",
            command=self.saml_login
        )
        saml_btn.pack(side="left", padx=5)
    
    def google_sso_login(self):
        """Handle Google SSO login"""
        try:
            self.log("Starting Google SSO...")
            
            # Create SSO handler
            sso = GoogleSSOHandler(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
            
            # Authenticate
            result = sso.authenticate()
            
            if result["success"]:
                token_data = result["token_data"]
                access_token = token_data.get("access_token")
                
                # Get user info
                user_info = get_google_user_info(access_token)
                if user_info:
                    email = user_info.get("email")
                    name = user_info.get("name")
                    
                    self.log(f"Google SSO successful: {email}")
                    
                    # Send to your API for verification/jwt creation
                    self.authenticate_with_backend(email, name, "google")
                else:
                    self.log("Failed to get user info from Google")
                    messagebox.showerror("Error", "Failed to get user information")
            else:
                error = result.get("error", "Unknown error")
                self.log(f"Google SSO failed: {error}")
                messagebox.showerror("Error", f"Google SSO failed: {error}")
                
        except Exception as e:
            self.log(f"SSO error: {str(e)}")
            messagebox.showerror("Error", f"SSO error: {str(e)}")
    
    def authenticate_with_backend(self, email, name, provider):
        """Authenticate with backend using SSO credentials"""
        try:
            # Send SSO info to your API
            response = requests.post(
                f"{self.api_url}/auth/sso",
                json={
                    "email": email,
                    "name": name,
                    "provider": provider
                },
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.token = token_data["access_token"]
                self.headers = {"Authorization": f"Bearer {self.token}"}
                
                # Decode token
                token_info = jwt.decode(self.token, options={"verify_signature": False})
                self.current_user = token_info.get("sub", email)
                self.user_role = token_info.get("role", "user")
                
                self.log(f"SSO login successful for {self.current_user} (role: {self.user_role})")
                
                # Remove login frame and show interface
                self.login_frame.destroy()
                if self.user_role in ["admin", "master"]:
                    self.setup_admin_interface()
                else:
                    self.setup_user_interface()
            else:
                self.log(f"Backend authentication failed: {response.text}")
                messagebox.showerror("Error", f"Backend authentication failed: {response.status_code}")
                
        except Exception as e:
            self.log(f"Backend auth error: {str(e)}")
            messagebox.showerror("Error", f"Connection error: {str(e)}")
    
    def saml_login(self):
        """SAML SSO login (requires backend support)"""
        # SAML в desktop приложениях сложнее - обычно требует браузер
        # Можно использовать тот же подход, что и для Google
        messagebox.showinfo("SAML", "SAML authentication requires backend configuration.\nPlease contact administrator.")
```

#### 4. Backend API endpoint для SSO

```python
# server/main.py (FastAPI)
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import jwt
import datetime

app = FastAPI()

class SSORequest(BaseModel):
    email: str
    name: str
    provider: str

@app.post("/auth/sso")
async def sso_auth(request: SSORequest):
    """
    Handle SSO authentication from desktop client
    Verifies user exists in DB or creates new user
    Returns JWT token
    """
    
    # Check if user exists
    user = await get_user_by_email(request.email)
    
    if not user:
        # Auto-create user from SSO
        user = await create_user_from_sso(request.email, request.name, request.provider)
    
    # Generate JWT
    token_payload = {
        "sub": user.username,
        "role": user.role,
        "email": request.email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    
    access_token = jwt.encode(token_payload, "SECRET_KEY", algorithm="HS256")
    
    return {"access_token": access_token, "token_type": "bearer"}

async def get_user_by_email(email: str):
    # Your DB logic here
    pass

async def create_user_from_sso(email: str, name: str, provider: str):
    # Your DB logic here - create user with "user" role by default
    pass
```

### 🛡️ Безопасность

1. **Client Secret Storage**: 
   - Desktop приложения НЕ должны хранить client secret
   - Использовать **PKCE** (Proof Key for Code Exchange)
   - Или использовать backend proxy для обмена code → token

2. **PKCE Flow** (рекомендуется):

```python
import hashlib
import base64
import secrets

def generate_pkce():
    code_verifier = secrets.token_urlsafe(32)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip('=')
    return code_verifier, code_challenge

# В auth URL добавить:
# &code_challenge=CODE_CHALLENGE&code_challenge_method=S256
```

3. **Token Storage**:
   - Использовать `keyring` для безопасного хранения
   - Не хранить в открытом виде

```python
import keyring

# Save token
keyring.set_password("eclypse", "access_token", token)

# Get token
token = keyring.get_password("eclypse", "access_token")
```

### 📋 Конфигурация Google Cloud Console

1. Создать OAuth 2.0 Client ID
2. Добавить Authorized redirect URIs:
   - `http://localhost:8080/callback`
3. Выбрать Application type: **Desktop app**

### 🔄 Альтернативный вариант: Device Flow

Если не хочется запускать локальный сервер:

```python
def device_flow_auth():
    """Google Device Flow для desktop apps"""
    
    # 1. Request device code
    response = requests.post(
        "https://oauth2.googleapis.com/device/code",
        data={
            "client_id": CLIENT_ID,
            "scope": "openid email profile"
        }
    )
    data = response.json()
    
    # 2. Show user code and verification URL
    print(f"Go to: {data['verification_url']}")
    print(f"Enter code: {data['user_code']}")
    
    # 3. Poll for token
    while True:
        token_response = requests.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": CLIENT_ID,
                "device_code": data['device_code'],
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
            }
        )
        
        if token_response.status_code == 200:
            return token_response.json()
        
        error = token_response.json().get('error')
        if error != 'authorization_pending':
            break
        
        time.sleep(data['interval'])
```

## 📊 Сравнение решений

| Решение | Сложность | UX | Безопасность | Offline |
|---------|-----------|----|--------------|---------|
| **Local Server + Browser** | Средняя | ⭐⭐⭐⭐⭐ | Высокая | ❌ |
| **Device Flow** | Низкая | ⭐⭐⭐ | Высокая | ❌ |
| **SAML** | Высокая | ⭐⭐⭐ | Высокая | ❌ |
| **API Key** | Низкая | ⭐⭐ | Низкая | ✅ |

## 🎯 Рекомендация

**Для Eclypse Client используйте:**

1. **Google OAuth2 с локальным сервером** (PKCE)
2. **Backend endpoint** `/auth/sso` для создания/проверки пользователя
3. **Device Flow** как fallback для случаев, когда порт 8080 занят

Это обеспечит:
- ✅ Удобный UX (один клик)
- ✅ Высокую безопасность
- ✅ Автоматическую регистрацию новых пользователей
- ✅ Поддержку существующей архитектуры JWT