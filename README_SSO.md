# Eclypse SSO Integration - Complete Implementation

## 📋 Overview

This is a complete implementation of Google SSO integration for the Eclypse VDI management system, following the architecture described in `google_sso_solution.md` and `google_sso_integration.md`.

## 🏗️ Project Structure

```
moonshine-manager/
├── client/
│   ├── eclypse_en_sso.py          # Desktop client with SSO support
│   ├── requirements_sso.txt        # Client dependencies
│   └── sso_handler.py             # (Optional) SSO handler module
├── server/
│   ├── main_sso.py                 # FastAPI backend with SSO
│   ├── database_sso.py             # Database manager with SSO support
│   ├── requirements.txt            # Server dependencies
│   └── migrations/                 # Database migrations
├── docker-compose-sso.yml          # Docker setup for SSO version
├── Dockerfile_sso                  # Backend Dockerfile
├── google_sso_solution.md          # Original solution document
├── google_sso_integration.md       # Integration details
└── README_SSO.md                   # This file
```

## 🚀 Quick Start

### 1. Backend Setup

#### Option A: Manual Setup
```bash
cd server
pip install -r requirements.txt
python main_sso.py
```

#### Option B: Docker Setup
```bash
# Build and run with docker-compose
docker-compose -f docker-compose-sso.yml up -d
```

### 2. Client Setup
```bash
cd client
pip install -r requirements_sso.txt
python eclypse_en_sso.py
```

## 🔧 Configuration

### Environment Variables (Backend)

Create `.env` file in `server/`:

```env
DB_URL=postgresql://myuser:mypass@localhost:5432/vdi_db
JWT_SECRET_KEY=your-super-secret-key-here
```

### Google OAuth Configuration

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials:
   - Application type: **Desktop app**
   - Authorized redirect URIs: `http://localhost:8080/callback`
5. Update in `client/eclypse_en_sso.py`:
   ```python
   GOOGLE_CLIENT_ID = "your-client-id.apps.googleusercontent.com"
   GOOGLE_CLIENT_SECRET = "your-client-secret"
   ```

## 📊 Database Schema

### Tables Created

```sql
-- Users table (extended)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    role VARCHAR(50) DEFAULT 'user',
    sso_linked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- SSO accounts table
CREATE TABLE sso_accounts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

-- VMs table (existing)
CREATE TABLE vms (
    id SERIAL PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    sunshine_user VARCHAR(255),
    sunshine_password VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Assignments table (existing)
CREATE TABLE assignments (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    vm_id INTEGER REFERENCES vms(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, vm_id)
);
```

## 🔐 Authentication Flow

### Traditional Login
```
1. User enters username/password
2. Client sends to /auth/token
3. Backend verifies credentials
4. Returns JWT token
5. Client stores token for API calls
```

### Google SSO Login
```
1. User clicks "Login with Google"
2. Client starts local Flask server (localhost:8080)
3. Opens browser to Google OAuth
4. User authenticates with Google
5. Google redirects to localhost:8080/callback with code
6. Client exchanges code for Google access token
7. Client sends token to /auth/sso
8. Backend:
   - Verifies token with Google
   - Checks if SSO account exists
   - If yes: returns JWT for existing user
   - If no: creates new user + SSO link, returns JWT
9. Client stores JWT
```

### Link SSO to Existing Account
```
1. User logs in traditionally
2. Goes to Profile tab
3. Clicks "Link Google Account"
4. Same SSO flow as above
5. Backend links SSO to existing user
```

## 🛡️ Security Features

1. **PKCE Support**: Ready for PKCE implementation
2. **Token Verification**: All tokens verified with provider
3. **Role-Based Access**: Admin/Master/User roles
4. **SSO Linking Rules**:
   - One SSO account per user
   - Email must match
   - Can unlink anytime
5. **Fallback**: Traditional login still works

## 🎯 API Endpoints

### Authentication
- `POST /auth/token` - Traditional login
- `POST /auth/register` - Register new user
- `POST /auth/sso` - SSO authentication
- `POST /auth/sso/link` - Link SSO account
- `POST /auth/sso/unlink` - Unlink SSO account

### Admin
- `GET /admin/users` - List users
- `DELETE /admin/user/{id}` - Delete user

### VM Management
- `POST /vm/register` - Register VM
- `GET /vm/list` - List VMs
- `DELETE /vm/delete/{id}` - Delete VM

### Assignments
- `POST /vm/assign` - Assign VM to user
- `DELETE /vm/unassign` - Remove assignment
- `GET /vm/assignments` - List assignments

### Pairing
- `POST /vm/prepare-pairing` - Get PIN
- `POST /vm/complete-pairing` - Complete pairing

### Health
- `GET /health` - Health check
- `GET /` - API info

## 📱 Client Features

### Login Screen
- Traditional username/password
- Google SSO button
- SAML button (placeholder)
- SSL verification toggle
- API URL configuration

### Admin Interface
- User management
- VM management
- Assignment management
- VM connection
- Profile with SSO management

### User Interface
- VM list
- Connect to VM
- Profile with SSO linking
- Logout

### Profile Tab
- User information
- SSO account management
  - Link Google Account
  - Unlink Google Account
- Logout button

## 🐛 Troubleshooting

### Common Issues

1. **"Google Client ID not configured"**
   - Update `GOOGLE_CLIENT_ID` in `eclypse_en_sso.py`

2. **"Port 8080 already in use"**
   - Change `redirect_uri` in both client and Google Console
   - Or use Device Flow alternative

3. **"Database connection failed"**
   - Check `DB_URL` environment variable
   - Ensure PostgreSQL is running
   - Run migrations

4. **"Invalid Google token"**
   - Check if token expired
   - Verify Google OAuth configuration
   - Ensure correct scopes

5. **"SSO account already linked"**
   - User must unlink from other account first
   - Or use different Google account

## 🚢 Docker Deployment

### docker-compose-sso.yml
```yaml
version: '3.8'

services:
  db:
    image: postgres:15
    environment:
      POSTGRES_USER: myuser
      POSTGRES_PASSWORD: mypass
      POSTGRES_DB: vdi_db
    ports:
      - "5432:5432"
    volumes:
      - db_data:/var/lib/postgresql/data

  api:
    build:
      context: .
      dockerfile: Dockerfile_sso
    environment:
      DB_URL: postgresql://myuser:mypass@db:5432/vdi_db
      JWT_SECRET_KEY: "SUPER_SECRET_KEY"
    ports:
      - "443:443"
    depends_on:
      - db

volumes:
  db_data:
```

### Run with Docker
```bash
docker-compose -f docker-compose-sso.yml up -d
```

## 📋 Migration Guide

### From Original System to SSO Version

1. **Backup database**
2. **Update server files**:
   - Replace `main.py` with `main_sso.py`
   - Replace database module with `database_sso.py`
3. **Run migrations**:
   ```sql
   ALTER TABLE users ADD COLUMN sso_linked BOOLEAN DEFAULT FALSE;
   CREATE TABLE sso_accounts (...);
   ```
4. **Update client**:
   - Replace `eclypse_en.py` with `eclypse_en_sso.py`
   - Install new dependencies
5. **Configure Google OAuth**
6. **Test SSO flow**
7. **Keep traditional login as fallback**

## 🔒 Production Checklist

- [ ] Use proper SSL certificates (not self-signed)
- [ ] Set strong JWT secret key
- [ ] Use environment variables for all secrets
- [ ] Enable password hashing (bcrypt/argon2)
- [ ] Implement rate limiting
- [ ] Add logging and monitoring
- [ ] Use production database (PostgreSQL with backups)
- [ ] Configure proper CORS if needed
- [ ] Set up HTTPS reverse proxy (nginx)
- [ ] Implement session management
- [ ] Add audit logging
- [ ] Configure Google OAuth properly
- [ ] Test all flows

## 📚 Additional Resources

- Original solution: `google_sso_solution.md`
- Integration details: `google_sso_integration.md`
- Client code: `client/eclypse_en_sso.py`
- Backend code: `server/main_sso.py`
- Database: `server/database_sso.py`

## ✅ Testing

### Test Scenarios

1. **New user via SSO**
   - Click Google Login
   - Complete flow
   - Verify user created
   - Verify JWT received

2. **Existing user links SSO**
   - Login traditionally
   - Link Google account
   - Logout
   - Login with Google
   - Same user access

3. **Admin functions**
   - Create users
   - Register VMs
   - Assign VMs
   - Delete users

4. **User functions**
   - View assigned VMs
   - Connect to VM
   - Manage SSO in profile

## 🎉 Success Criteria

✅ Desktop client with Google SSO button  
✅ Local Flask server for OAuth callback  
✅ Backend endpoint `/auth/sso`  
✅ Database with SSO support  
✅ Automatic user creation  
✅ SSO linking to existing accounts  
✅ Role preservation  
✅ Fallback to traditional login  
✅ Docker deployment ready  
✅ Complete documentation  

## 📞 Support

For issues or questions:
1. Check troubleshooting section
2. Review logs from backend
3. Verify Google OAuth configuration
4. Test database connectivity
5. Check token validation

---

**Implementation Complete!** 🚀

All components are ready for deployment. Follow the configuration steps to set up Google SSO and start using passwordless authentication.