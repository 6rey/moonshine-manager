"""
Database module for SSO-enabled Eclypse backend
Handles database connections, migrations, and SSO account management
"""

import asyncpg
from datetime import datetime
from typing import Optional, Dict, List


class DatabaseManager:
    """Manages database connections and operations"""
    
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool = None
    
    async def connect(self):
        """Create connection pool with retry logic"""
        import asyncio
        
        max_retries = 10
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                print(f"🔄 Attempting to connect to database (attempt {attempt + 1}/{max_retries})...")
                self.pool = await asyncpg.create_pool(self.dsn, min_size=5, max_size=20)
                print(f"✅ Database connection pool created successfully")
                await self.initialize_tables()
                return
            except Exception as e:
                print(f"❌ Connection attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    print(f"⏳ Retrying in {retry_delay} seconds...")
                    await asyncio.sleep(retry_delay)
                else:
                    print(f"🔧 Connection string attempted: {self.dsn.replace('mypass', '***')}")
                    print(f"💡 Make sure the database container is running and the database 'vdi_db' exists")
                    raise
    
    async def close(self):
        """Close connection pool"""
        if self.pool:
            await self.pool.close()
    
    async def initialize_tables(self):
        """Initialize all required tables with SSO support"""
        async with self.pool.acquire() as conn:
            # Users table (existing)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) UNIQUE NOT NULL,
                    email VARCHAR(255) UNIQUE,
                    password_hash VARCHAR(255),
                    role VARCHAR(50) DEFAULT 'user',
                    sso_linked BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """)
            
            # SSO accounts table (new)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS sso_accounts (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    provider VARCHAR(50) NOT NULL,
                    provider_user_id VARCHAR(255) NOT NULL,
                    email VARCHAR(255),
                    created_at TIMESTAMP DEFAULT NOW(),
                    UNIQUE(provider, provider_user_id)
                )
            """)
            
            # Index for faster lookups
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sso_provider_user 
                ON sso_accounts(provider, provider_user_id)
            """)
            
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sso_user_id 
                ON sso_accounts(user_id)
            """)
            
            # Virtual Machines table (existing)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS vms (
                    id SERIAL PRIMARY KEY,
                    hostname VARCHAR(255) NOT NULL,
                    ip_address VARCHAR(45) NOT NULL,
                    sunshine_user VARCHAR(255),
                    sunshine_password VARCHAR(255),
                    created_at TIMESTAMP DEFAULT NOW()
                )
            """)
            
            # Assignments table (existing)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS assignments (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    vm_id INTEGER REFERENCES vms(id) ON DELETE CASCADE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    UNIQUE(user_id, vm_id)
                )
            """)
            
            # Create default admin user if none exists
            await self.create_default_admin()
    
    async def create_default_admin(self):
        """Create default admin user if database is empty"""
        async with self.pool.acquire() as conn:
            result = await conn.fetchrow("SELECT COUNT(*) as count FROM users")
            if result['count'] == 0:
                # Create default admin with a secure password
                # Password: "admin123" (change in production!)
                import hashlib
                import secrets
                salt = secrets.token_hex(16)
                password_hash = f"{salt}:{hashlib.sha256(('admin123' + salt).encode()).hexdigest()}"
                
                await conn.execute(
                    """
                    INSERT INTO users (username, email, password_hash, role, sso_linked)
                    VALUES ($1, $2, $3, $4, $5)
                    """,
                    "admin", "admin@example.com", password_hash, "master", False
                )
                print("✅ Default admin user created: admin / admin123")
                print("⚠️  CHANGE THIS PASSWORD IMMEDIATELY IN PRODUCTION!")
    
    # ==================== User Operations ====================
    
    async def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by ID"""
        async with self.pool.acquire() as conn:
            return await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
    
    async def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        async with self.pool.acquire() as conn:
            return await conn.fetchrow("SELECT * FROM users WHERE username = $1", username)
    
    async def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email"""
        async with self.pool.acquire() as conn:
            return await conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
    
    async def get_user_by_sso(self, provider: str, provider_user_id: str) -> Optional[Dict]:
        """Get user by SSO provider and ID"""
        async with self.pool.acquire() as conn:
            return await conn.fetchrow(
                """
                SELECT u.* FROM users u
                JOIN sso_accounts s ON u.id = s.user_id
                WHERE s.provider = $1 AND s.provider_user_id = $2
                """,
                provider, provider_user_id
            )
    
    async def create_user(self, username: str, email: str = None, password_hash: str = None,
                         role: str = "user") -> int:
        """Create a new user"""
        async with self.pool.acquire() as conn:
            result = await conn.fetchrow(
                """
                INSERT INTO users (username, email, password_hash, role)
                VALUES ($1, $2, $3, $4)
                RETURNING id
                """,
                username, email, password_hash, role
            )
            return result['id']
    
    async def create_user_from_sso(self, email: str, name: str, provider: str,
                                  provider_user_id: str) -> int:
        """Create user from SSO authentication"""
        async with self.pool.acquire() as conn:
            # Generate username from email
            username_base = email.split("@")[0]
            username = username_base
            
            # Ensure unique username
            counter = 1
            while await conn.fetchrow("SELECT id FROM users WHERE username = $1", username):
                username = f"{username_base}{counter}"
                counter += 1
            
            # Create user
            result = await conn.fetchrow(
                """
                INSERT INTO users (username, email, role, sso_linked)
                VALUES ($1, $2, $3, $4)
                RETURNING id
                """,
                username, email, "user", True
            )
            user_id = result['id']
            
            # Create SSO account link
            await conn.execute(
                """
                INSERT INTO sso_accounts (user_id, provider, provider_user_id, email)
                VALUES ($1, $2, $3, $4)
                """,
                user_id, provider, provider_user_id, email
            )
            
            return user_id
    
    async def link_sso_to_user(self, user_id: int, provider: str, 
                              provider_user_id: str, email: str) -> bool:
        """Link SSO account to existing user"""
        async with self.pool.acquire() as conn:
            # Check if SSO already linked to another user
            existing = await conn.fetchrow(
                """
                SELECT user_id FROM sso_accounts 
                WHERE provider = $1 AND provider_user_id = $2
                """,
                provider, provider_user_id
            )
            
            if existing and existing['user_id'] != user_id:
                return False
            
            # Create link
            await conn.execute(
                """
                INSERT INTO sso_accounts (user_id, provider, provider_user_id, email)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT DO NOTHING
                """,
                user_id, provider, provider_user_id, email
            )
            
            # Update user's sso_linked flag
            await conn.execute(
                "UPDATE users SET sso_linked = TRUE WHERE id = $1",
                user_id
            )
            
            return True
    
    async def link_sso_account(self, user_id: int, provider: str,
                              provider_user_id: str, email: str) -> bool:
        """Link SSO account to user"""
        return await self.link_sso_to_user(user_id, provider, provider_user_id, email)
    
    async def unlink_sso_account(self, user_id: int, provider: str) -> bool:
        """Unlink SSO account from user"""
        return await self.unlink_sso_from_user(user_id, provider)
    
    async def unlink_sso_from_user(self, user_id: int, provider: str) -> bool:
        """Unlink SSO account from user"""
        async with self.pool.acquire() as conn:
            # Delete SSO link
            await conn.execute(
                "DELETE FROM sso_accounts WHERE user_id = $1 AND provider = $2",
                user_id, provider
            )
            
            # Check if any SSO accounts remain
            remaining = await conn.fetchrow(
                "SELECT COUNT(*) as count FROM sso_accounts WHERE user_id = $1",
                user_id
            )
            
            if remaining['count'] == 0:
                await conn.execute(
                    "UPDATE users SET sso_linked = FALSE WHERE id = $1",
                    user_id
                )
            
            return True
    
    async def delete_user(self, user_id: int) -> bool:
        """Delete user and all related data"""
        async with self.pool.acquire() as conn:
            # Delete user (cascades to sso_accounts and assignments)
            result = await conn.execute("DELETE FROM users WHERE id = $1", user_id)
            return result.split()[-1] == '1'
    
    async def get_all_users(self) -> List[Dict]:
        """Get all users"""
        async with self.pool.acquire() as conn:
            return await conn.fetch("SELECT id, username, email, role, sso_linked, created_at FROM users ORDER BY id")
    
    async def list_users(self) -> List[Dict]:
        """List all users"""
        return await self.get_all_users()
    
    # ==================== VM Operations ====================
    
    async def create_vm(self, hostname: str, ip_address: str,
                       sunshine_user: str = None, sunshine_password: str = None) -> int:
        """Create a new VM"""
        async with self.pool.acquire() as conn:
            result = await conn.fetchrow(
                """
                INSERT INTO vms (hostname, ip_address, sunshine_user, sunshine_password)
                VALUES ($1, $2, $3, $4)
                RETURNING id
                """,
                hostname, ip_address, sunshine_user, sunshine_password
            )
            return result['id']
    
    async def get_vm(self, vm_id: int) -> Optional[Dict]:
        """Get VM by ID"""
        async with self.pool.acquire() as conn:
            return await conn.fetchrow("SELECT * FROM vms WHERE id = $1", vm_id)
    
    async def get_vm_by_id(self, vm_id: int) -> Optional[Dict]:
        """Get VM by ID (alias for get_vm)"""
        return await self.get_vm(vm_id)
    
    async def delete_vm(self, vm_id: int) -> bool:
        """Delete VM"""
        async with self.pool.acquire() as conn:
            result = await conn.execute("DELETE FROM vms WHERE id = $1", vm_id)
            return result.split()[-1] == '1'
    
    async def get_all_vms(self) -> List[Dict]:
        """Get all VMs"""
        async with self.pool.acquire() as conn:
            return await conn.fetch("SELECT * FROM vms ORDER BY id")
    
    async def list_vms(self) -> List[Dict]:
        """List all VMs"""
        return await self.get_all_vms()
    
    async def get_user_vms(self, user_id: int) -> List[Dict]:
        """Get VMs assigned to a specific user"""
        async with self.pool.acquire() as conn:
            return await conn.fetch(
                """
                SELECT v.* FROM vms v
                JOIN assignments a ON v.id = a.vm_id
                WHERE a.user_id = $1
                ORDER BY v.id
                """,
                user_id
            )
    
    # ==================== Assignment Operations ====================
    
    async def assign_vm_to_user(self, user_id: int, vm_id: int) -> bool:
        """Assign VM to user"""
        async with self.pool.acquire() as conn:
            try:
                await conn.execute(
                    """
                    INSERT INTO assignments (user_id, vm_id)
                    VALUES ($1, $2)
                    """,
                    user_id, vm_id
                )
                return True
            except asyncpg.UniqueViolationError:
                return False
    
    async def unassign_vm(self, user_id: int, vm_id: int) -> bool:
        """Remove VM assignment"""
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                """
                DELETE FROM assignments
                WHERE user_id = $1 AND vm_id = $2
                """,
                user_id, vm_id
            )
            return result.split()[-1] == '1'
    
    async def unassign_vm_from_user(self, user_id: int, vm_id: int) -> bool:
        """Remove VM assignment (alias for unassign_vm)"""
        return await self.unassign_vm(user_id, vm_id)
    
    async def get_user_assignments(self, user_id: int) -> List[Dict]:
        """Get all VMs assigned to user"""
        async with self.pool.acquire() as conn:
            return await conn.fetch(
                """
                SELECT v.* FROM vms v
                JOIN assignments a ON v.id = a.vm_id
                WHERE a.user_id = $1
                ORDER BY v.id
                """,
                user_id
            )
    
    async def get_all_assignments(self) -> List[Dict]:
        """Get all assignments with user and VM info"""
        async with self.pool.acquire() as conn:
            return await conn.fetch(
                """
                SELECT 
                    a.user_id,
                    a.vm_id,
                    u.username,
                    v.hostname as vm_hostname,
                    v.ip_address as vm_ip
                FROM assignments a
                JOIN users u ON a.user_id = u.id
                JOIN vms v ON a.vm_id = v.id
                ORDER BY u.username, v.hostname
                """
            )
    
    async def is_vm_assigned_to_user(self, user_id: int, vm_id: int) -> bool:
        """Check if VM is assigned to user"""
        async with self.pool.acquire() as conn:
            result = await conn.fetchrow(
                """
                SELECT COUNT(*) as count FROM assignments
                WHERE user_id = $1 AND vm_id = $2
                """,
                user_id, vm_id
            )
            return result['count'] > 0
    
    # ==================== SSO-Specific Operations ====================
    
    async def get_sso_accounts_for_user(self, user_id: int) -> List[Dict]:
        """Get all SSO accounts linked to user"""
        async with self.pool.acquire() as conn:
            return await conn.fetch(
                "SELECT * FROM sso_accounts WHERE user_id = $1",
                user_id
            )
    
    async def get_user_by_sso_provider(self, provider: str, email: str) -> Optional[Dict]:
        """Find user by SSO provider and email"""
        async with self.pool.acquire() as conn:
            return await conn.fetchrow(
                """
                SELECT u.* FROM users u
                JOIN sso_accounts s ON u.id = s.user_id
                WHERE s.provider = $1 AND s.email = $2
                """,
                provider, email
            )


# Helper function to create database manager
async def create_db_manager(db_url: str) -> DatabaseManager:
    """Factory function to create and initialize database manager"""
    db = DatabaseManager(db_url)
    await db.connect()
    return db