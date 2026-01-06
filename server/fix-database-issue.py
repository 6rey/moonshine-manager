#!/usr/bin/env python3
"""
Quick fix script for database connection issues
This script helps diagnose and fix the "database 'myuser' does not exist" error
"""

import os
import sys
import asyncio
import asyncpg

async def test_connection():
    """Test database connection and provide diagnostics"""
    
    # Get database URL
    db_url = os.getenv("DB_URL", "postgresql://myuser:mypass@localhost:5432/vdi_db")
    
    print("🔍 Database Connection Diagnostic Tool")
    print("=" * 50)
    print(f"Connection string: {db_url.replace('mypass', '***')}")
    print()
    
    # Parse connection string
    try:
        # Extract components from connection string
        # Format: postgresql://user:pass@host:port/dbname
        if db_url.startswith("postgresql://"):
            parts = db_url[13:].split("@")
            if len(parts) == 2:
                user_pass = parts[0].split(":")
                host_port_db = parts[1].split("/")
                
                if len(host_port_db) == 2:
                    host_port = host_port_db[0].split(":")
                    dbname = host_port_db[1]
                    
                    print(f"📋 Parsed Configuration:")
                    print(f"   User: {user_pass[0]}")
                    print(f"   Host: {host_port[0]}")
                    print(f"   Port: {host_port[1] if len(host_port) > 1 else '5432'}")
                    print(f"   Database: {dbname}")
                    print()
    except:
        print("⚠️  Could not parse connection string")
        print()
    
    # Test connection
    print("🔄 Testing connection...")
    try:
        conn = await asyncpg.connect(db_url)
        
        # Test basic query
        result = await conn.fetchrow("SELECT version() as version, current_database() as db")
        print(f"✅ Connection successful!")
        print(f"   PostgreSQL version: {result['version']}")
        print(f"   Connected to database: {result['db']}")
        
        # Check if tables exist
        tables = await conn.fetch("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name
        """)
        
        if tables:
            print(f"   Tables found: {len(tables)}")
            for table in tables:
                print(f"      - {table['table_name']}")
        else:
            print("   ⚠️  No tables found in public schema")
        
        await conn.close()
        return True
        
    except asyncpg.InvalidCatalogNameError:
        print(f"❌ Database does not exist")
        print(f"   The database '{dbname}' needs to be created")
        return False
        
    except asyncpg.ConnectionDoesNotExistError:
        print(f"❌ Connection failed - database or host not reachable")
        print(f"   Check if the database container is running")
        return False
        
    except asyncpg.InvalidAuthorizationSpecificationError:
        print(f"❌ Authentication failed")
        print(f"   Check username and password")
        return False
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

async def create_database():
    """Attempt to create the database"""
    db_url = os.getenv("DB_URL", "postgresql://myuser:mypass@localhost:5432/vdi_db")
    
    # Connect to postgres database to create our database
    postgres_url = db_url.replace("/vdi_db", "/postgres")
    
    print("\n🔄 Attempting to create database...")
    
    try:
        conn = await asyncpg.connect(postgres_url)
        
        # Check if database exists
        exists = await conn.fetchrow(
            "SELECT 1 FROM pg_database WHERE datname = 'vdi_db'"
        )
        
        if exists:
            print("✅ Database 'vdi_db' already exists")
        else:
            await conn.execute("CREATE DATABASE vdi_db")
            print("✅ Database 'vdi_db' created successfully")
        
        await conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Failed to create database: {e}")
        return False

async def main():
    """Main diagnostic function"""
    
    print("🔧 Database Connection Fix Tool")
    print("=" * 50)
    print()
    
    # Test connection
    success = await test_connection()
    
    if not success:
        print("\n💡 Recommended actions:")
        print("1. Ensure Docker containers are running:")
        print("   docker-compose -f docker-compose-sso.yml up -d")
        print()
        print("2. Wait 30 seconds for PostgreSQL to initialize")
        print()
        print("3. If database doesn't exist, run:")
        print("   docker exec vdi_db_sso psql -U myuser -c 'CREATE DATABASE vdi_db;'")
        print()
        print("4. Check container logs:")
        print("   docker logs vdi_db_sso")
        print()
        
        # Offer to create database
        response = input("Would you like me to attempt to create the database? (y/n): ")
        if response.lower() in ['y', 'yes']:
            await create_database()
            print("\n🔄 Testing connection again...")
            await test_connection()

if __name__ == "__main__":
    asyncio.run(main())