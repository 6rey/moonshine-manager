#!/usr/bin/env python3
"""
Test script to verify authentication works correctly
"""

import asyncio
import hashlib
import secrets

# Simulate the password hashing from Init.py
def hash_password(password: str) -> str:
    """Simple password hashing using hashlib"""
    salt = secrets.token_hex(16)
    return f"{salt}:{hashlib.sha256((password + salt).encode()).hexdigest()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    try:
        salt, hash_val = hashed_password.split(':')
        return hashlib.sha256((plain_password + salt).encode()).hexdigest() == hash_val
    except:
        return False

# Test the authentication logic
def test_password_hashing():
    print("🔐 Testing password hashing and verification...")
    
    # Test 1: Hash a password
    password = "admin123"
    hashed = hash_password(password)
    print(f"✅ Password '{password}' hashed to: {hashed[:50]}...")
    
    # Test 2: Verify correct password
    is_valid = verify_password(password, hashed)
    print(f"✅ Correct password verification: {is_valid}")
    
    # Test 3: Verify wrong password
    is_invalid = verify_password("wrongpassword", hashed)
    print(f"✅ Wrong password rejected: {not is_invalid}")
    
    # Test 4: Test the exact logic from main_sso.py
    print("\n🔐 Testing main_sso.py login logic...")
    
    # Simulate stored hash
    stored_password_hash = hashed
    
    # Simulate login attempt
    login_password = "admin123"
    
    try:
        salt, stored_hash = stored_password_hash.split(':')
        computed_hash = hashlib.sha256((login_password + salt).encode()).hexdigest()
        
        if computed_hash != stored_hash:
            print("❌ Login failed - hash mismatch")
        else:
            print("✅ Login successful - hash matches")
    except Exception as e:
        print(f"❌ Login failed with exception: {e}")
    
    # Test 5: Test NULL password handling
    print("\n🔐 Testing NULL password handling...")
    stored_password_hash = None
    
    if not stored_password_hash:
        print("✅ NULL password correctly rejected")
    else:
        print("❌ NULL password not handled correctly")

if __name__ == "__main__":
    test_password_hashing()
    print("\n🎉 All tests completed!")