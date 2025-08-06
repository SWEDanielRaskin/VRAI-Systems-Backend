#!/usr/bin/env python3
"""
Simple test script to verify authentication endpoints
"""

import requests
import json

# Test configuration
BASE_URL = "https://vraisystems.up.railway.app"
LOGIN_ENDPOINT = f"{BASE_URL}/api/auth/login"
VERIFY_ENDPOINT = f"{BASE_URL}/api/auth/verify"

def test_login():
    """Test login endpoint"""
    print("Testing login endpoint...")
    
    # Test with correct credentials
    login_data = {
        "username": "carlathomas",
        "password": "hti89pqc"
    }
    
    try:
        response = requests.post(LOGIN_ENDPOINT, json=login_data)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        if response.status_code == 200:
            token = response.json().get('token')
            if token:
                print("✅ Login successful! Token received.")
                return token
            else:
                print("❌ Login failed: No token received")
                return None
        else:
            print("❌ Login failed")
            return None
            
    except Exception as e:
        print(f"❌ Error testing login: {e}")
        return None

def test_verify_auth(token):
    """Test verify authentication endpoint"""
    print("\nTesting verify authentication endpoint...")
    
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    try:
        response = requests.get(VERIFY_ENDPOINT, headers=headers)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        if response.status_code == 200:
            print("✅ Authentication verification successful!")
        else:
            print("❌ Authentication verification failed")
            
    except Exception as e:
        print(f"❌ Error testing verify auth: {e}")

def test_protected_endpoint(token):
    """Test a protected endpoint"""
    print("\nTesting protected endpoint...")
    
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    try:
        # Test the settings endpoint
        response = requests.get(f"{BASE_URL}/api/settings/business_name", headers=headers)
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ Protected endpoint accessible!")
        else:
            print("❌ Protected endpoint not accessible")
            
    except Exception as e:
        print(f"❌ Error testing protected endpoint: {e}")

def main():
    print("🔐 Testing VRAI Systems Authentication")
    print("=" * 50)
    
    # Test login
    token = test_login()
    
    if token:
        # Test verify auth
        test_verify_auth(token)
        
        # Test protected endpoint
        test_protected_endpoint(token)
        
        print("\n✅ All authentication tests completed!")
    else:
        print("\n❌ Authentication tests failed!")

if __name__ == "__main__":
    main() 