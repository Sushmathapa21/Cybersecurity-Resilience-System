#!/usr/bin/env python3
"""
Test script to verify delete account functionality and cascade deletes
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import User, PasswordHistory, LoginLog, UserSession

def test_delete_account():
    """Test the delete account functionality"""
    with app.app_context():
        print("=== Testing Delete Account Functionality ===")
        
        # Create a test user
        test_user = User(
            username='test_delete_user',
            email='test_delete@example.com',
            is_active=True
        )
        test_user.set_password('TestPassword123!')
        
        db.session.add(test_user)
        db.session.commit()
        
        user_id = test_user.id
        print(f"Created test user: {test_user.username} (ID: {user_id})")
        
        # Add some related data
        # Password history
        ph = PasswordHistory(user_id=user_id, password_hash='test_hash_1')
        db.session.add(ph)
        
        # Login log
        ll = LoginLog(user_id=user_id, ip_address='127.0.0.1', success=True, user_agent='Test Browser')
        db.session.add(ll)
        
        # User session
        us = UserSession(user_id=user_id, session_token='test_token_123', is_active=True)
        db.session.add(us)
        
        db.session.commit()
        
        # Verify data was created
        ph_count = PasswordHistory.query.filter_by(user_id=user_id).count()
        ll_count = LoginLog.query.filter_by(user_id=user_id).count()
        us_count = UserSession.query.filter_by(user_id=user_id).count()
        
        print(f"Before deletion - PasswordHistory: {ph_count}, LoginLog: {ll_count}, UserSession: {us_count}")
        
        # Delete the user
        print("Deleting user...")
        db.session.delete(test_user)
        db.session.commit()
        
        # Verify all related data was deleted
        ph_count_after = PasswordHistory.query.filter_by(user_id=user_id).count()
        ll_count_after = LoginLog.query.filter_by(user_id=user_id).count()
        us_count_after = UserSession.query.filter_by(user_id=user_id).count()
        user_exists = User.query.get(user_id) is not None
        
        print(f"After deletion - PasswordHistory: {ph_count_after}, LoginLog: {ll_count_after}, UserSession: {us_count_after}")
        print(f"User still exists: {user_exists}")
        
        if ph_count_after == 0 and ll_count_after == 0 and us_count_after == 0 and not user_exists:
            print("✅ SUCCESS: All data was properly deleted via cascade!")
            return True
        else:
            print("❌ FAILURE: Some data was not deleted properly")
            return False

if __name__ == '__main__':
    success = test_delete_account()
    sys.exit(0 if success else 1) 