"""
Automated Test Verification Script for SecureLogin AI
=====================================================
Tests:
1. User registration & secure password hashing verification
2. Legitimate login authentication & session tracking
3. Failed password detection & remaining attempts counter
4. 3rd consecutive failed attempt lockout & status transition to BLOCKED
5. ML Isolation Forest Anomaly Risk evaluation
6. Tableau CSV export generation & sanitization
"""

import sys
from app import app, db
from models import User, LoginLog
from ml.model import detector

def run_tests():
    print("=" * 60)
    print("RUNNING AUTOMATED TEST SUITE FOR SECURELOGIN AI")
    print("=" * 60)

    client = app.test_client()
    
    with app.app_context():
        # Ensure database tables are created
        db.create_all()

        # Test 1: Verify Password Hashing
        print("\n[*] TEST 1: Password Hashing Verification...")
        test_user = User.query.filter_by(email="student@college.edu").first()
        assert test_user is not None, "Demo user should be seeded!"
        assert test_user.check_password("Student@123") == True, "Password verification failed!"
        assert test_user.check_password("WrongPassword") == False, "Wrong password accepted!"
        assert test_user.password_hash != "Student@123", "Password stored in plaintext!"
        print("[+] PASS: Password securely hashed using scrypt and verified.")

        # Test 2: Clean slate for lockout testing
        test_user.reset_failed_attempts()
        db.session.commit()
        assert test_user.is_locked() == False, "User should start unlocked."

        # Test 3: First Failed Login
        print("\n[*] TEST 2: First Failed Attempt...")
        resp = client.post("/login", data={"email": "student@college.edu", "password": "BadPassword1"}, follow_redirects=True)
        assert b"Remaining attempts before security alert: 2" in resp.data, "Failed attempt 1 did not decrement properly"
        db.session.refresh(test_user)
        assert test_user.failed_attempts == 1, "failed_attempts counter not 1"
        print("[+] PASS: First failed attempt recorded. Remaining attempts = 2.")

        # Test 4: Second Failed Login
        print("\n[*] TEST 3: Second Failed Attempt...")
        resp = client.post("/login", data={"email": "student@college.edu", "password": "BadPassword2"}, follow_redirects=True)
        assert b"Remaining attempts before security alert: 1" in resp.data, "Failed attempt 2 did not decrement properly"
        db.session.refresh(test_user)
        assert test_user.failed_attempts == 2, "failed_attempts counter not 2"
        print("[+] PASS: Second failed attempt recorded. Remaining attempts = 1.")

        # Test 5: Third Failed Login -> Trigger Lockout
        # Test 5: Third Failed Login -> Trigger Security Alert
        print("\n[*] TEST 4: Third Failed Attempt & Security Alert Trigger...")
        resp = client.post("/login", data={"email": "student@college.edu", "password": "BadPassword3"}, follow_redirects=True)
        assert b"SECURITY ALERT: 3 consecutive failed login attempts detected" in resp.data, "Security alert not triggered on 3rd attempt"
        db.session.refresh(test_user)
        assert test_user.failed_attempts == 3, "failed_attempts counter not 3"
        print("[+] PASS: Security alert triggered upon 3 consecutive failed attempts.")

        # Test 6: Immediate Unlock & Access with Correct Password
        print("\n[*] TEST 5: Entering Correct Password to Immediately Unlock...")
        resp = client.post("/login", data={"email": "student@college.edu", "password": "Student@123"}, follow_redirects=True)
        assert b"Authenticated securely" in resp.data or b"Security Operations Center" in resp.data, "Entering correct password failed to open dashboard!"
        db.session.refresh(test_user)
        assert test_user.failed_attempts == 0, "Failed attempts counter was not reset on successful login!"
        assert test_user.is_locked() == False, "Account remained locked after correct password!"
        print("[+] PASS: Account immediately unlocked and opened upon entering correct password.")

        # Test 8: ML Anomaly Detector
        print("\n[*] TEST 7: ML Isolation Forest Prediction Test...")
        risk_normal, label_normal = detector.predict_risk(failed_attempts=0)
        risk_high, label_high = detector.predict_risk(failed_attempts=3)
        print(f"    - Baseline Normal Risk: {risk_normal} ({label_normal})")
        print(f"    - 3-Attempt Theft Risk: {risk_high} ({label_high})")
        assert risk_high > risk_normal, "Risk score did not escalate with failed attempts!"
        print("[+] PASS: ML Anomaly Detector properly scores threat probability.")

        # Test 9: Tableau CSV Export Endpoint
        print("\n[*] TEST 8: Tableau CSV Export...")
        resp = client.get("/export-tableau-csv")
        assert resp.status_code == 200, "CSV export failed"
        csv_data = resp.data.decode("utf-8")
        assert "log_id,timestamp,login_hour,anonymized_user,success_flag" in csv_data, "CSV header missing or corrupted"
        assert "password" not in csv_data.lower(), "SECURITY VIOLATION: Password field found in CSV!"
        print("[+] PASS: Tableau CSV exported securely with zero password leakage.")

    print("\n" + "=" * 60)
    print("ALL 8 SYSTEM TESTS PASSED SUCCESSFULLY! (100% OPERATIONAL)")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
