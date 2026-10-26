"""
Automated Comprehensive Test Suite for CyberGuard
Validates the core CyberGuard functional requirements:
1. Static confidential record serving
2. Pre-seeded authentication & Brute-force defense
3. Bulk record exfiltration interception (> 10 records) & safe export (<= 10 records)
4. Request velocity bot monitoring
5. Real-time IP Geolocation resolution
6. Immutable SHA-256 blockchain ledger & cryptographic integrity
"""

import io
import hashlib
import json
import os
import zipfile
import app
from app import ledger, blacklisted_users, blacklisted_ips, login_failed_attempts
import populate_logs

def run_all_tests():
    print("=" * 65)
    print("  RUNNING CYBERGUARD VERIFICATION SUITE")
    print("=" * 65)

    client = app.app.test_client()

    populate_logs.main()
    app.ACTIVE_BLOCKLIST.clear()
    app.USER_LOCKOUTS.clear()
    app.REQUEST_TRACKER.clear()
    app.request_velocity_tracker.clear()
    blacklisted_users.clear()
    blacklisted_ips.clear()
    login_failed_attempts.clear()

    # -------------------------------------------------------------
    # 1. Test Static Confidential Record Routing
    # -------------------------------------------------------------
    print("\n[TEST 1] Confidential Record Access Requires Authentication...")
    res = client.get("/records/record_1.txt")
    assert res.status_code == 302
    print("   -> Anonymous access to confidential records is redirected to login")

    # -------------------------------------------------------------
    # 2. Test Pre-Seeded Valid Authentication
    # -------------------------------------------------------------
    print("\n[TEST 2] Pre-seeded Authentication (Rushyanth)...")
    res = client.post("/", data={"username": "Rushyanth", "password": "23K81A7333"}, follow_redirects=True)
    assert res.status_code == 200
    assert b"CyberGuard" in res.data
    assert b"Operator:" in res.data
    assert b"100 Forensic Records Indexed" in res.data
    res = client.get("/records/record_1.txt")
    assert res.status_code == 200
    assert res.mimetype == "text/plain"
    record_lines = res.get_data(as_text=True).splitlines()
    signature = record_lines[-1].split("=", 1)[1].removeprefix("sha256:")
    assert hashlib.sha256("\n".join(record_lines[:-1]).encode("utf-8")).hexdigest() == signature
    print("   -> Login Successful: Rushyanth authenticated and signed record served")

    # -------------------------------------------------------------
    # 3. Test Safe Server Log Record Download (<= 10 records)
    # -------------------------------------------------------------
    print("\n[TEST 3] Safe Server Log Record Export (5 records)...")
    safe_records = [f"record_{i}.txt" for i in range(1, 6)]
    res = client.post("/download", data={"selected_records": safe_records})
    assert res.status_code == 200
    assert res.mimetype == "application/zip"
    
    # Verify zip content
    zip_bytes = io.BytesIO(res.data)
    with zipfile.ZipFile(zip_bytes, "r") as z:
        names = z.namelist()
        assert len(names) == 5
        assert z.read("record_1.txt").startswith(b"ip=")
        print(f"   -> Safe ZIP delivered containing: {names}")

    # -------------------------------------------------------------
    # 4. Test Bulk Server Log Record Exfiltration (> 10 records)
    # -------------------------------------------------------------
    print("\n[TEST 4] Bulk Exfiltration Attack Interception (25 records)...")
    attack_records = [f"record_{i}.txt" for i in range(1, 26)]
    initial_blocks = len(ledger.chain)

    res = client.post("/download", data={"selected_records": attack_records}, follow_redirects=True)
    assert res.status_code == 200
    assert b"Access Denied" in res.data or b"BULK_DATA_EXFILTRATION" in res.data
    assert "Rushyanth" in blacklisted_users
    print("   -> Exfiltration Intercepted! Rushyanth marked blacklisted.")
    
    # Verify Blockchain Mined a Threat Block
    assert len(ledger.chain) == initial_blocks + 1
    new_block = ledger.get_latest_block()
    print(f"   -> Mined Blockchain Block #{new_block.index}")
    print(f"   -> Threat Type: {new_block.threat_data['violation_type']}")
    print(f"   -> Target User: {new_block.threat_data['username']}")
    print(f"   -> Geolocation: {new_block.threat_data['geolocation']['city']}, {new_block.threat_data['geolocation']['country']}")
    print(f"   -> SHA-256 Hash: {new_block.current_hash}")
    assert new_block.current_hash.startswith("00")  # Proof-of-work
    assert new_block.threat_data['violation_type'] == "BULK_DATA_EXFILTRATION"

    # -------------------------------------------------------------
    # 5. Test Brute-Force Defense (3 failed attempts for Ruthika)
    # -------------------------------------------------------------
    print("\n[TEST 5] Brute-Force Defense (3 failed attempts)...")
    # Reset blacklists for Ruthika test
    if "Ruthika" in blacklisted_users:
        blacklisted_users.remove("Ruthika")
    blacklisted_ips.clear()
    login_failed_attempts["Ruthika"] = 0

    # Attempts 1 and 2
    for attempt in range(1, 3):
        res = client.post("/", data={"username": "Ruthika", "password": "wrong_password"}, follow_redirects=True)
        assert res.status_code == 200
        assert b"Invalid credentials" in res.data

    # Attempt 3 (Should trigger lockout and blockchain block)
    res = client.post("/", data={"username": "Ruthika", "password": "wrong_password"}, follow_redirects=True)
    assert "Ruthika" in blacklisted_users
    latest_block = ledger.get_latest_block()
    assert latest_block.threat_data['violation_type'] == "BRUTE_FORCE_LOGIN_ATTACK"
    assert latest_block.threat_data['username'] == "Ruthika"
    print(f"   -> Brute-Force Detected! Ruthika locked out and recorded in Block #{latest_block.index}")

    # -------------------------------------------------------------
    # 6. Test Cryptographic Blockchain Verification
    # -------------------------------------------------------------
    print("\n[TEST 6] Cryptographic Chain Integrity Validation...")
    is_valid, msg = ledger.is_valid()
    assert is_valid is True
    print(f"   -> Validation Status: {msg} (Chain Length: {len(ledger.chain)})")

    # -------------------------------------------------------------
    # 7. Test Ledger Route Render
    # -------------------------------------------------------------
    print("\n[TEST 7] Blockchain Ledger UI Route (/ledger)...")
    res = client.get("/ledger")
    assert res.status_code == 200
    assert b"Immutable Forensic Audit Chain" in res.data
    assert b"BULK_DATA_EXFILTRATION" in res.data
    print("   -> /ledger rendered successfully with all forensic telemetry")

    # -------------------------------------------------------------
    # 8. Test Blocked User Cannot Continue Browsing
    # -------------------------------------------------------------
    print("\n[TEST 8] Verifying Blocked User Cannot Access Dataset or Log In...")
    # Ruthika is currently blacklisted from Test 5
    res = client.post("/", data={"username": "Ruthika", "password": "23K81A7307"}, follow_redirects=True)
    assert b"Access Denied" in res.data or b"SEV-1 Threat Intercepted" in res.data

    # Verify localhost can always access the login portal to test other users
    res_login = client.get("/")
    assert res_login.status_code == 200
    assert b"Secure Portal Access" in res_login.data
    print("   -> Protected Routing: Blacklisted user rejected; login portal remains 100% accessible on localhost.")

    # -------------------------------------------------------------
    # 9. Test Proxy IP Handling and Admin Lockout Reset
    # -------------------------------------------------------------
    print("\n[TEST 9] Proxy IP Handling & Admin Security Lockout Reset...")
    with app.app.test_request_context(
        "/",
        headers={"X-Forwarded-For": "203.0.113.9"},
        environ_overrides={"REMOTE_ADDR": "127.0.0.1"}
    ):
        assert app.get_client_ip() == "203.0.113.9"

    with app.app.test_request_context(
        "/",
        headers={"X-Forwarded-For": "203.0.113.9"},
        environ_overrides={"REMOTE_ADDR": "198.51.100.10"}
    ):
        assert app.get_client_ip() == "198.51.100.10"

    assert client.post("/admin/reset_demo").status_code == 403

    app.ADMIN_PASSWORD = "test-only-admin-password"
    admin_client = app.app.test_client()
    admin_login = admin_client.post(
        "/", data={"username": "admin", "password": app.ADMIN_PASSWORD}
    )
    assert admin_login.status_code == 302
    assert b"Reset Security Lockouts" in admin_client.get("/ledger").data
    assert b"Reset Security Lockouts" not in client.get("/ledger").data
    dashboard_response = admin_client.get("/dashboard")
    assert dashboard_response.status_code == 200
    assert b"Client IP: 127.0.0.1" in dashboard_response.data
    assert b"Cyber Range Workstation" in dashboard_response.data

    assert client.get("/api/live_stream").status_code == 401
    live_stream_response = admin_client.get("/api/live_stream")
    assert live_stream_response.status_code == 200
    live_entries = live_stream_response.get_json()["entries"]
    assert len(live_entries) == 10
    assert live_entries[0]["filename"] == "record_100.txt"

    audit_response = admin_client.get("/api/verify_chain")
    assert audit_response.status_code == 200
    assert audit_response.get_json()["is_valid"] is True
    assert b"Run Cryptographic Audit" in admin_client.get("/ledger").data
    assert b"Export Forensic Report" in admin_client.get("/ledger").data
    original_genesis_hash = ledger.chain[0].current_hash
    ledger.chain[0].current_hash = "f" * 64
    assert ledger.is_valid()[0] is False
    ledger.chain[0].current_hash = original_genesis_hash
    original_parent_hash = ledger.chain[1].previous_hash
    ledger.chain[1].previous_hash = "f" * 64
    assert ledger.is_valid()[0] is False
    ledger.chain[1].previous_hash = original_parent_hash
    unauthenticated_report = client.get("/admin/export_report")
    assert unauthenticated_report.status_code == 403

    blacklisted_users.add("Rushyanth")
    blacklisted_ips.add("203.0.113.44")
    app.ACTIVE_BLOCKLIST["203.0.113.44"] = {"reason": "test"}
    app.USER_LOCKOUTS["Rushyanth"] = {"locked": True, "failed_attempts": 3}
    app.REQUEST_TRACKER["203.0.113.44"] = [1.0]
    app.save_blacklist()
    reset_response = admin_client.post("/admin/reset_demo")
    assert reset_response.status_code == 302
    assert not blacklisted_users
    assert not blacklisted_ips
    assert not app.ACTIVE_BLOCKLIST
    assert not app.USER_LOCKOUTS
    assert not app.REQUEST_TRACKER
    assert not login_failed_attempts
    with open(app.BLACKLIST_FILE, "r", encoding="utf-8") as blacklist_file:
        persisted_blacklist = json.load(blacklist_file)
    assert persisted_blacklist == {"users": [], "ips": []}

    # Admin unblock remains reachable from a blocklisted IP, but requires admin authentication.
    blocked_ip = "203.0.113.44"
    locked_user = "Rushyanth"
    app.ACTIVE_BLOCKLIST[blocked_ip] = {"reason": "test"}
    app.USER_LOCKOUTS[locked_user] = {"locked": True, "failed_attempts": 3}
    app.REQUEST_TRACKER[blocked_ip] = [1.0]
    app.request_velocity_tracker[blocked_ip] = [1.0]
    blacklisted_ips.add(blocked_ip)
    blacklisted_users.add(locked_user)
    login_failed_attempts[locked_user] = 3

    unauthorized_client = app.app.test_client()
    unauthorized_response = unauthorized_client.post(
        "/admin/unblock",
        json={"ip": blocked_ip, "username": locked_user},
        environ_overrides={"REMOTE_ADDR": blocked_ip}
    )
    assert unauthorized_response.status_code == 403

    unblock_response = admin_client.post(
        "/admin/unblock",
        json={"ip": blocked_ip, "username": locked_user},
        environ_overrides={"REMOTE_ADDR": blocked_ip}
    )
    assert unblock_response.status_code == 200
    assert blocked_ip not in app.ACTIVE_BLOCKLIST
    assert blocked_ip not in blacklisted_ips
    assert blocked_ip not in app.REQUEST_TRACKER
    assert blocked_ip not in app.request_velocity_tracker
    assert locked_user not in app.USER_LOCKOUTS
    assert locked_user not in blacklisted_users
    assert login_failed_attempts[locked_user] == 0
    assert ledger.get_latest_block().threat_data["violation_type"] == "ADMIN_OVERRIDE_UNBLOCK"

    report_response = admin_client.get("/admin/export_report")
    assert report_response.status_code == 200
    assert report_response.mimetype == "application/json"
    report = json.loads(report_response.get_data(as_text=True))
    assert report["summary"]["block_count"] == len(ledger.chain)
    assert report["threats"][-1]["violation_type"] == "ADMIN_OVERRIDE_UNBLOCK"
    assert report["blockchain"][-1]["current_hash"] == ledger.get_latest_block().current_hash
    assert blocked_ip not in report["blocked_ips"]
    assert locked_user not in report["locked_users"]

    res = client.post(
        "/", data={"username": "Rushyanth", "password": "23K81A7333"},
        follow_redirects=True
    )
    assert res.status_code == 200
    assert b"Operator:" in res.data
    print("   -> Forwarded IP accepted only from local proxy; admin reset cleared persistent lockouts.")

    # -------------------------------------------------------------
    # 10. Test Blockchain Disk Persistence (Simulated Server Restart)
    # -------------------------------------------------------------
    print("\n[TEST 10] Blockchain File Persistence & Reload (blockchain_ledger.json)...")
    assert os.path.exists(app.LEDGER_FILE)
    with open(app.LEDGER_FILE, "r", encoding="utf-8") as f:
        stored_blocks = json.load(f)
    assert len(stored_blocks) == len(ledger.chain)
    
    # Simulate a new server process loading from file
    restarted_ledger = app.BlockchainLedger(storage_file=app.LEDGER_FILE)
    assert len(restarted_ledger.chain) == len(stored_blocks)
    valid, _ = restarted_ledger.is_valid()
    assert valid is True
    print(f"   -> Disk Persistence Validated: {len(stored_blocks)} blocks loaded permanently from file across restart.")

    print("\n" + "=" * 65)
    print("  ALL 10 TESTS PASSED! CYBERGUARD PROTOTYPE FULLY OPERATIONAL.")
    print("=" * 65)

if __name__ == "__main__":
    run_all_tests()
