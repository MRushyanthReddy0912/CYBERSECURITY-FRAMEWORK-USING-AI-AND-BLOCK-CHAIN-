"""
CyberGuard: Advanced Cybersecurity Framework using Artificial Intelligence and Blockchain
Major Graduation Engineering Project

Core Modules & Features:
1. Static Routing for 100 Confidential Records (/records/<filename>)
2. Pre-seeded Authentication & 3-Strike Brute-Force Defense
3. Confidential Server Log Records & Bulk Exfiltration Defense (Strict 10 Record Limit)
4. Request Velocity & Automated Bot Scraper Defense
5. Real-Time IP Geolocation Intelligence Tracking (ip-api.com)
6. Immutable SHA-256 Blockchain Forensic Ledger with Proof-of-Work
"""

import os
import sys
import re
import io
import time
import json
import hmac
import ipaddress
import zipfile
import hashlib
import urllib.request
from collections import defaultdict
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier

# Windows console encoding safety
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory,
    send_file, jsonify, Response, abort
)

# -----------------------------------------------------------------------------
# Configuration & Constants
# -----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RECORDS_DIR = os.path.join(BASE_DIR, "records")
LEDGER_FILE = os.path.join(BASE_DIR, "blockchain_ledger.json")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or "Admin@123"
# Ensure records directory exists
os.makedirs(RECORDS_DIR, exist_ok=True)

# Pre-seeded users (No registration page needed as requested)
PRESEEDED_USERS = {
    "Rushyanth": "23K81A7333",
    "Ruthika": "23K81A7307",
    "Venkat": "23K81A7317"
}

# In-memory security tracking structures & persistence
BLACKLIST_FILE = os.path.join(BASE_DIR, "blacklist.json")
login_failed_attempts = defaultdict(int)    # username -> failed count
blacklisted_users = set()                    # locked username set
blacklisted_ips = set()                      # locked IP address set
request_velocity_tracker = defaultdict(list) # ip -> list of recent timestamps

# Persistent state dictionaries for dynamic management
ACTIVE_BLOCKLIST = {}  # {ip: {"reason": ..., "timestamp": ...}}
USER_LOCKOUTS = {}     # {username: {"locked": True, "failed_attempts": ...}}
REQUEST_TRACKER = {}   # {ip: [timestamps]}

def is_localhost_ip(ip):
    """
    Checks if an IP address is a local loopback/development address.
    Localhost is permanently exempt from IP blacklisting so developers/testers
    are never locked out of the authentication portal.
    """
    if not ip:
        return True
    ip = ip.strip()
    return ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127.")

def blacklist_ip_if_remote(ip):
    """
    Blacklists external attacker IPs while ensuring localhost is permanently exempt.
    """
    if not is_localhost_ip(ip):
        blacklisted_ips.add(ip)

def save_blacklist():
    try:
        # Exclude localhost from saved blacklisted IPs
        safe_ips = [ip for ip in blacklisted_ips if not is_localhost_ip(ip)]
        with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "users": list(blacklisted_users),
                "ips": safe_ips
            }, f, indent=2)
    except Exception as e:
        print(f"[Blacklist Save Error] {e}")

def load_blacklist():
    if os.path.exists(BLACKLIST_FILE):
        try:
            with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                blacklisted_users.clear()
                blacklisted_users.update(data.get("users", []))
                # Ensure localhost is permanently exempt from IP blacklist
                safe_ips = [ip for ip in data.get("ips", []) if not is_localhost_ip(ip)]
                blacklisted_ips.clear()
                blacklisted_ips.update(safe_ips)
        except Exception as e:
            print(f"[Blacklist Load Error] {e}")

# Load persisted blacklist on boot (ignoring localhost)
load_blacklist()

MAX_DOWNLOAD_LIMIT = 10                      # Strict record download security limit
MAX_LOGIN_ATTEMPTS = 3                      # Brute-force threshold
VELOCITY_WINDOW_SECONDS = 2.0               # Sliding window for bot detection
VELOCITY_MAX_REQUESTS = 8                   # Max hits allowed within window


def initialize_threat_models():
    normal_behavior = np.array([
        [download_count, failed_attempts, velocity]
        for download_count in range(MAX_DOWNLOAD_LIMIT + 1)
        for failed_attempts in range(MAX_LOGIN_ATTEMPTS)
        for velocity in range(6)
    ], dtype=float)
    attack_behavior = np.array(
        [[download_count, failed_attempts, velocity]
         for download_count in range(MAX_DOWNLOAD_LIMIT + 1, 31)
         for failed_attempts in range(MAX_LOGIN_ATTEMPTS + 1)
         for velocity in range(13)]
        + [[download_count, failed_attempts, velocity]
           for download_count in range(MAX_DOWNLOAD_LIMIT + 1)
           for failed_attempts in range(MAX_LOGIN_ATTEMPTS, 7)
           for velocity in range(6)]
        + [[download_count, failed_attempts, velocity]
           for download_count in range(MAX_DOWNLOAD_LIMIT + 1)
           for failed_attempts in range(MAX_LOGIN_ATTEMPTS)
           for velocity in range(6, 13)],
        dtype=float
    )

    isolation_forest = IsolationForest(
        n_estimators=50,
        contamination=0.05,
        random_state=42
    )
    isolation_forest.fit(normal_behavior)

    traffic_features = np.vstack((normal_behavior, attack_behavior))
    traffic_labels = np.concatenate((
        np.zeros(len(normal_behavior), dtype=int),
        np.ones(len(attack_behavior), dtype=int)
    ))
    traffic_classifier = RandomForestClassifier(
        n_estimators=100,
        class_weight="balanced",
        random_state=42
    )
    traffic_classifier.fit(traffic_features, traffic_labels)
    return isolation_forest, traffic_classifier


ISOLATION_FOREST, RANDOM_FOREST_CLASSIFIER = initialize_threat_models()


# -----------------------------------------------------------------------------
# Proxy-Aware Client IP Extraction & Real-Time Geolocation Intelligence
# -----------------------------------------------------------------------------
def get_client_ip():
    """
    Extracts the true client IP address, properly handling ngrok tunnels,
    Cloudflare, reverse proxies, and mobile network forward headers.
    """
    remote_addr = request.remote_addr or "127.0.0.1"

    # Trust forwarding headers only when a local tunnel/proxy connects to Flask.
    try:
        proxy_is_local = ipaddress.ip_address(remote_addr).is_loopback
    except ValueError:
        proxy_is_local = remote_addr == "localhost"

    if not proxy_is_local:
        return remote_addr

    # Ngrok and local reverse proxies provide the original client in this header.
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        for forwarded_ip in xff.split(","):
            try:
                return str(ipaddress.ip_address(forwarded_ip.strip()))
            except ValueError:
                continue

    x_real = request.headers.get("X-Real-IP")
    if x_real and x_real.strip():
        try:
            return str(ipaddress.ip_address(x_real.strip()))
        except ValueError:
            pass

    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip and cf_ip.strip():
        try:
            return str(ipaddress.ip_address(cf_ip.strip()))
        except ValueError:
            pass

    return remote_addr


def get_ip_geolocation(ip):
    """
    Queries public IP geolocation API to resolve geographic forensics (Country, City, Region, ISP).
    Gracefully handles local loopback and private LAN subnets while resolving real public IPs from ngrok/mobile.
    """
    # Handle loopback / developer host
    if not ip or ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127."):
        return {
            "country": "Localhost / Internal Host",
            "city": "Cyber Range Workstation",
            "region": "Loopback Enclave",
            "isp": "Local Loopback Adapter",
            "ip": ip or "127.0.0.1"
        }

    # Handle private Wi-Fi / LAN mobile connections
    if ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        return {
            "country": "Local Wi-Fi Network / LAN",
            "city": "Connected Mobile Device",
            "region": "Intranet Wireless",
            "isp": "Local Wi-Fi Gateway",
            "ip": ip
        }

    # Query public geolocation for real external/ngrok IPs
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,regionName,isp,query"
        req = urllib.request.Request(url, headers={"User-Agent": "CyberGuard-SOC/2.0"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown Country"),
                    "city": data.get("city", "Unknown City"),
                    "region": data.get("regionName", "Unknown Region"),
                    "isp": data.get("isp", "Unknown Provider"),
                    "ip": data.get("query", ip)
                }
    except Exception as e:
        print(f"[Geo Warning] Geolocation lookup skipped for {ip}: {e}")

    return {
        "country": "External Node",
        "city": "Public Mobile/WAN Gateway",
        "region": "External Network",
        "isp": "Public Carrier / ISP",
        "ip": ip
    }


def get_latest_record_entries(limit=10):
    record_files = []
    for filename in os.listdir(RECORDS_DIR):
        match = re.fullmatch(r"record_(\d+)\.txt", filename, re.IGNORECASE)
        path = os.path.join(RECORDS_DIR, filename)
        if match and os.path.isfile(path):
            record_files.append((int(match.group(1)), filename, path))

    latest_files = sorted(record_files, key=lambda entry: entry[0], reverse=True)[:limit]
    entries = []
    for _, filename, path in latest_files:
        with open(path, "r", encoding="utf-8") as record_file:
            entries.append({
                "filename": filename,
                "content": record_file.read(),
                "modified_at": datetime.fromtimestamp(
                    os.path.getmtime(path)
                ).isoformat(timespec="seconds")
            })
    return entries


# -----------------------------------------------------------------------------
# Immutable SHA-256 Blockchain Ledger
# -----------------------------------------------------------------------------
class Block:
    def __init__(self, index, timestamp, threat_data, previous_hash, nonce=0, current_hash=None):
        self.index = index
        self.timestamp = timestamp
        self.threat_data = threat_data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.current_hash = current_hash or self.calculate_hash()

    def calculate_hash(self):
        """
        Calculates SHA-256 cryptographic hash over block payload.
        """
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "threat_data": self.threat_data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode("utf-8")).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "timestamp_formatted": datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "threat_data": self.threat_data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "current_hash": self.current_hash
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            index=data["index"],
            timestamp=data["timestamp"],
            threat_data=data["threat_data"],
            previous_hash=data["previous_hash"],
            nonce=data.get("nonce", 0),
            current_hash=data.get("current_hash")
        )


class BlockchainLedger:
    def __init__(self, difficulty=2, storage_file=LEDGER_FILE):
        self.difficulty = difficulty
        self.storage_file = storage_file
        self.chain = []

        if not self.load_from_file():
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis_threat = {
            "violation_type": "GENESIS_ROOT_INIT",
            "username": "SYSTEM_SECURITY_CORE",
            "ip_address": "127.0.0.1",
            "geolocation": {
                "country": "CyberGuard Sentinel",
                "city": "Core Enclave",
                "region": "Root",
                "isp": "Cryptographic Root Anchor"
            },
            "details": "Root of Trust established. Proof-of-Work SHA-256 ledger initialized.",
            "action_taken": "LEDGER_SEALED"
        }
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            threat_data=genesis_threat,
            previous_hash="0" * 64,
            nonce=0
        )
        self.proof_of_work(genesis_block)
        self.chain.append(genesis_block)
        self.save_to_file()

    def get_latest_block(self):
        return self.chain[-1]

    def proof_of_work(self, block):
        """
        Executes SHA-256 Proof-of-Work mining finding target difficulty prefix ('00').
        """
        prefix = "0" * self.difficulty
        while not block.current_hash.startswith(prefix):
            block.nonce += 1
            block.current_hash = block.calculate_hash()
        return block

    def record_threat(self, username, ip_address, violation_type, details, geolocation=None):
        """
        Appends a newly mined forensic threat block to the chain.
        """
        if geolocation is None:
            geolocation = get_ip_geolocation(ip_address)

        threat_data = {
            "violation_type": violation_type,
            "username": username,
            "ip_address": ip_address,
            "geolocation": geolocation,
            "details": details,
            "action_taken": "ZERO_TRUST_SESSION_TERMINATION_AND_BLOCKLISTED",
            "severity": "CRITICAL_SEV_1"
        }

        latest = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            threat_data=threat_data,
            previous_hash=latest.current_hash,
            nonce=0
        )

        self.proof_of_work(new_block)
        self.chain.append(new_block)
        self.save_to_file()
        print(f"\n[BLOCKCHAIN] Sealed Block #{new_block.index} [Hash: {new_block.current_hash}] for {violation_type}")
        return new_block

    def is_valid(self):
        """
        Verifies SHA-256 cryptographic hashes and parent linkages across all blocks.
        """
        prefix = "0" * self.difficulty
        if not self.chain:
            return False, "Ledger is empty; genesis block is missing."

        for i, curr in enumerate(self.chain):
            if curr.current_hash != curr.calculate_hash():
                return False, f"Block #{curr.index} has been altered. Hash mismatch detected."

            if curr.index != i:
                return False, f"Block position {i} contains unexpected index #{curr.index}."

            expected_previous_hash = "0" * 64 if i == 0 else self.chain[i - 1].current_hash
            if curr.previous_hash != expected_previous_hash:
                return False, f"Block #{curr.index} has an invalid previous_hash link."

            if not curr.current_hash.startswith(prefix):
                return False, f"Block #{curr.index} violates proof-of-work difficulty rule."

        return True, "Chain integrity 100% verified against SHA-256 cryptographic signatures."

    def save_to_file(self):
        try:
            with open(self.storage_file, "w", encoding="utf-8") as f:
                json.dump([b.to_dict() for b in self.chain], f, indent=2)
        except Exception as e:
            print(f"[Ledger Error] Failed saving chain: {e}")

    def load_from_file(self):
        if not os.path.exists(self.storage_file):
            return False
        try:
            with open(self.storage_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not data:
                    return False
                self.chain = [Block.from_dict(d) for d in data]
                return True
        except Exception as e:
            print(f"[Ledger Error] Failed loading chain: {e}")
            return False

    def get_all_blocks(self):
        self.load_from_file()
        return [b.to_dict() for b in self.chain]


# Instantiate global singleton blockchain ledger
ledger = BlockchainLedger()


# -----------------------------------------------------------------------------
# Security Middleware / Velocity Bot Monitor
# -----------------------------------------------------------------------------
@app.before_request
def enforce_security_barriers():
    """
    Enforces blacklist checks and request velocity / automated bot detection.
    """
    # Always allow static files, login portal, and recovery endpoints
    if request.path.startswith("/admin/") or request.path == "/ledger" or request.path in (
        "/", "/login", "/favicon.ico", "/blocked", "/api/verify_chain"
    ):
        return

    client_ip = get_client_ip()

    # 1. Check IP Blacklist (Exempt localhost)
    if not is_localhost_ip(client_ip) and (
        client_ip in blacklisted_ips or client_ip in ACTIVE_BLOCKLIST
    ):
        return redirect(url_for("blocked_page", reason="IP address is permanently blacklisted."))

    # 2. Check Username Blacklist for logged in session
    username = session.get("username")
    if username and username in blacklisted_users:
        session.clear()
        return redirect(url_for("blocked_page", reason="Account has been locked by autonomous defense."))

    # 3. Velocity / Automated Bot Monitoring
    now = time.time()
    timestamps = request_velocity_tracker[client_ip]
    # Prune timestamps older than window
    request_velocity_tracker[client_ip] = [t for t in timestamps if now - t < VELOCITY_WINDOW_SECONDS]
    request_velocity_tracker[client_ip].append(now)

    if len(request_velocity_tracker[client_ip]) > VELOCITY_MAX_REQUESTS:
        hits = len(request_velocity_tracker[client_ip])
        # Clear tracker immediately to avoid reentrant loops
        request_velocity_tracker[client_ip].clear()

        print(f"\n[SECURITY ALERT] Request velocity spike from IP {client_ip} ({hits} hits in {VELOCITY_WINDOW_SECONDS}s)!")
        
        # Blacklist remote IP & terminate session
        blacklist_ip_if_remote(client_ip)
        if not is_localhost_ip(client_ip):
            ACTIVE_BLOCKLIST[client_ip] = {
                "reason": "HIGH_VELOCITY_SCRAPER_BOT",
                "timestamp": now
            }
        target_user = session.get("username", "automated_bot_scraper")
        if target_user in PRESEEDED_USERS:
            blacklisted_users.add(target_user)
        save_blacklist()
        session.clear()

        # Geolocation & Blockchain Logging
        geo = get_ip_geolocation(client_ip)
        details = f"Automated bot velocity exceeded: {hits} requests in {VELOCITY_WINDOW_SECONDS}s."
        block = ledger.record_threat(
            username=target_user,
            ip_address=client_ip,
            violation_type="HIGH_VELOCITY_SCRAPER_BOT",
            details=details,
            geolocation=geo
        )

        return redirect(url_for(
            "blocked_page",
            violation_type="HIGH_VELOCITY_SCRAPER_BOT",
            username=target_user,
            ip_address=client_ip,
            details=details,
            block_index=block.index,
            block_hash=block.current_hash
        ))


# -----------------------------------------------------------------------------
# Static Routing for Confidential Records (Requirement 1)
# -----------------------------------------------------------------------------
@app.route("/records/<path:filename>")
def serve_record(filename):
    """
    Statically serves text records from the records/ dataset directory.
    """
    if not filename.lower().endswith(".txt"):
        abort(404)
    if not session.get("username"):
        return redirect(url_for("login"))
    if session["username"] in blacklisted_users:
        session.clear()
        return redirect(url_for("blocked_page", reason="Account has been locked by autonomous defense."))
    return send_from_directory(RECORDS_DIR, filename)


# -----------------------------------------------------------------------------
# Authentication Routes & Brute-Force Defense (Requirement 2)
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    """
    Login portal with pre-seeded credentials and 3-strike brute-force defense.
    """
    if "username" in session:
        return redirect(url_for("dashboard"))

    client_ip = get_client_ip()
    recovery_values = request.form if request.method == "POST" else request.args
    recovery_ip = recovery_values.get("recovery_ip", "").strip()
    recovery_username = recovery_values.get("recovery_username", "").strip()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        is_admin_login = bool(ADMIN_PASSWORD) and username == "admin" and hmac.compare_digest(
            password, ADMIN_PASSWORD
        )

        # Check if already blacklisted
        admin_recovery_needed = (
            username in blacklisted_users
            or username in USER_LOCKOUTS
            or (
                not is_localhost_ip(client_ip)
                and (client_ip in blacklisted_ips or client_ip in ACTIVE_BLOCKLIST)
            )
            or (
                recovery_ip
                and (recovery_ip in blacklisted_ips or recovery_ip in ACTIVE_BLOCKLIST)
            )
            or (
                recovery_username
                and (recovery_username in blacklisted_users or recovery_username in USER_LOCKOUTS)
            )
        )
        if admin_recovery_needed and not is_admin_login:
            return redirect(url_for(
                "blocked_page",
                violation_type="ACCOUNT_LOCKED",
                username=username,
                ip_address=client_ip,
                details="Access Denied: Account is locked due to security policy violations."
            ))

        # Validate against pre-seeded credentials
        if is_admin_login or (username in PRESEEDED_USERS and PRESEEDED_USERS[username] == password):
            # Login successful: Reset failed attempts counter
            login_failed_attempts[username] = 0
            session["username"] = username
            if is_admin_login and admin_recovery_needed:
                return redirect(url_for(
                    "blocked_page",
                    violation_type="ADMIN_RECOVERY",
                    username=recovery_username or username,
                    ip_address=recovery_ip or client_ip,
                    details="Admin authenticated to restore access from a locked IP or account."
                ))
            flash(f"Access granted. Welcome, {username}! Real-time surveillance active.", "success")
            return redirect(url_for("dashboard"))

        else:
            # Failed attempt handling
            login_failed_attempts[username] += 1
            attempts_left = MAX_LOGIN_ATTEMPTS - login_failed_attempts[username]

            print(f"[AUTH FAIL] Failed login attempt #{login_failed_attempts[username]} for user '{username}' from {client_ip}")

            # Check Brute-Force threshold
            if login_failed_attempts[username] >= MAX_LOGIN_ATTEMPTS:
                print(f"[BRUTE-FORCE ALERT] User '{username}' exceeded {MAX_LOGIN_ATTEMPTS} failed attempts. Lockout triggered!")
                
                # Blacklist user and remote IP (localhost is exempt)
                blacklisted_users.add(username)
                blacklist_ip_if_remote(client_ip)
                save_blacklist()

                # Fetch Geolocation & Mine to Blockchain
                geo = get_ip_geolocation(client_ip)
                details = f"Exceeded {MAX_LOGIN_ATTEMPTS} consecutive failed authentication attempts. Account locked."
                block = ledger.record_threat(
                    username=username,
                    ip_address=client_ip,
                    violation_type="BRUTE_FORCE_LOGIN_ATTACK",
                    details=details,
                    geolocation=geo
                )

                return redirect(url_for(
                    "blocked_page",
                    violation_type="BRUTE_FORCE_LOGIN_ATTACK",
                    username=username,
                    ip_address=client_ip,
                    details=details,
                    block_index=block.index,
                    block_hash=block.current_hash
                ))
            else:
                flash(f"Invalid credentials. Security warning: {attempts_left} attempt(s) remaining before account lockout.", "danger")

    return render_template(
        "login.html",
        recovery_ip=recovery_ip,
        recovery_username=recovery_username
    )


# -----------------------------------------------------------------------------
# Confidential Record Repository & Bulk Exfiltration Defense (Requirement 3)
# -----------------------------------------------------------------------------
@app.route("/dashboard")
def dashboard():
    """
    Renders the protected server log record dataset and download controls.
    """
    username = session.get("username")
    if not username:
        flash("Authentication required to access protected server log records.", "info")
        return redirect(url_for("login"))

    if username in blacklisted_users:
        session.clear()
        return redirect(url_for("blocked_page", reason="Account is blacklisted."))

    client_ip = get_client_ip()

    # Read and sort record files numerically: record_1.txt, record_2.txt ...
    raw_files = [
        filename for filename in os.listdir(RECORDS_DIR)
        if filename.lower().endswith(".txt")
        and os.path.isfile(os.path.join(RECORDS_DIR, filename))
    ]
    def extract_number(name):
        match = re.search(r"\d+", name)
        return int(match.group()) if match else 0

    records = sorted(raw_files, key=extract_number)

    geo = get_ip_geolocation(client_ip)
    return render_template(
        "dashboard.html",
        records=records,
        latest_records=get_latest_record_entries(),
        username=username,
        client_ip=client_ip,
        geo=geo
    )


@app.route("/download", methods=["POST"])
def download_records():
    """
    THE CRITICAL DEFENSE INTERCEPTOR:
    - If user selects <= 10 records: Bundles and serves a safe ZIP archive.
    - If user selects > 10 records: Triggers Bulk Exfiltration Defense, locks account,
      records incident in blockchain, and redirects to Access Denied.
    """
    username = session.get("username")
    client_ip = get_client_ip()

    if not username:
        flash("Session expired. Please log in.", "danger")
        return redirect(url_for("login"))

    now = time.time()
    selected_records = request.form.getlist("selected_records")
    count = len(selected_records)

    # Security scanners & path traversal checks
    user_agent = request.headers.get("User-Agent", "").lower()
    scanner_sigs = ["sqlmap", "nikto"]
    traversal = any(
        (".." in filename or "/" in filename or "\\" in filename or not filename.lower().endswith(".txt"))
        for filename in selected_records
    )
    scanner = any(sig in user_agent for sig in scanner_sigs)
    if traversal or scanner:
        ACTIVE_BLOCKLIST[client_ip] = {"reason": "PATH_TRAVERSAL_OR_SCANNER", "timestamp": now}
        geo = get_ip_geolocation(client_ip)
        block = ledger.record_threat(
            username=username,
            ip_address=client_ip,
            violation_type="PATH_TRAVERSAL_OR_SCANNER",
            details="Path traversal or scanner signature detected.",
            geolocation=geo
        )
        return jsonify({"error": "Forbidden"}), 403

    if count == 0:
        flash("No server log records selected. Please choose records to export.", "warning")
        return redirect(url_for("dashboard"))

    velocity = sum(
        1 for timestamp in request_velocity_tracker[client_ip]
        if now - timestamp < VELOCITY_WINDOW_SECONDS
    )
    features = np.array([[
        count,
        login_failed_attempts.get(username, 0),
        velocity
    ]], dtype=float)
    anomaly_detected = ISOLATION_FOREST.predict(features)[0] == -1
    malicious_traffic = RANDOM_FOREST_CLASSIFIER.predict(features)[0] == 1

    if (anomaly_detected or malicious_traffic) and count <= MAX_DOWNLOAD_LIMIT:
        details = (
            "AI threat detection flagged this request "
            f"(downloads={count}, failed_attempts={int(features[0, 1])}, velocity={velocity})."
        )
        ACTIVE_BLOCKLIST[client_ip] = {
            "reason": "AI_PREDICTED_CYBER_ATTACK",
            "timestamp": now
        }
        blacklist_ip_if_remote(client_ip)
        blacklisted_users.add(username)
        USER_LOCKOUTS[username] = {
            "locked": True,
            "failed_attempts": login_failed_attempts.get(username, 0)
        }
        save_blacklist()
        session.clear()

        block = ledger.record_threat(
            username=username,
            ip_address=client_ip,
            violation_type="AI_PREDICTED_CYBER_ATTACK",
            details=details,
            geolocation=get_ip_geolocation(client_ip)
        )
        return redirect(url_for(
            "blocked_page",
            violation_type="AI_PREDICTED_CYBER_ATTACK",
            username=username,
            ip_address=client_ip,
            details=details,
            block_index=block.index,
            block_hash=block.current_hash,
            nonce=block.nonce
        ))

    # === CORE SECURITY DECISION POINT ===
    if count > MAX_DOWNLOAD_LIMIT:
        # MALICIOUS BULK EXFILTRATION ATTACK INTERCEPTED!
        print(f"\n{'='*70}")
        print(f"[CRITICAL ALERT] DATA EXFILTRATION ATTACK INTERCEPTED!")
        print(f"Operator: {username} | IP: {client_ip} | Requested: {count} server log records (Max Limit: {MAX_DOWNLOAD_LIMIT})")
        print(f"{'='*70}")

        # Step 1: Immediate zero-trust lockout
        blacklisted_users.add(username)
        blacklist_ip_if_remote(client_ip)
        save_blacklist()
        session.clear()

        # Step 2: Capture Real-Time IP Geolocation
        geo = get_ip_geolocation(client_ip)

        # Step 3: Mine Immutable Cryptographic Block into Blockchain
        details = (
            f"Unauthorized bulk server log record exfiltration attempt: {count} records requested in a single batch. "
            f"Strict security quota of {MAX_DOWNLOAD_LIMIT} records violated. Zero-trust lockout engaged."
        )
        block = ledger.record_threat(
            username=username,
            ip_address=client_ip,
            violation_type="BULK_DATA_EXFILTRATION",
            details=details,
            geolocation=geo
        )

        # Step 4: Route immediately to Access Denied / Lockout Screen
        return redirect(url_for(
            "blocked_page",
            violation_type="BULK_DATA_EXFILTRATION",
            username=username,
            ip_address=client_ip,
            details=details,
            block_index=block.index,
            block_hash=block.current_hash,
            nonce=block.nonce
        ))

    else:
        # ✅ NORMAL / AUTHORIZED EXPORT (count <= 10)
        print(f"[SAFE EXPORT] Serving authorized batch of {count} server log records to '{username}'")

        # Create in-memory zip archive
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for record_name in selected_records:
                safe_name = os.path.basename(record_name)
                record_path = os.path.join(RECORDS_DIR, safe_name)
                if os.path.isfile(record_path):
                    zip_file.write(record_path, arcname=safe_name)

        zip_buffer.seek(0)
        filename = f"CyberGuard_Server_Log_Records_{int(time.time())}.zip"
        return send_file(
            zip_buffer,
            mimetype="application/zip",
            as_attachment=True,
            download_name=filename
        )


# -----------------------------------------------------------------------------
# Access Denied / Security Lockout Page
# -----------------------------------------------------------------------------
@app.route("/blocked")
def blocked_page():
    """
    Renders high-severity autonomous defense lockout screen.
    """
    violation_type = request.args.get("violation_type", "SECURITY_POLICY_VIOLATION")
    username = request.args.get("username", "Revoked Operator")
    client_ip = request.args.get("ip_address") or get_client_ip()
    details = request.args.get("details", "Unauthorized operation flagged by autonomous defense.")
    
    geo = get_ip_geolocation(client_ip)

    block = None
    if request.args.get("block_index"):
        block = {
            "index": request.args.get("block_index"),
            "current_hash": request.args.get("block_hash"),
            "nonce": request.args.get("nonce", "1")
        }
    else:
        if len(ledger.chain) > 1:
            latest = ledger.chain[-1]
            block = {
                "index": latest.index,
                "current_hash": latest.current_hash,
                "nonce": latest.nonce
            }

    return render_template(
        "blocked.html",
        violation_type=violation_type,
        username=username,
        ip_address=client_ip,
        details=details,
        geo=geo,
        block=block
    )


# -----------------------------------------------------------------------------
# Blockchain Audit Ledger Route & Controls (Requirement 6)
# -----------------------------------------------------------------------------
@app.route("/ledger")
def view_ledger():
    """
    Displays the immutable SHA-256 blockchain audit trail loaded directly from blockchain_ledger.json.
    """
    ledger.load_from_file()
    load_blacklist()
    blocks = ledger.get_all_blocks()
    client_ip = get_client_ip()
    return render_template(
        "ledger.html",
        blocks=blocks,
        blocked_users=sorted(list(blacklisted_users)),
        blocked_ips=sorted(list(blacklisted_ips)),
        blocked_count=len(blacklisted_users) + len(blacklisted_ips),
        client_ip=client_ip
    )


@app.route("/api/live_stream")
def api_live_stream():
    if not session.get("username"):
        response = jsonify({"error": "Authentication required."})
        response.status_code = 401
        response.headers["Cache-Control"] = "no-store"
        return response
    response = jsonify({
        "entries": get_latest_record_entries(),
        "timestamp": datetime.now().isoformat(timespec="seconds")
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/verify_chain")
def api_verify_chain():
    """
    Cryptographically verifies SHA-256 hashes and block parent linkage.
    """
    if not ledger.load_from_file():
        return jsonify({
            "is_valid": False,
            "message": "Ledger file could not be loaded for cryptographic audit.",
            "total_blocks": 0,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }), 500
    is_valid, msg = ledger.is_valid()
    return jsonify({
        "is_valid": is_valid,
        "message": msg,
        "total_blocks": len(ledger.chain),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


@app.route("/admin/export_report")
def export_forensic_report():
    require_admin()
    if not ledger.load_from_file():
        abort(500, description="Blockchain ledger file could not be loaded for forensic export.")
    load_blacklist()
    blocks = [block.to_dict() for block in ledger.chain]
    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            "threat_count": sum(
                1 for block in blocks
                if block["threat_data"].get("violation_type") != "GENESIS_ROOT_INIT"
            ),
            "blocked_ip_count": len(set(blacklisted_ips) | set(ACTIVE_BLOCKLIST)),
            "locked_user_count": len(set(blacklisted_users) | set(USER_LOCKOUTS)),
            "block_count": len(blocks)
        },
        "blocked_ips": sorted(set(blacklisted_ips) | set(ACTIVE_BLOCKLIST)),
        "locked_users": sorted(set(blacklisted_users) | set(USER_LOCKOUTS)),
        "threats": [
            {
                "block_index": block["index"],
                "timestamp": block["timestamp_formatted"],
                "violation_type": block["threat_data"].get("violation_type"),
                "username": block["threat_data"].get("username"),
                "ip_address": block["threat_data"].get("ip_address"),
                "geolocation": block["threat_data"].get("geolocation"),
                "details": block["threat_data"].get("details"),
                "nonce": block["nonce"],
                "previous_hash": block["previous_hash"],
                "current_hash": block["current_hash"]
            }
            for block in blocks
            if block["threat_data"].get("violation_type") != "GENESIS_ROOT_INIT"
        ],
        "blockchain": [
            {
                "index": block["index"],
                "previous_hash": block["previous_hash"],
                "current_hash": block["current_hash"]
            }
            for block in blocks
        ]
    }
    report_file = io.BytesIO(json.dumps(report, indent=2).encode("utf-8"))
    return send_file(
        report_file,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"cyberguard_forensic_report_{datetime.now():%Y%m%d_%H%M%S}.json"
    )


@app.route("/api/ping")
def api_ping():
    """
    Lightweight, attachment-free endpoint for testing request velocity.
    """
    return jsonify({"status": "ok", "timestamp": time.time()})


@app.route("/admin/clear_ip_blacklist", methods=["POST"])
def clear_ip_blacklist():
    """
    Clears all active IP blacklists and velocity restrictions instantly.
    """
    require_admin()
    return reset_security_lockouts()


@app.route("/admin/unblock_ip/<path:ip_address>", methods=["POST"])
def unblock_ip(ip_address):
    """
    Allows admin to unblock an individual IP address.
    """
    require_admin()
    blacklisted_ips.discard(ip_address)
    ACTIVE_BLOCKLIST.pop(ip_address, None)
    REQUEST_TRACKER.pop(ip_address, None)
    request_velocity_tracker.pop(ip_address, None)
    save_blacklist()
    flash(f"IP address '{ip_address}' has been unblocked.", "success")
    return redirect(url_for("view_ledger"))


@app.route("/admin/unblock/<username>", methods=["POST"])
def unblock_user(username):
    """
    Allows evaluators to unblock a test user with 1 click during presentation.
    """
    require_admin()
    blacklisted_users.discard(username)
    USER_LOCKOUTS.pop(username, None)
    login_failed_attempts[username] = 0
    save_blacklist()
    flash(f"User account '{username}' has been successfully unblocked.", "success")
    return redirect(url_for("view_ledger"))


@app.route("/admin/unblock", methods=["POST"])
def admin_unblock():
    require_admin()
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Expected a JSON object."}), 400

    ip = data.get("ip")
    username = data.get("username")
    if ip is not None and not isinstance(ip, str):
        return jsonify({"error": "IP address must be a string."}), 400
    if username is not None and not isinstance(username, str):
        return jsonify({"error": "Username must be a string."}), 400

    ip = ip.strip() if ip else None
    username = username.strip() if username else None
    if not ip and not username:
        return jsonify({"error": "Specify an IP address, username, or both."}), 400

    if ip:
        ACTIVE_BLOCKLIST.pop(ip, None)
        blacklisted_ips.discard(ip)
        REQUEST_TRACKER.pop(ip, None)
        request_velocity_tracker.pop(ip, None)
    if username:
        USER_LOCKOUTS.pop(username, None)
        blacklisted_users.discard(username)
        login_failed_attempts[username] = 0
    save_blacklist()
    client_ip = ip or get_client_ip()
    ledger.record_threat(
        username=username or "admin",
        ip_address=client_ip,
        violation_type="ADMIN_OVERRIDE_UNBLOCK",
        details="Admin unblock override executed.",
        geolocation=get_ip_geolocation(client_ip)
    )
    return jsonify({"status": "unblocked"}), 200
@app.route("/admin/reset_demo", methods=["POST"])
def reset_demo():
    """
    Resets all blacklisted accounts, IP restrictions, and velocity counters to clean state.
    """
    require_admin()
    return reset_security_lockouts()


def require_admin():
    if session.get("username") != "admin":
        abort(403)


def reset_security_lockouts():
    blacklisted_users.clear()
    blacklisted_ips.clear()
    ACTIVE_BLOCKLIST.clear()
    USER_LOCKOUTS.clear()
    REQUEST_TRACKER.clear()
    login_failed_attempts.clear()
    request_velocity_tracker.clear()
    save_blacklist()
    flash("All account lockouts, IP blacklists, and velocity restrictions have been cleared.", "success")
    return redirect(url_for("view_ledger"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Session terminated securely.", "info")
    return redirect(url_for("login"))


# -----------------------------------------------------------------------------
# Server Entry Point
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  [CYBERGUARD] ADVANCED CYBERSECURITY FRAMEWORK")
    record_count = sum(
        1 for filename in os.listdir(RECORDS_DIR)
        if filename.lower().endswith(".txt")
        and os.path.isfile(os.path.join(RECORDS_DIR, filename))
    )
    print(f"  [DATASET] Confidential Records: {record_count} server log records ready in records/")
    print(f"  [BLOCKCHAIN] Ledger: {len(ledger.chain)} blocks loaded (PoW Difficulty: {ledger.difficulty})")
    print("  [GEOLOCATION] Public IP Geolocation Sensor: ACTIVE")
    print("  [SERVER] Bound to: 0.0.0.0:5000 (Localhost, LAN & ngrok ready)")
    print("  [LOCAL ACCESS]   http://127.0.0.1:5000")
    print("  [REMOTE/MOBILE]  Connect via local network IP or ngrok http 5000")
    print("=" * 70 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
