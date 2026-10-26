# CyberGuard: Advanced Cybersecurity Framework

> **Major Graduation Engineering Project**  
> **Technologies**: Python 3 (Flask), SHA-256 Blockchain (Proof-of-Work), IP Geolocation Telemetry, Brute-Force Interceptor, Velocity Defense.

---

## 📌 Project Overview & System Architecture

**CyberGuard** is an autonomous cybersecurity framework designed to safeguard confidential server log records against:
1. **Malicious Bulk Data Exfiltration**: Unauthorized attempts to bulk-download restricted server log and audit records.
2. **Credential Brute-Force Attacks**: Automated password guessing attacks.
3. **Automated High-Velocity Bot Scraping**: Rapid-fire API and asset scraping bots.
4. **Log Tampering & Repudiation**: Log modification attempts eliminated via an immutable SHA-256 blockchain ledger.

---

## 📂 Exact Project Directory Structure

```text
CyberSecurity/
│
├── app.py                     # Main Flask server, security engine, and blockchain logic
├── test_cyberguard.py         # Automated verification suite
├── blockchain_ledger.json     # Persistent JSON storage for the SHA-256 blockchain
├── populate_logs.py           # Generates 100 structured synthetic server log records
│
├── records/                   # Dataset folder containing 100 synthetic server log records
│   ├── record_1.txt           # Structured confidential audit record
│   ├── record_2.txt
│   └── ...                    # (record_3.txt to record_100.txt)
│
└── templates/                 # HTML UI views
    ├── login.html             # Login portal with brute-force defense & quick-fill buttons
    ├── dashboard.html         # Confidential record repository & export controls
    ├── blocked.html           # Access Denied / Security lockout forensic dossier
    └── ledger.html            # Immutable blockchain audit log explorer with live validator
```

---

## 🛡️ Core Functional Modules

### 1. Flask Static Routing for Confidential Records
- Text records are served from the `records/` folder via `/records/<filename>` and listed on the authenticated `/dashboard`.
- Each generated record includes an IP, timestamp, HTTP request line, response status, transferred bytes, User-Agent, SHA-256 integrity signature, and classification level.

### 2. Pre-Seeded Authentication & 3-Strike Brute-Force Defense
- **Pre-seeded Accounts** are configured in `PRESEEDED_USERS`.
- **Administrator** signs in with username `admin` and the password configured in `ADMIN_PASSWORD`.
- **Brute-Force Interceptor**: Tracks failed attempts. Upon **3 consecutive failed logins**, the account and client IP are locked, and a threat incident is mined into the blockchain ledger.

### 3. Confidential Server Log Records & Bulk Exfiltration Defense (Core Demo Flow)
- Repository of **100 structured server log records** with export selection controls.
- **Strict Security Quota**: Max **10 records** per export.
  - **Safe Export (<= 10 records)**: Bundles selected `.txt` records into an in-memory ZIP archive.
  - **Malicious Exfiltration Attack (> 10 records)**: The backend intercepts the request, terminates the session, blacklists the user and IP, resolves IP geolocation, mines an immutable SHA-256 block, and redirects to the **Access Denied** alert screen.

### 4. Request Velocity & Automated Bot Scraper Defense
- Sliding-window frequency monitor. If an automated script or scraper sends rapid requests (exceeding 8 requests in 2 seconds) to `/api/ping`, `/download`, or other protected routes, CyberGuard flags `HIGH_VELOCITY_SCRAPER_BOT`, terminates access, and logs the incident to the blockchain.

### 5. Machine-Learning Threat Detection
- A startup-trained Isolation Forest learns a lightweight baseline of normal download counts, failed-login attempts, and request velocity.
- A Random Forest classifier labels the same traffic features as safe or malicious. Either model can trigger a zero-trust lockout and an `AI_PREDICTED_CYBER_ATTACK` blockchain event.
- Use **Test Request Velocity** on the dashboard to exercise the rapid-request detector without starting a file download or opening a Save As dialog.

### 6. Real-Time IP Geolocation Intelligence Tracking
- Interrogates `http://ip-api.com/json/{ip}` to record attacker location (Country, City, Region, ISP).
- Intelligently handles local loopback (`127.0.0.1`) and campus LAN addresses with designated secure enclave labels.
- The authenticated dashboard displays the active client IP, detected city/country, and ISP.

### 7. Immutable SHA-256 Blockchain Forensic Ledger
- Custom Python `BlockchainLedger` class implementing:
  - Genesis block creation
  - SHA-256 hashing across `[index, timestamp, threat_data, previous_hash, nonce]`
  - **Proof-of-Work (PoW)** consensus targeting a `00` prefix
  - Independent chain integrity validator (`/api/verify_chain`), including genesis hash, block indices, parent linkage, and proof-of-work validation.
  - Full audit visualization at `/ledger`.
  - **Run Cryptographic Audit** on the ledger page to verify the chain interactively.

### 8. SOC Live Stream & Forensic Report
- Authenticated `/api/live_stream` returns the latest 10 numbered server log records as JSON; the dashboard refreshes the stream every 5 seconds.
- Admin-only `/admin/export_report` downloads a JSON incident summary with threat events, blocked IPs, locked users, and ledger hashes.

---

## 🚀 How to Run the Application Locally

### Step 1: Install Dependencies
```bash
pip install flask numpy scikit-learn
```

### Step 2: Generate the Synthetic Server Log Dataset
```bash
python populate_logs.py
```
This creates `records/record_1.txt` through `records/record_100.txt`.

### Step 3: Run the Automated Verification Suite
Verify all sub-systems before demonstrating:
```bash
python test_cyberguard.py
```

### Step 4: Start the Flask Server
Set an administrator password with `ADMIN_PASSWORD` before starting the server (the current development fallback is `Admin@123`). Set `FLASK_SECRET_KEY` to a persistent random secret if sessions must survive server restarts; without it, the app generates a fresh secret at startup.

PowerShell:
```powershell
$env:ADMIN_PASSWORD = "<choose a strong password>"
$env:FLASK_SECRET_KEY = "<choose a separate random secret>"
```

The administrator signs in with username `admin`. If the current IP or account is locked, a successful administrator sign-in opens the recovery screen; its unblock action clears the selected IP and account restrictions.

```bash
python app.py
```
Open your browser and navigate to:
```text
http://127.0.0.1:5000
```

---

## 🎯 Step-by-Step Viva & College Review Demonstration

1. **Demonstrate Login**:
   - Go to `http://127.0.0.1:5000`.
   - Sign in using one of the accounts in `PRESEEDED_USERS` (for example, `Rushyanth`).
   - Click **Authenticate & Access Dataset**.

2. **Demonstrate Safe Record Export (Scenario A)**:
   - On `/dashboard`, select up to 10 server log records.
   - Export the selected records as a ZIP archive.

3. **Demonstrate Bulk Record Exfiltration Defense (Scenario B)**:
   - Select more than 10 records and submit the export.
   - **Result**: The request is intercepted, the session is terminated, the account and IP are blocked, and the incident is recorded on the blockchain before showing the **Access Denied** screen.

4. **Demonstrate Blockchain Forensic Ledger**:
   - Click **"Inspect in Blockchain Ledger"** or visit `http://127.0.0.1:5000/ledger`.
   - Show the review panel:
     - **Block #0**: Genesis Root
     - **Block #1**: `BULK_DATA_EXFILTRATION` threat block containing the affected operator, client IP, geolocation, nonce, previous hash, and current hash starting with `00`.
   - Click **"Verify Chain Integrity"**: Show the green `IMMUTABLE` confirmation.

5. **Demonstrate Brute-Force Defense**:
   - Return to login page. Click **"Test Failed Login"** 3 times.
   - On the 3rd attempt, account lockout triggers, mining Block #2 (`BRUTE_FORCE_LOGIN_ATTACK`) into the blockchain ledger.

6. **Resetting Demo for Repeat Testing**:
   - In `/ledger`, click **"Unblock All / Reset Demo"** to return the system to clean demo state at any time.
