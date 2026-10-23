# SecureLogin AI – Intelligent Login Theft Detection and Alert System

**A Complete Real-World College Project for Third Year Artificial Intelligence & Machine Learning (TY AIML)**

---

## 📌 Project Overview

**SecureLogin AI** is a defense-in-depth web application designed to combat credential theft, brute-force attacks, and unauthorized account takeovers. It integrates:
1. **Application-Level Security Firewall & Rule Engine (INS)**: Stateful sliding-window rate limiting and deterministic 3-attempt account lockout policies.
2. **Machine Learning Anomaly Detection (MLF)**: An unsupervised `IsolationForest` ensemble model from `scikit-learn` that scores login risk based on diurnal patterns, velocity, and failure sequences.
3. **Dual-Channel Incident Response**: Dispatches real SMTP security alert emails and real WhatsApp notifications upon lockout breach.
4. **Data Analysis & Visualization Pipeline (DAV)**: Anonymized, zero-leakage CSV telemetry export directly connectable to **Tableau Desktop / Tableau Public** with 6 college-grade charts.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    User["Client / Browser"] -->|HTTP POST /login| Firewall["Layer 7 Application Firewall"]
    
    subgraph Security_Engine ["Security & Intelligence Layer"]
        Firewall -->|Check IP Sliding Window| RateLimit["Rate Limiter (20 req / 60s)"]
        RateLimit -->|Extract Features| ML["Scikit-Learn Isolation Forest"]
        ML -->|Predict Risk Score (0.0 - 1.0)| RuleEngine["Rule Engine & Lockout Evaluator"]
        RuleEngine -->|Verify Hash (scrypt)| DB[(SQLite Database)]
    end

    subgraph Incident_Response ["Dual-Channel Alert System"]
        RuleEngine -->|If 3rd Consecutive Failure| AlertRouter["Notification Router"]
        AlertRouter -->|TLS / App Password| SMTP["SMTP Email Service"]
        AlertRouter -->|REST API / Twilio| WhatsApp["WhatsApp Messaging Service"]
    end

    subgraph Analytics_Pipeline ["DAV Subject - Tableau"]
        DB -->|Sanitize & Anonymize| CSVExport["exports/tableau_login_data.csv"]
        CSVExport -->|Import Data Source| Tableau["Tableau BI Dashboard"]
    end

    RuleEngine -->|If Valid & Unlocked| SOCDashboard["SOC Web Dashboard"]
```

---

## 📁 Project Folder Structure

```text
secure_login_ai/
│
├── app.py                      # Core Flask web server, route controllers & initialization
├── config.py                   # Centralized application settings & .env loading
├── models.py                   # SQLAlchemy ORM models (User, LoginLog) & password hashing
├── test_system.py              # Automated 8-point verification test suite
├── requirements.txt            # Python package dependencies
├── .env.example                # Template for environment variables
├── .env                        # Active local environment variables
├── README.md                   # Complete academic documentation & submission guide
│
├── security/
│   ├── __init__.py
│   └── firewall.py             # Layer 7 Application Firewall & Rule Engine (INS)
│
├── services/
│   ├── __init__.py
│   ├── email_service.py        # Python SMTP alert dispatcher
│   └── whatsapp_service.py     # Modular WhatsApp alert dispatcher (Twilio / REST)
│
├── ml/
│   ├── __init__.py
│   ├── model.py                # Isolation Forest runtime predictor & fallback heuristics
│   ├── train_model.py          # Synthetic telemetry generator & model training script
│   └── isolation_forest.joblib # Serialized scikit-learn model artifact
│
├── templates/
│   ├── base.html               # Cybersecurity SOC layout with Bootstrap 5 & icons
│   ├── register.html           # Input-validated registration form
│   ├── login.html              # Login interface with security warnings & lockout countdown
│   ├── dashboard.html          # Executive SOC dashboard with Chart.js telemetry
│   ├── login_activity.html     # Security audit log table
│   ├── security_alerts.html    # Incident tracker & alert delivery logs
│   ├── firewall.html           # INS firewall concepts, sliding windows & admin reset
│   ├── ml_detection.html       # MLF Isolation Forest playground & feature breakdown
│   ├── tableau.html            # DAV Tableau data dictionary & chart guide
│   └── profile.html            # User profile & manual alert testing triggers
│
├── static/
│   ├── css/
│   │   └── style.css           # Dark cybersecurity theme (SOC aesthetics)
│   └── js/
│       └── dashboard.js        # Dynamic frontend interactivity
│
└── exports/
    └── tableau_login_data.csv  # Privacy-compliant dataset exported for Tableau
```

---

## ⚙️ Quick Start Installation & Execution

### 1. Open Terminal in VS Code
Ensure you are in the project folder:
```powershell
cd C:\Users\Tejas6822\.gemini\antigravity\scratch\secure_login_ai
```

### 2. Install Required Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Train or Verify the Machine Learning Model
The ML model can be trained or retrained anytime using:
```powershell
python ml/train_model.py
```

### 4. Run the Automated Test Suite
Verify that all 8 components (hashing, lockout, rate limiting, ML scoring, and CSV export) pass:
```powershell
python test_system.py
```

### 5. Launch the Web Application
```powershell
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 🔑 Demo Credentials (Pre-Seeded)

The system automatically initializes a pre-seeded student account for instant testing:
- **Email:** `student@college.edu`
- **Password:** `Student@123`
- **WhatsApp:** `+919876543210`

You can also register brand-new accounts on the `/register` page with your own email and phone number.

---

## 📧 How to Configure Real SMTP Email Alerts

1. Open `.env` in VS Code.
2. For **Gmail**:
   - Go to [Google Account Security](https://myaccount.google.com/security).
   - Ensure **2-Step Verification** is turned ON.
   - Search for **App Passwords** (or navigate to Security -> 2-Step Verification -> App Passwords).
   - Create a new App Password named `SecureLoginAI`.
   - Copy the generated 16-character code (e.g. `abcd efgh ijkl mnop`).
3. Fill in your `.env`:
   ```ini
   SMTP_SERVER=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USERNAME=your_gmail@gmail.com
   SMTP_PASSWORD=abcdefghijklmnop
   SMTP_USE_TLS=True
   ALERT_SENDER_EMAIL=your_gmail@gmail.com
   ```
4. Test the email by logging into the dashboard -> go to **Profile** -> click **Send Test Security Email**!

---

## 📱 How to Configure Real WhatsApp Alerts

The system is modular and supports **Twilio WhatsApp API** (free trial available) or any generic **REST Gateway**:

### Option A: Using Twilio WhatsApp Sandbox (Recommended for Students)
1. Sign up for a free account at [Twilio](https://www.twilio.com).
2. In the Twilio Console, go to **Messaging -> Try it out -> Send a WhatsApp message**.
3. Follow the instructions to join the Twilio Sandbox (e.g. sending `join <sandbox-word>` from your phone to `+1 415 523 8886`).
4. Copy your **Account SID** and **Auth Token** into `.env`:
   ```ini
   TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   TWILIO_AUTH_TOKEN=your_auth_token_here
   TWILIO_WHATSAPP_NUMBER=whatsapp:+14155238886
   ```

*(Note: If no WhatsApp credentials are provided, the system gracefully logs that the service is simulated and does NOT crash).*

---

## 📊 DAV Subject – Tableau Integration & Visualizations

### Step-by-Step Connection Guide:
1. Log into SecureLogin AI and click **DAV / Tableau** in the sidebar.
2. Click **Download Tableau Dataset (CSV)**.
3. Open **Tableau Desktop** or **Tableau Public**.
4. Under *Connect -> To a File*, choose **Text file** and select `tableau_login_data.csv`.
5. Verify column data types:
   - `timestamp` → Date & Time
   - `risk_score` → Number (decimal)
   - `security_status` → String / Dimension

### The 6 Recommended Tableau Charts for Your Viva / Presentation:
1. **Successful vs. Failed Logins**: Donut Chart showing legitimate traffic vs. intrusion attempts.
2. **Suspicious Attempts by Date**: Line trend tracking security incident frequency over days.
3. **Login Attempts by Hour**: Heatmap/Bar chart showing diurnal attack clusters (night vs day).
4. **Blocked Login Count**: Single KPI metric of intrusions stopped by the 3-attempt rule.
5. **ML Risk Score Distribution**: Histogram displaying Isolation Forest separation.
6. **Security Status Summary**: 100% Stacked bar chart summarizing overall system posture.

---

## 🛡️ Academic Concepts (INS & MLF)

### INS Concept: Application-Level Firewall (Layer 7)
- **Why it matters:** Traditional OS and network firewalls inspect Layer 3/4 packet headers (IPs and TCP/UDP ports). They cannot inspect encrypted HTTP payloads or understand that an attacker is trying dictionary passwords.
- **Implementation:** Our Application Firewall evaluates HTTP request frequency (sliding window of 20 requests per 60s per IP), counts failed password events per user, enforces 15-minute lockouts, and prevents user enumeration.

### MLF Concept: Isolation Forest Anomaly Detection
- **Why Isolation Forest:** Traditional classification requires balanced labels (thousands of real attacks). Isolation Forest is an unsupervised tree ensemble that isolates anomalies because they have atypical feature attributes (shorter tree path length).
- **Features Used:**
  1. `failed_attempts`: Consecutive credential mismatches.
  2. `login_hour`: Diurnal metric (0 to 23).
  3. `attempts_last_10m`: Velocity / request frequency.
  4. `is_night_time`: Off-hours indicator.
- **Fail-Safe Design:** Deterministic rule enforcement (lockout on 3 attempts) is always active regardless of whether the ML model is loaded.

---

## 🧪 Demonstration Procedure for College Viva

1. **Demonstrate Normal Login:**
   - Log in with `student@college.edu` and `Student@123`.
   - Show dashboard with 0 failed attempts and low risk score (e.g. `0.08` or `0.32`).
2. **Demonstrate Attack Detection & 3-Attempt Lockout:**
   - Log out.
   - Enter `student@college.edu` with wrong password 3 times in a row.
   - On Attempt 1: Warning shows "2 attempts remaining".
   - On Attempt 2: Warning shows "1 attempt remaining".
   - On Attempt 3: Account is locked for 15 minutes!
   - Show that entering the correct password is now blocked because the account is locked.
3. **Demonstrate Incident Response:**
   - Check the console and **Security Alerts** page to see the incident log.
   - Show the dispatched SMTP email and WhatsApp notification.
4. **Demonstrate ML Anomaly Testing:**
   - Visit the **ML Detection** page and use the interactive sliders to show how night-time bursts increase the risk score to `0.90+`.
5. **Demonstrate Tableau Export:**
   - Go to **DAV / Tableau**, download the CSV, and show how the data is sanitized without password hashes.
