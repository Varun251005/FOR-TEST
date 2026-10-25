# FOR-TEST: AI-IDS-IPS Testing Target

A lightweight, dedicated authentication web application designed to act as a controlled target for demonstrating network traffic observation, suspicious authentication pattern detection, and prevention in the **AI-IDS-IPS (Artificial Intelligence-based Intrusion Detection and Prevention System)** project.

---

## A. Project Overview

`FOR-TEST` provides a realistic authentication interface that generates observable HTTP request patterns under both normal and adversarial testing conditions. It is engineered specifically as a traffic generation target for an isolated security testing environment.

### Expected Demonstration Architecture

```text
                 Test Client (Browser / Test Scripts)
                                 |
                                 v
                    FOR-TEST Authentication App
                                 |
                                 v
                           HTTP Requests
                                 |
                                 v
                 Raspberry Pi / Packet Capture Tap
                                 |
                                 v
                         Traffic Processing
                                 |
                                 v
                         Feature Extraction
                                 |
                                 v
                            ML Detection
                                 |
                                 v
                           IDS/IPS Alert
                                 |
                                 v
                           SOC Dashboard
```

> [!NOTE]
> Building and running this website provides the target web service. The existing packet-capture tap and detection pipeline must be configured separately to observe and analyze its network traffic.

---

## B. Requirements

- **Operating System:** Linux (Fedora, Debian/Ubuntu, Arch, etc.) or macOS / Windows
- **Python:** Python 3.8+ (tested on Python 3.14)
- **Package Manager:** `pip`
- **Web Browser:** Any modern web browser (Firefox, Chrome, Edge)
- **Network:** Isolated laboratory network or local loopback

---

## C. Setup on Fedora / Linux

Clone or place the `FOR-TEST` repository on your test machine, then run:

```bash
# Navigate to the project directory
cd FOR-TEST

# Create an isolated Python virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate

# Install the minimal dependencies
pip install -r requirements.txt
```

---

## D. Configure the Flask Secret Key

To maintain secure defaults and avoid hardcoded secrets, `FOR-TEST` **strictly requires** a session secret key before it will start. If the key is not set, the application will exit immediately with a security configuration error.

Generate and export a cryptographically strong secret key:

```bash
export FLASK_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

*(Alternatively, you can provide `SECRET_KEY` in your environment or a `.env` file for local development).*

---

## E. Start the Application

With your virtual environment activated and `FLASK_SECRET_KEY` set:

```bash
python app.py
```

The application initializes the SQLite database (`database.db`), creates the log directory (`logs/requests.log`), and binds the server to:

```text
http://0.0.0.0:5000
```

---

## F. Open the Website (Local Access)

Open your web browser and navigate to:

```text
http://127.0.0.1:5000
```

Unauthenticated users will be directed to `/login`. Upon successful authentication, users are redirected to `/dashboard`.

---

## G. Access from Another Lab Machine (LAN)

The application binds to `0.0.0.0:5000` so that testing clients on the isolated laboratory network can access it.

### 1. Identify Host Machine IP

On Linux, run:

```bash
hostname -I
```

or:

```bash
ip -4 addr show
```

Note the IP address assigned to your laboratory interface (for example, `192.168.1.50`).

### 2. Configure Host Firewall (Fedora / RHEL / Ubuntu)

Do not disable your firewall globally. Open only port 5000 for your lab subnet:

- **On Fedora / RHEL (firewalld):**
  ```bash
  sudo firewall-cmd --add-port=5000/tcp --permanent
  sudo firewall-cmd --reload
  ```

- **On Ubuntu / Debian (UFW):**
  ```bash
  sudo ufw allow 5000/tcp
  ```

### 3. Connect from Remote Test Machine

From another machine on the isolated network, open:

```text
http://<LAB-MACHINE-IP>:5000
```

---

## H. Demo Credentials

The application automatically seeds the following demonstration accounts during startup (using secure Werkzeug password hashes):

| Username | Password   | Role    | Access Level          |
| :------- | :--------- | :------ | :-------------------- |
| `admin`  | `admin123` | `admin` | Administrator Testing |
| `user`   | `user123`  | `user`  | Standard User Testing |

> [!WARNING]
> These credentials are provided strictly for demonstration and testing within an isolated lab environment. Never use these credentials in a production system.

---

## I. HTTP Request & Telemetry Logs

All incoming HTTP requests and authentication lifecycle events are recorded in:

```text
logs/requests.log
```

### Log Record Format

Each entry contains the following structured fields separated by pipes (`|`):

```text
timestamp | source_ip | http_method | request_path | response_status | event | user_agent
```

### Sample Log Output

```text
2026-10-25 18:05:42 | 127.0.0.1       | GET  | /login          | 200 | PAGE_REQUEST    | Mozilla/5.0 ...
2026-10-25 18:05:42 | 192.168.1.15   | POST | /login          | 401 | LOGIN_FAILURE   | python-requests/2.31.0
2026-10-25 18:05:45 | 192.168.1.10   | POST | /login          | 302 | LOGIN_SUCCESS   | Mozilla/5.0 ...
2026-10-25 18:05:46 | 192.168.1.10   | GET  | /dashboard      | 200 | PAGE_REQUEST    | Mozilla/5.0 ...
2026-10-25 18:06:00 | 192.168.1.10   | POST | /logout         | 302 | LOGOUT          | Mozilla/5.0 ...
```

### Privacy & Logging Guarantees

- **No Passwords Logged:** Submitted passwords, password hashes, and session cookies are never written to log files.
- **Direct Remote Address:** IP addresses are captured from `request.remote_addr` without trusting unverified proxy headers.
- **Crash-Resilient:** Logging exceptions are caught to prevent server termination.

---

## J. AI-IDS-IPS Integration & Testing

### Traffic Generation Target

`FOR-TEST` is purposefully free of client-side or server-side rate limiters, CAPTCHA, or IP lockout mechanisms. This allows external test harnesses to generate:

1. **Brute-Force & Credential Stuffing:** High-frequency failed login attempts.
2. **Anomalous User-Agents:** Requests sent with automated tool headers or blank user-agents.
3. **Bursty Authentication:** Rapid sequences of logins and logouts.
4. **Normal Traffic:** Intermittent authentications by legitimate users.

### Network Layer vs. Application Layer Telemetry

- **`FOR-TEST` (Application Layer):** Records processed HTTP endpoints, HTTP status codes, and user authentication outcomes.
- **AI-IDS-IPS (Network Layer):** Captures raw packets (TCP/IP streams) via a network tap or Raspberry Pi, computes statistical flow features (packet size distribution, flow duration, inter-arrival times), and applies the ML classification model.

*(Application logs verify that requests reached the application; IDS/IPS alerts confirm the ML pipeline detected the traffic signature).*

---

## K. Automated Verification Suite

Run the built-in test suite to verify application logic:

```bash
.venv/bin/python test_suite.py
```

The suite executes 13 automated tests covering:
- Login page rendering and branding
- Admin and standard user credential verification
- Rejection of invalid credentials (HTTP 401)
- Exclusion of passwords from logs
- Dashboard access control and unauthenticated redirects
- Session clearance on POST `/logout`
- Logging telemetry format and event classification
- Absence of rate limiting (verifying burst traffic)
- Enforcement of `FLASK_SECRET_KEY` configuration
- Prevention of duplicate database accounts across restarts

---

## L. Security Notice

> [!CAUTION]
> **LABORATORY ENVIRONMENT ONLY**
> 
> This application intentionally omits rate limiting, account lockout, and IP throttling to enable security traffic observation.
> **DO NOT** expose this application to the public internet, deploy it into production, or enter real personal credentials.

