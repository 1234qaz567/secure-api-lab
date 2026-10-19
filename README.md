# Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis

**Student Name**: Ruan Hongzhe  
**Student ID**: 422810  
**HDU Number**: 23320213

## 1. Project and API Description
This project is a secure REST API backend built with **Python and Flask**. It uses SQLite for data storage. The application implements robust security measures to defend against common web vulnerabilities (OWASP Top 10).

### API Endpoints:
1. **`POST /auth/login`**
   * **Description**: Authenticates a user and issues a JWT token.
   * **How to call**: Send a JSON body `{"username":"alice", "password":"Password123!"}`. 
   * **Response**: Returns `{"token": "<JWT_TOKEN>"}` on success, or `401 Unauthorized` on failure.
   
2. **`GET /api/data`**
   * **Description**: Retrieves a list of users. This endpoint is protected and requires a valid JWT.
   * **How to call**: Send a GET request with the header `Authorization: Bearer <JWT_TOKEN>`.
   * **Response**: Returns a JSON array of users, e.g., `[{"id":1, "username":"alice"}]`.

3. **`POST /api/notes`** (Custom Endpoint)
   * **Description**: Creates a new note. Protected and requires JWT.
   * **How to call**: Send a POST request with the header `Authorization: Bearer <JWT_TOKEN>` and a JSON body `{"content": "my note"}`.

## 2. Detailed Description of Security Measures
*   **SQL Injection (SQLi) Protection**: 
    All database interactions strictly use **Parameterized Queries** (prepared statements with `?` placeholders). For example: `db.execute("SELECT * FROM users WHERE username = ?", (username,))`. String concatenation is never used to construct SQL queries.
*   **Cross-Site Scripting (XSS) Protection**: 
    All user-controlled data returned in API responses or stored in the database is escaped using `markupsafe.escape()`. This converts HTML special characters (like `<` and `>`) into safe HTML entities, preventing malicious scripts from executing in the browser.
*   **Authentication and Password Hashing**: 
    *   Passwords are never stored in plaintext. They are hashed using **`bcrypt`** with a secure salt.
    *   Upon successful login, a **JWT (JSON Web Token)** is issued using `flask-jwt-extended`. 
    *   Protected endpoints are secured with the `@jwt_required()` middleware, which validates the token's signature and expiration before allowing access.

## 3. CI/CD Pipeline with Security Scanners
The project uses **GitHub Actions** (`.github/workflows/main.yml`) to automatically run security scans on every push:
*   **SAST (Static Application Security Testing)**: Uses **Bandit** to analyze the Python source code for security issues (e.g., hardcoded passwords, SQL injection patterns).
*   **SCA (Software Composition Analysis)**: Uses **pip-audit** to scan the dependencies listed in `requirements.txt` against known vulnerability databases.

**Screenshot of successful SAST/SCA pipeline:**

*<img width="1215" height="1005" alt="9d0277385a1227eacc33ae7a2e421b42" src="https://github.com/user-attachments/assets/dddc8126-b488-4914-8d8a-f277cdedad9c" />
*

**Link to the last successful pipeline run:** 
*[https://github.com/1234qaz567/secure-api-lab/actions/runs/39223456543]*

## 4. CVE Vulnerability Analysis and Remediation

### 4.1 Vulnerability Overview
*   **CVE ID**: CVE-2024-23334
*   **Description**: A directory traversal vulnerability in `aiohttp` (versions < 3.9.4). When a static file route is configured with `follow_symlinks=True`, the application fails to validate if the requested file path is strictly within the root directory. This allows attackers to use `../` sequences to read arbitrary files on the server's operating system.

### 4.2 Sequence of Actions to Reproduce the Attack
1.  Started the vulnerable environment using Vulhub (`aiohttp:3.9.1`) via Docker Compose.
2.  Executed a raw HTTP request using a Python Socket script to bypass local path normalization (which often happens with standard `curl`). The payload was sent to the `/static` endpoint:
    ```python
    # Command used to trigger the attack
    docker exec -it aiohttp python -c "import socket; s = socket.socket(); s.connect(('127.0.0.1', 8080)); s.sendall(b'GET /static/../../../../../../../../etc/passwd HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'); res = b''; [res := res + chunk for chunk in iter(lambda: s.recv(4096), b'')]; print(res.decode())"
3.  **Result**: The server returned `HTTP/1.1 200 OK` and exposed the contents of the Linux `/etc/passwd` file (`root:x:0:0:root:/root:/bin/bash...`).

**Screenshot of successful exploitation:**

*<img width="1826" height="731" alt="b42c4a8301d8cf0e702977e072adb9d5" src="https://github.com/user-attachments/assets/d0120a74-c320-4f3d-bab3-f69edc5da269" />
*

### 4.3 Root Cause Analysis
The root cause is a **path traversal (CWE-22)** logic error in the `aiohttp` framework. When a static directory is served, the framework parses the requested URL. If `follow_symlinks=True` is set, the framework follows symbolic links and relative paths (`../`) without properly verifying if the final resolved absolute path is still contained within the designated static root directory. Because this boundary check is missing, an attacker can navigate up the directory tree and access files anywhere on the filesystem that the application process has permission to read.

### 4.4 Description of the Applied Fix
To eliminate the vulnerability, the following changes were made to the Docker environment (`docker-compose.yml` and the `server.py` code):

1.  **Upgraded the Dependency**: Updated `aiohttp` from the vulnerable version `3.9.1` to the patched version **`3.9.4`**.
2.  **Secure Configuration**: Modified the static route definition in the application code to explicitly disable symlink following by setting `follow_symlinks=False`.

```python
# Vulnerable Code: web.static("/static", "static/", follow_symlinks=True)
# Fixed Code:
app.router.add_routes([web.static("/static", "./static/", follow_symlinks=False)])
```
### 4.5 Proof of Vulnerability Elimination
After applying the fix and rebuilding the Docker container, the exact same exploitation command was executed again.

**Result**: The server correctly rejected the malicious request, returning `HTTP/1.1 404 Not Found` and the header `Server: Python/3.11 aiohttp/3.9.4`. The `/etc/passwd` file is no longer accessible.

**Screenshot of successful remediation:**

*<img width="2373" height="378" alt="6bd5f8f990cf9e6049699af38f4f0f1c" src="https://github.com/user-attachments/assets/7e8715c0-f80f-4aa6-ac8b-1c9e4e090f73" />
*
