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

*[请在此处直接拖拽/粘贴你的 GitHub Actions 绿色成功截图]*

**Link to the last successful pipeline run:** 
*[请在此处粘贴你的 Actions 运行链接，例如：https://github.com/1234qaz567/secure-api-lab/actions/runs/123456789]*

## 4. CVE Vulnerability Analysis and Remediation

### 4.1 Vulnerability Overview
* **CVE ID**: CVE-2022-22978
* **Description**: An authentication bypass vulnerability in Spring Security. When configuring access control using `RegexRequestMatcher` with regular expressions containing `.` (dot), the dot does not match line terminators by default. Attackers can inject URL-encoded newline characters (`%0a` or `%0d`) into the request path to bypass regular expression matching, thereby accessing protected administrative endpoints without authentication.

### 4.2 Sequence of Actions to Reproduce the Attack
1. Started the vulnerable environment using Vulhub (`vulhub/spring-security:5.6.3`) via Docker Compose.
2. Tested normal access to the protected route:
   ```bash
   curl -i http://localhost:8080/admin
   ```
   Result: Returned HTTP/1.1 404 (Blocked by Spring Security).
3. Executed the bypass payload by injecting an encoded newline:
   ```bash
   curl --path-as-is -i "http://localhost:8080/admin/%0a"
   ```
4. Result: The request bypassed the security filter and returned HTTP/1.1 200 OK, successfully accessing the protected admin page with the message "Congratulations, you are an admin!".

Screenshot of successful exploitation:


### 4.3 Root Cause Analysis
The root cause is a logic flaw in Spring Security's RegexRequestMatcher. When developers use a regex like /admin/.* to protect resources, the regex engine expects the path to match. However, Java's . metacharacter does not match line terminators (like \n or \r). By inserting %0a into the URL, the server decodes it to a newline character. The regex match fails, so Spring Security skips the authorization check and passes the request directly to the controller, resulting in unauthorized access.

### 4.4 Description of the Applied Fix
Due to Docker registry limitations preventing the pulling of the official 5.6.4 patch image, a custom Python reverse proxy (`proxy.py`) was implemented to eliminate the vulnerability. 
The proxy uses a `@app.before_request` hook to inspect incoming URLs. If it detects URL-encoded newline characters (`%0a` or `%0d`), it immediately returns a `403 Forbidden` response, effectively blocking the malicious payload before it reaches the backend Spring application.

### 4.5 Proof of Vulnerability Elimination
After deploying the custom security proxy, the exact same exploitation command was executed again.

**Result**: The proxy successfully intercepted the request and returned `HTTP/1.1 403 FORBIDDEN` with the message `{"error": "Security Filter: Malicious newline character detected!"}`. The authentication bypass is completely neutralized.

**Screenshot of successful remediation:**

*[请在此处直接拖拽/粘贴你刚才 403 FORBIDDEN 的截图]*