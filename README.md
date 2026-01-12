# Payment Portal API

This project is a REST API for handling user payments and transactions. It connects to a SQLite database and provides endpoints for login, user details, and payment processing.

**⚠️ SECURITY WARNING ⚠️**
This repository is INTENTIONALLY VULNERABLE.
It is created solely for testing the SecurED-Hub security platform.
DO NOT DEPLOY THIS TO PRODUCTION.

## Vulnerabilities Included

1.  **SQL Injection**:
    - `POST /api/login`: Direct string concatenation allows authentication bypass.
    - `GET /api/user/<id>`: URL parameter injection.

2.  **Hardcoded Secrets**:
    - `JWT_SECRET`: Plain text secret key in `app.py`.
    - `AWS_ACCESS_KEY_ID`: Exposed AWS credentials.
    - `STRIPE_SECRET_KEY`: Exposed payment API key.

3.  **Weak Cryptography**:
    - `jwt.decode(..., verify_signature=False)`: Allows token forgery.
    - `HS256` with weak key.

4.  **Command Injection**:
    - `GET /api/system-ping`: Uses `subprocess.check_output` with shell=True on user input.

5.  **Sensitive Data Exposure**:
    - Credit card numbers stored in plain text in the database.
    - Debug mode enabled (`debug=True`).

6.  **Vulnerable Dependencies**:
    - Outdated `Flask` and `PyJWT` versions with known CVEs.

#test

## Detection Coverage
- **Bandit**: Should detect SQLi, hardcoded secrets, shell=True, debug=True.
- **Secret Scanners**: Should detect AWS and Stripe keys.
- **Pip-Audit**: Should flag `Flask 2.0.1` and `PyJWT 1.7.1`.
- **LLM/RAG**: Should explain "Why is verify_signature=False dangerous?"
