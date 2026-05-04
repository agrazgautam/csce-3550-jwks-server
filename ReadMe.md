# JWKS Server

## Project 2: Extending the JWKS server

This project extends Project 2 into Project 3, enhancing the JWKS server with improved security and user management. It adds AES encryption, user registration, authentication request logging, and a rate limiter to strengthen overall system security and control access.


The database file used is:

```
totally_not_my_privateKeys.db
```

---

# Project Structure

```
project/
│
├── main.py
├── auth.py
├── key_manager.py
├── requirements.txt
├── totally_not_my_privateKeys.db   (created automatically)
└── README.md
```

---

# Requirements

* Python **3.9+**
* pip
* SQLite (included with Python)
* Gradebot executable (`gradebot.exe`)

---

# Install Dependencies

Install required Python libraries using the provided `requirements.txt`.

```bash
pip install -r requirements.txt
```

Typical dependencies include:

* `cryptography`
* `PyJWT`

---

# Start the Server

Run the server using:

```bash
python main.py
```

If successful, you should see:

```
Starting server at http://127.0.0.1:8080
```

The server will automatically:

1. Create the SQLite database if it does not exist
2. Create the `keys` table
3. Generate and store:

   * One **expired key**
   * One **valid key**

---

# Run Gradebot

Ensure the server is **not already running**, then run:

```bash
gradebot.exe project-3 --run="py main.py"
```

Gradebot will:

1. Start the server
2. Run automated tests
3. Verify the register endpoint
4. Verify Private Keys encryption
5. Create Auth Logs table

---

# Running Tests

This project includes automated tests to verify JWT creation, database functionality, and server endpoints.

## Run All Tests

From the project root directory:

```bash
pytest
```

## Run Tests with Coverage
To verify that the project meets the 80% coverage requirement, run:
```bash
pytest --cov=. --cov-report=term
```

## Generate HTML Coverage Report

You can generate a detailed coverage report:
```bash
pytest --cov=. --cov-report=html
```

Then open:
`htmlcov/index.html`


---

# Security Considerations

This project prevents SQL injection by using **parameterized queries** when interacting with SQLite:

```python
cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
```

This ensures that user input cannot modify SQL statements.

---

# Database Schema

The SQLite table structure:

Keys
```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);
```

Users
```sql
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);
```

Auth Logs
```sql
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
);
```

Where:

* `kid` – Unique key ID
* `key` – Serialized RSA private key (PEM format)
* `exp` – Expiration timestamp (Unix time)


---
