import sqlite3
import bcrypt

conn = sqlite3.connect("app.db")
conn.executescript("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL
);
""")

password = b"Password123!"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
conn.execute(
    "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
    ("alice", hashed),
)
conn.commit()
conn.close()
print("DB initialized, user 'alice' / 'Password123!' created")