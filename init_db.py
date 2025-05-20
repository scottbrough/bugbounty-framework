import sqlite3

conn = sqlite3.connect("bugbounty.db")
c = conn.cursor()
c.execute("""
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT,
    host TEXT,
    vulnerability TEXT,
    severity TEXT,
    confidence REAL,
    date TEXT,
    status TEXT
)
""")
conn.commit()
conn.close()
