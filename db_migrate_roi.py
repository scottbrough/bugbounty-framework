import sqlite3

conn = sqlite3.connect("bugbounty.db")
c = conn.cursor()

# Add new fields if they don't exist
try: c.execute("ALTER TABLE findings ADD COLUMN time_spent REAL")
except: pass
try: c.execute("ALTER TABLE findings ADD COLUMN payout REAL")
except: pass
try: c.execute("ALTER TABLE findings ADD COLUMN hourly_rate REAL")
except: pass

conn.commit()
conn.close()
print("[✔] ROI fields added to findings table.")
