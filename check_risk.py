import sqlite3, json
conn = sqlite3.connect('netguard.db')
c = conn.cursor()
c.execute("SELECT ip_address, risk_score, risk_level, risk_factors FROM devices WHERE ip_address = '192.168.1.176'")
row = c.fetchone()
print(row[0], '->', row[1], row[2])
for f in json.loads(row[3]):
    print(' +', f['weight'], '-', f['reason'])
conn.close()
