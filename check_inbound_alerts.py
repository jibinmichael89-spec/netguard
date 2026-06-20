import sqlite3
import time

while True:
    conn = sqlite3.connect('netguard.db')
    c = conn.cursor()
    c.execute('SELECT device_ip, source_ip, source_port, destination_port, severity, timestamp FROM alerts WHERE alert_type="inbound_connection" ORDER BY timestamp DESC LIMIT 5')
    rows = c.fetchall()
    
    print('\n--- Inbound Alerts ---')
    if rows:
        for row in rows:
            print(f'{row[1]}:{row[2]} -> {row[0]}:{row[3]} [{row[4]}] {row[5]}')
    else:
        print('(No inbound alerts yet)')
    
    conn.close()
    time.sleep(10)
