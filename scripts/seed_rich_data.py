import sqlite3
import random
import os
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend', 'securelog.db')

def seed_rich_trend_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # We want to generate data for today from 08:00 to 20:00 (12 hours)
    # We will generate data points every 15 minutes to make the graph spiky.
    
    base_time = datetime.now().replace(hour=8, minute=0, second=0, microsecond=0)
    
    # The image shows varying spikes. Let's create a predictable but random-looking pattern.
    
    events = []
    
    # 48 periods (12 hours * 4)
    for i in range(49):
        current_time = base_time + timedelta(minutes=15 * i)
        time_str = current_time.isoformat()
        
        # Base volume
        info_vol = random.randint(5, 50)
        warn_vol = random.randint(0, 20)
        err_vol = random.randint(0, 10)
        
        # Add some spikes
        if i in [5, 15, 25, 35, 40]:  # Error spikes
            err_vol += random.randint(100, 250)
        if i in [10, 20, 30, 42]:  # Warning spikes
            warn_vol += random.randint(100, 200)
            info_vol += random.randint(50, 100)
            
        # Add events
        for _ in range(info_vol):
            events.append((time_str, time_str, '10.0.0.1', 'INFO', 'Normal system operation', 'SYSTEM_INFO', 'auth-service'))
        for _ in range(warn_vol):
            events.append((time_str, time_str, '10.0.0.2', 'WARNING', 'High latency detected', 'LATENCY_WARN', 'web-server'))
        for _ in range(err_vol):
            events.append((time_str, time_str, '10.0.0.3', 'ERROR', 'Database connection failed', 'DB_ERROR', 'db-service'))

    # Insert into database
    query = """
    INSERT INTO log_events 
    (event_time, ingested_at, source_ip, severity, message, event_type, service, parse_status)
    VALUES (?, ?, ?, ?, ?, ?, ?, 'SUCCESS')
    """
    
    print(f"Generated {len(events)} events. Inserting...")
    cursor.executemany(query, events)
    conn.commit()
    conn.close()
    print("Done!")

if __name__ == "__main__":
    seed_rich_trend_data()
