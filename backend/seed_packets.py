"""
Seed the database with packet_capture.csv data.
Clears old mock data, then loads the CSV into log_events table.
"""
import csv
import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "securelog.db")
CSV_PATH = os.path.join(os.path.dirname(__file__), "data", "packet_capture.csv")

def seed():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Clear old mock data but keep the schema
    cur.execute("DELETE FROM log_events")
    conn.commit()
    print(f"[*] Cleared existing log_events table")

    with open(CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        count = 0
        for row in reader:
            # Parse event_time
            event_time = row["event_time"]
            if event_time.endswith("Z"):
                event_time = event_time[:-1] + "+00:00"
            elif len(event_time) == 16:  # 2026-10-01T08:00
                event_time += ":00"

            cur.execute("""
                INSERT INTO log_events (
                    event_time, ingested_at, host, source_ip, destination_ip,
                    source_port, destination_port, username, event_type, action,
                    protocol, service, method, path, status_code,
                    severity, message, user_agent, raw_message, parser_name, parse_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_time,
                datetime.utcnow().isoformat(),
                row.get("host") or None,
                row.get("source_ip") or None,
                row.get("destination_ip") or None,
                int(row["source_port"]) if row.get("source_port") and row["source_port"].strip() else None,
                int(row["destination_port"]) if row.get("destination_port") and row["destination_port"].strip() else None,
                row.get("username") or None,
                row.get("event_type") or None,
                row.get("action") or None,
                row.get("protocol") or None,
                row.get("service") or None,
                row.get("method") or None,
                row.get("path") or None,
                int(row["status_code"]) if row.get("status_code") and row["status_code"].strip() else None,
                row.get("severity") or None,
                row.get("message") or None,
                row.get("user_agent") or None,
                row.get("raw_message") or None,
                "packet_csv_import",
                "PARSED"
            ))
            count += 1

    conn.commit()
    conn.close()
    print(f"[+] Seeded {count} packet events from {CSV_PATH}")
    print(f"[+] Database: {DB_PATH}")

if __name__ == "__main__":
    seed()
