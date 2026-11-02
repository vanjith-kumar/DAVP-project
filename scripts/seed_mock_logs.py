import csv
import httpx
import json
import time
import os

API_URL = "http://localhost:8000/api"
CSV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "mock_logs.csv")

def get_token():
    # Login as admin to get token
    reg = httpx.post(f"{API_URL}/auth/register", json={"username": "mocking", "password": "mockpassword", "email": "mocking@example.com"})
    print("Reg:", reg.status_code, reg.text)
    response = httpx.post(f"{API_URL}/auth/login", data={"username": "mocking", "password": "mockpassword"})
    if response.status_code == 200:
        return response.json().get("access_token")
    print(f"Failed to login. Response: {response.text}")
    return None

def ingest_logs():
    token = get_token()
    if not token:
        return

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    messages = []
    with open(CSV_PATH, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if 'raw_message' in row:
                messages.append(row['raw_message'])

    print(f"Read {len(messages)} messages from CSV.")
    
    # Ingest in batch
    payload = {
        "messages": messages,
        "source_id": 1
    }
    
    response = httpx.post(f"{API_URL}/logs/ingest/batch", json=payload, headers=headers)
    if response.status_code == 200:
        print("Successfully ingested logs!")
    else:
        print(f"Error ingesting logs: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    ingest_logs()
