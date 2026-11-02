"""
SecureLog AI - Mock Data Generator, Data Analysis & Visualization Suite
Generates realistic, rich, 100% complete security telemetry without missing values,
deduplicates repeated columns, performs statistical data analysis using Pandas,
creates publication-quality dark-themed SOC visualizations using Matplotlib,
and seeds the local database for instant dashboard richness.
"""

import os
import csv
import json
import random
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Headless backend
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.gridspec import GridSpec

# Project root paths
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPTS_DIR)
BACKEND_DIR = os.path.join(BASE_DIR, "backend")
DATA_DIR = os.path.join(BASE_DIR, "data")
BACKEND_DATA_DIR = os.path.join(BACKEND_DIR, "data")
DOCS_DIR = os.path.join(BASE_DIR, "docs")
DOCS_IMG_DIR = os.path.join(DOCS_DIR, "images")
DB_PATH = os.path.join(BACKEND_DIR, "securelog.db")
CSV_PATH_DATA = os.path.join(DATA_DIR, "dashboard_mock_logs.csv")
CSV_PATH_BACKEND = os.path.join(BACKEND_DATA_DIR, "dashboard_mock_logs.csv")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BACKEND_DATA_DIR, exist_ok=True)
os.makedirs(DOCS_IMG_DIR, exist_ok=True)

# -----------------------------------------------------------------------------
# 1. Threat Scenarios & Profiles Definition (100% Populated, Zero Missing Cells)
# -----------------------------------------------------------------------------

ATTACK_SCENARIOS = [
    {
        "name": "Distributed SSH Brute Force",
        "event_type": "ssh_brute_force",
        "severity": "HIGH",
        "action": "BLOCKED",
        "service": "sshd",
        "protocol": "SSH",
        "methods": ["SSH_AUTH", "SSH_CONNECT", "PASSWORD_AUTH"],
        "paths": ["/usr/sbin/sshd", "/etc/pam.d/sshd", "/dev/pts/0", "/var/log/auth.log"],
        "status_codes": [401],
        "destination_ports": [22],
        "usernames": ["root", "admin", "ubuntu", "test", "oracle", "support", "deploy"],
        "user_agents": [
            "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
            "libssh2/1.10.0 (Automated SSH Client)",
            "Paramiko/3.4.0 (Python SSH Driver)",
            "Dropbear_2020.81 (Embedded Client)",
            "Hydra/9.5 (Network Logon Cracker)"
        ],
        "source_ips": ["45.33.22.11", "185.220.101.5", "194.26.29.112"],
        "dest_ips": ["10.0.0.100", "10.0.0.50", "10.0.0.200"],
        "messages": [
            "Failed password for invalid user {user} from {ip} port {port} ssh2",
            "Failed password for {user} from {ip} port {port} ssh2",
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser={user} rhost={ip}",
            "Connection closed by authenticating user {user} {ip} port {port} [preauth]",
            "Maximum authentication attempts exceeded for invalid user {user} from {ip}"
        ],
        "hours": [8, 9, 10, 18, 19],
        "weight": 28
    },
    {
        "name": "SQL Injection Probe & Exploit",
        "event_type": "sql_injection",
        "severity": "CRITICAL",
        "action": "BLOCKED",
        "service": "nginx",
        "protocol": "HTTP",
        "methods": ["GET", "POST", "GET", "POST"],
        "paths": [
            "/api/v1/users?id=1' UNION SELECT username,password_hash FROM users--",
            "/api/v1/products?cat=electronics' OR '1'='1",
            "/admin/reports.php?filter=1; DROP TABLE audit_logs;--",
            "/v1/auth/token?grant_type=' OR 1=1--",
            "/api/v1/orders?order_id=105' AND SLEEP(5)--",
            "/api/v1/search?query=admin' UNION ALL SELECT NULL,CONCAT(user(),schema())--"
        ],
        "status_codes": [403, 401, 403],
        "destination_ports": [443, 80],
        "usernames": ["anonymous", "guest_session", "api_probe", "admin_inject", "web_crawler", "sql_tester"],
        "user_agents": [
            "sqlmap/1.7.11#stable (https://sqlmap.org)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Havij/1.17",
            "curl/8.4.0 (Security-Audit-Script)",
            "Mozilla/5.0 (X11; Linux x86_64) OWASP-ZAP/2.14.0",
            "Nikto/2.1.6 (Web Security Scanner)"
        ],
        "source_ips": ["185.220.101.5", "103.251.167.20", "89.248.165.74"],
        "dest_ips": ["10.0.0.100", "10.0.0.50"],
        "messages": [
            "WAF Alert: SQL Injection pattern detected in query parameter from {ip} on {path}",
            "ModSecurity: Access denied with code 403 (SQLi LibInjection match) for {ip} user {user}",
            "Nginx reverse-proxy blocked suspicious URI pattern containing SQL comments: {path}"
        ],
        "hours": [11, 12, 13, 21, 22],
        "weight": 18
    },
    {
        "name": "Stealth Port Scan / Recon",
        "event_type": "port_scan",
        "severity": "MEDIUM",
        "action": "DENIED",
        "service": "suricata",
        "protocol": "TCP",
        "methods": ["TCP_SYN", "PORT_PROBE", "CONNECT", "TCP_FIN"],
        "paths": [
            "/network/interface/eth0/syn_scan",
            "/tcp/range/1-1024",
            "/ports/probe/stealth_syn",
            "/subnet/10.0.0.0/24",
            "/services/port_enumeration"
        ],
        "status_codes": [403, 400],
        "destination_ports": [80, 443, 22, 21, 3306, 8080, 8443],
        "usernames": ["unauthenticated", "scanner_agent", "recon_probe", "network_guest", "nmap_probe"],
        "user_agents": [
            "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
            "Masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)",
            "ZMap/2.1.1 (Internet Scanner)",
            "RustScan/2.2.3 (Fast Port Scanner)"
        ],
        "source_ips": ["194.26.29.112", "79.124.62.86", "198.51.100.42"],
        "dest_ips": ["10.0.0.100", "10.0.0.200", "10.0.0.50"],
        "messages": [
            "ET SCAN Potential NMAP SYN scan detected from {ip} across ports 21-1024",
            "Suricata IDS: Fast scan signature match on interface eth0 from {ip} targeting port {port}",
            "Firewall rule 102 DROP: TCP SYN packet to closed port {port} from {ip}"
        ],
        "hours": [2, 3, 4, 15, 16],
        "weight": 22
    },
    {
        "name": "Malware C2 Beaconing",
        "event_type": "c2_beacon",
        "severity": "CRITICAL",
        "action": "ALERT",
        "service": "suricata",
        "protocol": "HTTPS",
        "methods": ["POST", "GET", "POST"],
        "paths": ["/gateway/v2/sync", "/heartbeat.bin", "/beacon/poll", "/channel/v1/connect"],
        "status_codes": [200, 204],
        "destination_ports": [8443, 443],
        "usernames": ["svchost_exec", "nt_authority_system", "infected_host_session", "rundll32_worker", "wscript_host"],
        "user_agents": [
            "CobaltStrike-Beacon/4.8 (Malleable-C2)",
            "WinHTTP-Loader/1.0 (DirectTLS)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PowerShell/7.2",
            "Empire-Agent/4.5 (PowerShell-Stager)"
        ],
        "source_ips": ["10.0.0.15", "10.0.0.42"],  # Compromised internal hosts
        "dest_ips": ["103.251.167.20", "194.26.29.112"],
        "messages": [
            "ET MALWARE CobaltStrike Malleable C2 HTTP traffic pattern detected to {dip}",
            "Anomalous regular heartbeat beacon interval (60s +/- 5%) to untrusted IP {dip}",
            "TLS JA3 Fingerprint matched known command & control agent framework targeting {dip}"
        ],
        "hours": [1, 2, 6, 14, 20, 23],
        "weight": 12
    },
    {
        "name": "Privilege Escalation / Sudo Abuse",
        "event_type": "privilege_escalation",
        "severity": "HIGH",
        "action": "ALERT",
        "service": "auth-service",
        "protocol": "LOCAL",
        "methods": ["SUDO_EXEC", "SETUID_CALL", "PRIV_ESCALATE", "SYSTEM_AUTH"],
        "paths": ["/etc/shadow", "/usr/bin/pkexec", "/usr/bin/sudo", "/bin/su", "/etc/sudoers.d/custom"],
        "status_codes": [403, 401],
        "destination_ports": [22],
        "usernames": ["devuser", "app_runner", "operator_local", "restricted_worker", "deploy_temp"],
        "user_agents": [
            "sudo/1.9.9 (pam_unix; tty=/dev/pts/2)",
            "Linux-Auditd/3.0.7 (kernel-level monitor)",
            "systemd-logind/249 (session-controller)",
            "polkit-agent/0.105 (auth-manager)"
        ],
        "source_ips": ["192.168.1.105", "10.0.0.22"],
        "dest_ips": ["127.0.0.1", "10.0.0.1"],
        "messages": [
            "sudo: pam_unix(sudo:auth): authentication failure; logname={user} uid=1001 euid=0 tty=/dev/pts/2",
            "AUDIT: unauthorized attempt to modify {path} by process python3[PID 14201] user={user}",
            "Linux auditd: execution of SUID binary {path} with suspicious environment variables by {user}"
        ],
        "hours": [14, 15, 16, 17],
        "weight": 10
    },
    {
        "name": "SYN Flood / DoS Wave",
        "event_type": "ddos_syn_flood",
        "severity": "HIGH",
        "action": "RATE_LIMITED",
        "service": "firewall",
        "protocol": "TCP",
        "methods": ["SYN_FLOOD", "VOLUMETRIC_INGRESS", "RATE_LIMIT"],
        "paths": ["/vip/ingress/port443", "/network/filter/syn_guard", "/firewall/rate_limit/ddos", "/chain/FORWARD"],
        "status_codes": [429, 403],
        "destination_ports": [443, 80],
        "usernames": ["botnet_client", "volumetric_src", "flood_agent", "unauthenticated", "ddos_node"],
        "user_agents": [
            "hping3/3.0.0-alpha-2 (SYN-Flood-Engine)",
            "Linux-Kernel/6.5 (TCP-Mitigation-Guard)",
            "iptables-synproxy/1.8 (Rate-Limiter)",
            "Mirai-Botnet/2.1 (DDoS-Engine)"
        ],
        "source_ips": ["198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13"],
        "dest_ips": ["10.0.0.100", "10.0.0.50"],
        "messages": [
            "SYN Flood mitigation triggered: connection rate exceeded 2,500 syn/sec from subnet",
            "Kernel: TCP syn flood on port {port}. Sending syncookies to mitigate volumetric surge",
            "DDoS Guard: Ingress rate-limiter engaged for target VIP {dip}"
        ],
        "hours": [17, 18],
        "weight": 15
    }
]

NORMAL_TRAFFIC_PATTERNS = [
    {
        "service": "nginx",
        "event_type": "http_access",
        "severity": "INFO",
        "action": "ALLOW",
        "protocol": "HTTP",
        "methods": ["GET", "POST", "GET", "PUT", "GET"],
        "paths": ["/", "/api/v1/health", "/dashboard", "/assets/main.css", "/api/v1/metrics", "/api/v1/summary", "/api/v1/status"],
        "status_codes": [200, 200, 200, 304, 204],
        "destination_ports": [80, 443],
        "usernames": ["web_user", "customer_session", "api_consumer", "devops_admin", "dashboard_viewer", "authenticated_guest", "analyst_user"],
        "user_agents": [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ],
        "source_ips": ["192.168.1.50", "192.168.1.51", "192.168.1.100", "10.0.0.10", "172.16.0.25"],
        "dest_ips": ["10.0.0.100", "10.0.0.200", "10.0.0.50"],
        "messages": [
            "Nginx: {method} {path} HTTP/1.1 200 - Client {ip} duration=0.012s user={user}",
            "Nginx: {method} {path} HTTP/2.0 200 - Client {ip} TLSv1.3 user={user}",
            "API Gateway: Processed authenticated API query for {path} from {ip} user={user}"
        ]
    },
    {
        "service": "sshd",
        "event_type": "auth_success",
        "severity": "LOW",
        "action": "SUCCESS",
        "protocol": "SSH",
        "methods": ["SSH_AUTH", "SSH_CONNECT", "SESSION_OPEN"],
        "paths": ["/dev/pts/0", "/dev/pts/1", "/etc/ssh/authorized_keys", "/usr/sbin/sshd"],
        "status_codes": [200],
        "destination_ports": [22],
        "usernames": ["devops_admin", "sysadmin", "lead_engineer", "deployer_service", "soc_analyst", "backup_runner"],
        "user_agents": [
            "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
            "OpenSSH_9.3p1 (macOS Apple Silicon)",
            "PuTTY_Release_0.79 (Windows Client)",
            "Dropbear_2020.81 (Authorized Admin)"
        ],
        "source_ips": ["192.168.1.10", "192.168.1.15", "10.0.0.5"],
        "dest_ips": ["10.0.0.100", "10.0.0.200", "10.0.0.50"],
        "messages": [
            "sshd: Accepted publickey for {user} from {ip} port {port} ssh2: RSA SHA256:4f8d9...",
            "sshd: pam_unix(sshd:session): session opened for user {user} by (uid=0) on {path}"
        ]
    },
    {
        "service": "postgres",
        "event_type": "db_query",
        "severity": "INFO",
        "action": "SUCCESS",
        "protocol": "TCP",
        "methods": ["SQL_SELECT", "SQL_INSERT", "SQL_COMMIT", "DB_AUTH"],
        "paths": ["database:securelog_db", "table:log_events", "table:alerts", "table:incidents", "schema:public.metrics"],
        "status_codes": [200],
        "destination_ports": [5432],
        "usernames": ["app_backend", "analytics_worker", "etl_pipeline", "readonly_service", "postgres_master"],
        "user_agents": [
            "PostgreSQL-Client/15.2 (asyncpg/0.29.0)",
            "psycopg2/2.9.9 (Python 3.9 Backend)",
            "pg_dump/15.2 (Database Backup)",
            "DBeaver/23.3 (Admin Console)"
        ],
        "source_ips": ["10.0.0.20", "10.0.0.21"],
        "dest_ips": ["10.0.0.50", "10.0.0.100"],
        "messages": [
            "PostgreSQL: connection authorized: user={user} database=securelog_db SSL=on",
            "PostgreSQL: checkpoint complete: wrote 142 buffers (0.9%); 0 WAL file(s) added; client={user}"
        ]
    },
    {
        "service": "suricata",
        "event_type": "dns_query",
        "severity": "INFO",
        "action": "ALLOW",
        "protocol": "DNS",
        "methods": ["DNS_QUERY", "DNS_RESPONSE"],
        "paths": ["query:updates.microsoft.com", "query:api.github.com", "query:registry.npmjs.org", "query:pypi.org", "query:time.cloudflare.com"],
        "status_codes": [200],
        "destination_ports": [53],
        "usernames": ["system_resolver", "dns_client_service", "dhcp_workstation", "internal_node", "coredns_worker"],
        "user_agents": [
            "systemd-resolved/249 (Linux x86_64)",
            "CoreDNS/1.10.1 (kubernetes-cluster)",
            "Apple-mDNS/1310.80.1 (Darwin resolver)",
            "bind9/9.18.1 (Local Caching DNS)"
        ],
        "source_ips": ["10.0.0.15", "192.168.1.100", "172.16.0.40"],
        "dest_ips": ["1.1.1.1", "8.8.8.8", "10.0.0.2"],
        "messages": [
            "DNS query: IN A {path} resolved to 20.189.173.19 client={user}",
            "DNS query: IN A {path} resolved to 140.82.114.5 client={user}"
        ]
    }
]

HOSTS = [
    "soc-edge-gw-01",
    "prod-web-01",
    "prod-web-02",
    "prod-db-primary",
    "auth-vault-01",
    "internal-ws-105"
]

# -----------------------------------------------------------------------------
# 2. Synthetic Data Generation Engine (Clean, Distinct Columns, 100% Populated)
# -----------------------------------------------------------------------------

def generate_mock_security_logs(target_count: int = 1450) -> List[Dict[str, Any]]:
    """
    Generates a realistic 24-hour log dataset with diurnal baseline traffic
    and clustered attack bursts.
    Ensures ZERO missing/null cells and NO duplicate columns.
    """
    print(f"[*] Generating realistic security log events over a 24-hour cycle (Target: ~{target_count})...")

    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=24)

    logs = []
    bucket_minutes = 15
    num_buckets = 96  # 24 hours * 4 buckets per hour

    for b in range(num_buckets):
        bucket_time = start_time + timedelta(minutes=b * bucket_minutes)
        hour = bucket_time.hour

        # Diurnal curve: lowest volume during off-hours, peak during business hours
        time_factor = 0.35 + 0.65 * (np.sin((hour - 6) / 24 * 2 * np.pi) ** 2)
        normal_events_in_bucket = int(np.random.poisson(lam=12 * time_factor))

        # Generate normal baseline traffic
        for _ in range(normal_events_in_bucket):
            event_dt = bucket_time + timedelta(seconds=random.randint(0, bucket_minutes * 60 - 1))
            pattern = random.choice(NORMAL_TRAFFIC_PATTERNS)
            src_ip = random.choice(pattern["source_ips"])
            dest_ip = random.choice(pattern["dest_ips"])
            src_port = random.randint(1024, 65535)
            dest_port = random.choice(pattern["destination_ports"])
            method = random.choice(pattern["methods"])
            path = random.choice(pattern["paths"])
            status_code = random.choice(pattern["status_codes"])
            user = random.choice(pattern["usernames"])
            ua = random.choice(pattern["user_agents"])
            host = random.choice(HOSTS)

            msg_template = random.choice(pattern["messages"])
            msg = msg_template.format(ip=src_ip, port=dest_port, path=path, method=method, user=user)

            logs.append({
                "event_time": event_dt.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                "host": host,
                "source_ip": src_ip,
                "destination_ip": dest_ip,
                "source_port": src_port,
                "destination_port": dest_port,
                "username": user,
                "event_type": pattern["event_type"],
                "action": pattern["action"],
                "protocol": pattern["protocol"],
                "service": pattern["service"],
                "method": method,
                "path": path,
                "status_code": status_code,
                "severity": pattern["severity"],
                "message": msg,
                "user_agent": ua,
                "raw_message": f"{event_dt.strftime('%b %d %H:%M:%S')} {host} {pattern['service']}: {msg}",
                "parser_name": "soc_log_normalizer",
                "parse_status": "PARSED"
            })

        # Generate active attack scenarios
        for scenario in ATTACK_SCENARIOS:
            if hour in scenario["hours"]:
                if random.random() < 0.65:
                    burst_size = random.randint(3, 14)
                    for _ in range(burst_size):
                        event_dt = bucket_time + timedelta(seconds=random.randint(0, bucket_minutes * 60 - 1))
                        src_ip = random.choice(scenario["source_ips"])
                        dest_ip = random.choice(scenario["dest_ips"])
                        src_port = random.randint(1024, 65535)
                        dest_port = random.choice(scenario["destination_ports"])
                        method = random.choice(scenario["methods"])
                        path = random.choice(scenario["paths"])
                        status_code = random.choice(scenario["status_codes"])
                        user = random.choice(scenario["usernames"])
                        ua = random.choice(scenario["user_agents"])
                        host = random.choice(HOSTS)

                        msg_template = random.choice(scenario["messages"])
                        msg = msg_template.format(ip=src_ip, port=dest_port, path=path, user=user, dip=dest_ip)

                        logs.append({
                            "event_time": event_dt.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
                            "host": host,
                            "source_ip": src_ip,
                            "destination_ip": dest_ip,
                            "source_port": src_port,
                            "destination_port": dest_port,
                            "username": user,
                            "event_type": scenario["event_type"],
                            "action": scenario["action"],
                            "protocol": scenario["protocol"],
                            "service": scenario["service"],
                            "method": method,
                            "path": path,
                            "status_code": status_code,
                            "severity": scenario["severity"],
                            "message": msg,
                            "user_agent": ua,
                            "raw_message": f"{event_dt.strftime('%b %d %H:%M:%S')} {host} {scenario['service']}: {msg}",
                            "parser_name": "soc_log_normalizer",
                            "parse_status": "PARSED"
                        })

    # Sort strictly by timestamp
    logs.sort(key=lambda x: x["event_time"])
    print(f"[+] Total generated events: {len(logs):,}")
    return logs


def save_logs_to_csv(logs: List[Dict[str, Any]], paths: List[str]):
    """
    Saves generated logs to specified CSV destinations.
    Enforces a strict integrity check ensuring 0 nulls, 0 empty strings, and 0 missing cells.
    """
    if not logs:
        return

    fieldnames = list(logs[0].keys())

    # STRICT INTEGRITY CHECK: Fail fast if any cell is empty or null
    for row_idx, row in enumerate(logs):
        for col_name in fieldnames:
            val = row.get(col_name)
            if val is None or val == "":
                raise ValueError(
                    f"[!] Integrity check failed at row {row_idx}, column '{col_name}': empty or null cell found!"
                )

    for path in paths:
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(logs)
        print(f"[+] Saved clean dataset CSV to: {path}")
        print(f"    - Dimensions: {len(logs):,} rows x {len(fieldnames)} columns")
        print(f"    - File Size : {os.path.getsize(path):,} bytes")
        print(f"    - Columns   : {', '.join(fieldnames[:5])} ... (+{len(fieldnames)-5} more)")


# -----------------------------------------------------------------------------
# 3. Python Data Analysis Engine (Pandas & NumPy)
# -----------------------------------------------------------------------------

def perform_data_analysis(csv_path: str) -> pd.DataFrame:
    """
    Performs comprehensive exploratory and security data analysis using Pandas.
    Calculates distributions, data quality checks, and prints formatted report.
    """
    print("\n" + "="*65)
    print("      PYTHON DATA ANALYSIS REPORT: SECURITY TELEMETRY       ")
    print("="*65)

    df = pd.read_csv(csv_path, keep_default_na=False)

    # 1. Dataset Quality & Completeness Audit (on raw CSV columns)
    total_events = len(df)
    total_cols = len(df.columns)
    empty_cells = (df == "").sum().sum() + df.isna().sum().sum()
    duplicate_cols = [c for c in df.columns if (df[c] == df.iloc[:, 0]).all() and c != df.columns[0]]
    col1_name = df.columns[0]
    col2_name = df.columns[1] if total_cols > 1 else "N/A"
    col1_col2_identical = (df.iloc[:, 0] == df.iloc[:, 1]).all() if total_cols > 1 else False

    # Add datetime helper for time-series analysis
    df["event_time_dt"] = pd.to_datetime(df["event_time"])

    print(f"\n[1] Data Quality & Completeness Audit:")
    print(f"    - Total Log Events      : {total_events:,}")
    print(f"    - Total Columns         : {total_cols}")
    print(f"    - Column 1              : '{col1_name}'")
    print(f"    - Column 2              : '{col2_name}'")
    print(f"    - Are Col 1 & 2 Equal?  : {col1_col2_identical} (Distinct: {col1_name} != {col2_name})")
    print(f"    - Empty / Null Cells    : {empty_cells} (100.0% Complete - ZERO empty cells)")
    print(f"    - Any Duplicate Columns : {'NONE (All distinct)' if len(duplicate_cols) == 0 else f'WARNING: {duplicate_cols}'}")
    print(f"    - Monitored Hosts       : {df['host'].nunique()}")
    print(f"    - Unique Source IPs     : {df['source_ip'].nunique()}")
    print(f"    - Time Window Range     : {df['event_time_dt'].min()} --> {df['event_time_dt'].max()}")

    # 2. Severity Breakdown
    sev_counts = df["severity"].value_counts()
    sev_percent = (df["severity"].value_counts(normalize=True) * 100).round(1)
    sev_summary = pd.DataFrame({"Count": sev_counts, "Percentage (%)": sev_percent})
    print("\n[2] Severity Distribution:")
    print(sev_summary.to_string())

    # 3. Attack & Event Type Analysis
    event_counts = df["event_type"].value_counts()
    event_percent = (df["event_type"].value_counts(normalize=True) * 100).round(1)
    event_summary = pd.DataFrame({"Count": event_counts, "Percentage (%)": event_percent})
    print("\n[3] Event & Attack Patterns Breakdown:")
    print(event_summary.to_string())

    # 4. Top Malicious / Suspicious Source IPs
    threat_df = df[df["severity"].isin(["CRITICAL", "HIGH", "MEDIUM"])]
    top_threat_ips = (
        threat_df.groupby("source_ip")
        .agg(
            threat_events=("severity", "count"),
            max_severity=("severity", lambda x: "CRITICAL" if "CRITICAL" in x.values else ("HIGH" if "HIGH" in x.values else "MEDIUM")),
            primary_attack=("event_type", lambda x: x.mode()[0] if not x.empty else "N/A"),
            protocols=("protocol", lambda x: ",".join(sorted(x.dropna().unique())))
        )
        .sort_values(by="threat_events", ascending=False)
        .head(7)
    )
    print("\n[4] Top Suspicious Source IPs (Hostile Entities):")
    print(top_threat_ips.to_string())

    # 5. Top Targeted Usernames & Methods
    print("\n[5] Top Targeted Users & Invoked Methods:")
    user_summary = df["username"].value_counts().head(5)
    for u, cnt in user_summary.items():
        print(f"    - User: {u:<20} : {cnt:>4} events ({cnt/total_events*100:4.1f}%)")

    # 6. Hourly Activity Aggregation
    df["hour"] = df["event_time_dt"].dt.hour
    hourly_matrix = df.groupby(["hour", "severity"]).size().unstack(fill_value=0)
    for col in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if col not in hourly_matrix:
            hourly_matrix[col] = 0

    print("\n[6] Hourly Traffic & Threat Velocity (Sample Peak Hours):")
    peak_hours = hourly_matrix.sum(axis=1).nlargest(5).index.tolist()
    print(hourly_matrix.loc[peak_hours].to_string())

    print("\n" + "="*65 + "\n")
    return df


# -----------------------------------------------------------------------------
# 4. Publication-Quality Data Visualization Suite (Matplotlib)
# -----------------------------------------------------------------------------

def generate_soc_visualizations(df: pd.DataFrame, output_image_path: str):
    """
    Generates a dark-themed, publication-quality 6-panel security operations
    visualization matching the dashboard color aesthetics.
    """
    print(f"[*] Rendering data visualization dashboard to {output_image_path}...")

    plt.style.use('dark_background')
    fig = plt.figure(figsize=(18, 12), facecolor='#0b0f19')
    gs = GridSpec(3, 3, figure=fig, hspace=0.38, wspace=0.28)

    COLOR_CRIT = '#f43f5e'   # Rose
    COLOR_HIGH = '#f97316'   # Orange
    COLOR_MED  = '#f59e0b'   # Amber
    COLOR_LOW  = '#0ea5e9'   # Sky Blue
    COLOR_INFO = '#06b6d4'   # Cyan
    PANEL_BG   = '#111827'   # Slate 900
    TEXT_MUTED = '#94a3b8'
    TEXT_LIGHT = '#f8fafc'
    GRID_COLOR = '#1e293b'

    # ── Panel 1: Security Event Volume Over 24 Hours (Span 2 cols) ──────────
    ax1 = fig.add_subplot(gs[0, :2], facecolor=PANEL_BG)
    df_hourly = df.set_index("event_time_dt").resample("30min")["severity"].value_counts().unstack(fill_value=0)
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if s not in df_hourly.columns:
            df_hourly[s] = 0

    cols_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    colors = [COLOR_INFO, COLOR_LOW, COLOR_MED, COLOR_HIGH, COLOR_CRIT]

    ax1.stackplot(
        df_hourly.index,
        [df_hourly[c] for c in cols_order],
        labels=["Normal Info", "Low Priority", "Medium Warning", "High Threat", "Critical Alert"],
        colors=colors,
        alpha=0.85
    )
    ax1.set_title("SECURITY ACTIVITY & THREAT VELOCITY OVER TIME (30-MIN INTERVALS)", fontsize=11, fontweight='bold', color=TEXT_LIGHT, pad=12, loc='left')
    ax1.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    ax1.set_ylabel("Events / 30m", color=TEXT_MUTED, fontsize=9)
    ax1.grid(True, linestyle='--', alpha=0.3, color=GRID_COLOR)
    ax1.tick_params(colors=TEXT_MUTED, labelsize=8)
    ax1.legend(loc="upper left", frameon=True, facecolor='#1f2937', edgecolor='none', fontsize=8)

    # ── Panel 2: Threat Severity Distribution Donut ──────────────────────────
    ax2 = fig.add_subplot(gs[0, 2], facecolor=PANEL_BG)
    sev_counts = df["severity"].value_counts()
    sev_keys = [k for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if k in sev_counts]
    sev_vals = [sev_counts[k] for k in sev_keys]
    sev_colors = [COLOR_CRIT if k == "CRITICAL" else (COLOR_HIGH if k == "HIGH" else (COLOR_MED if k == "MEDIUM" else (COLOR_LOW if k == "LOW" else COLOR_INFO))) for k in sev_keys]

    wedges, texts, autotexts = ax2.pie(
        sev_vals,
        labels=sev_keys,
        autopct='%1.1f%%',
        colors=sev_colors,
        startangle=140,
        pctdistance=0.75,
        textprops=dict(color=TEXT_LIGHT, fontsize=8),
        wedgeprops=dict(width=0.45, edgecolor='#0b0f19', linewidth=2)
    )
    for at in autotexts:
        at.set_fontsize(7.5)
        at.set_fontweight('bold')
    ax2.set_title("SEVERITY DISTRIBUTION", fontsize=11, fontweight='bold', color=TEXT_LIGHT, pad=12, loc='left')

    # ── Panel 3: Attack / Event Types Breakdown (Horizontal Bar) ─────────────
    ax3 = fig.add_subplot(gs[1, :2], facecolor=PANEL_BG)
    et_counts = df["event_type"].value_counts().head(7).sort_values(ascending=True)
    y_pos = np.arange(len(et_counts))
    labels = [k.replace("_", " ").title() for k in et_counts.index]

    bar_colors = [
        COLOR_CRIT if "Sql" in l or "C2" in l else
        (COLOR_HIGH if "Ssh" in l or "Ddos" in l or "Privilege" in l else
        (COLOR_MED if "Port" in l else COLOR_INFO))
        for l in labels
    ]

    bars = ax3.barh(y_pos, et_counts.values, color=bar_colors, height=0.6, alpha=0.9)
    ax3.set_yticks(y_pos)
    ax3.set_yticklabels(labels, fontsize=8, color=TEXT_LIGHT)
    ax3.set_xlabel("Event Occurrences", color=TEXT_MUTED, fontsize=9)
    ax3.set_title("TOP SECURITY EVENT & ATTACK PATTERNS", fontsize=11, fontweight='bold', color=TEXT_LIGHT, pad=12, loc='left')
    ax3.grid(True, axis='x', linestyle='--', alpha=0.3, color=GRID_COLOR)
    ax3.tick_params(colors=TEXT_MUTED, labelsize=8)

    for bar in bars:
        width = bar.get_width()
        ax3.text(width + 8, bar.get_y() + bar.get_height()/2, f"{int(width):,}",
                 va='center', ha='left', fontsize=8, color=TEXT_LIGHT, fontweight='bold')

    # ── Panel 4: Top Hostile Source IPs by Threat Count ─────────────────────
    ax4 = fig.add_subplot(gs[1, 2], facecolor=PANEL_BG)
    hostile_df = df[df["severity"].isin(["CRITICAL", "HIGH", "MEDIUM"])]
    top_ips = hostile_df["source_ip"].value_counts().head(5)

    ax4.bar(top_ips.index, top_ips.values, color=COLOR_HIGH, width=0.55, alpha=0.85)
    ax4.set_title("TOP SUSPICIOUS SOURCE IPs", fontsize=11, fontweight='bold', color=TEXT_LIGHT, pad=12, loc='left')
    ax4.set_ylabel("Hostile Events", color=TEXT_MUTED, fontsize=8)
    ax4.grid(True, axis='y', linestyle='--', alpha=0.3, color=GRID_COLOR)
    ax4.tick_params(axis='x', rotation=30, colors=TEXT_MUTED, labelsize=7.5)
    ax4.tick_params(axis='y', colors=TEXT_MUTED, labelsize=8)

    # ── Panel 5: Network Protocols & Services Breakdown ──────────────────────
    ax5 = fig.add_subplot(gs[2, :2], facecolor=PANEL_BG)
    svc_proto = df.groupby(["service", "protocol"]).size().unstack(fill_value=0)
    top_svcs = df["service"].value_counts().head(6).index
    svc_proto_filtered = svc_proto.loc[top_svcs]

    svc_proto_filtered.plot(
        kind='bar',
        stacked=True,
        ax=ax5,
        colormap='cool',
        width=0.6,
        alpha=0.9
    )
    ax5.set_title("TARGETED SERVICES & TRANSPORT PROTOCOL MATRIX", fontsize=11, fontweight='bold', color=TEXT_LIGHT, pad=12, loc='left')
    ax5.set_ylabel("Log Volume", color=TEXT_MUTED, fontsize=9)
    ax5.set_xlabel("")
    ax5.grid(True, axis='y', linestyle='--', alpha=0.3, color=GRID_COLOR)
    ax5.tick_params(axis='x', rotation=0, colors=TEXT_LIGHT, labelsize=8.5)
    ax5.tick_params(axis='y', colors=TEXT_MUTED, labelsize=8)
    ax5.legend(loc="upper right", frameon=True, facecolor='#1f2937', edgecolor='none', fontsize=8)

    # ── Panel 6: Action & Mitigation Status (Pie) ───────────────────────────
    ax6 = fig.add_subplot(gs[2, 2], facecolor=PANEL_BG)
    action_counts = df["action"].value_counts()
    act_colors = ['#10b981', '#f43f5e', '#f59e0b', '#3b82f6', '#8b5cf6']

    ax6.pie(
        action_counts.values,
        labels=action_counts.index,
        autopct='%1.0f%%',
        colors=act_colors[:len(action_counts)],
        startangle=90,
        textprops=dict(color=TEXT_LIGHT, fontsize=8),
        wedgeprops=dict(edgecolor='#0b0f19', linewidth=1.5)
    )
    ax6.set_title("ENFORCEMENT ACTIONS (WAF/FW/PAM)", fontsize=11, fontweight='bold', color=TEXT_LIGHT, pad=12, loc='left')

    # Overall Title Banner
    fig.suptitle("SECURELOG AI - SOC TELEMETRY DATA ANALYSIS & THREAT VISUALIZATION",
                 fontsize=14, fontweight='black', color='#38bdf8', y=0.98)

    plt.savefig(output_image_path, dpi=200, bbox_inches='tight', facecolor='#0b0f19')
    plt.close()
    print(f"[+] Visualization dashboard generated successfully at: {output_image_path}")


# -----------------------------------------------------------------------------
# 5. Database Seeder (Populate log_events, alerts, incidents, TI)
# -----------------------------------------------------------------------------

def seed_database(df: pd.DataFrame, db_path: str):
    """
    Seeds SQLite database with log events, matching alerts,
    investigation incidents, and threat intelligence cache records.
    """
    print(f"[*] Seeding data into SQLite database: {db_path}...")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # 1. Clean old log_events & alerts
    cur.execute("DELETE FROM log_events")
    cur.execute("DELETE FROM alerts")
    cur.execute("DELETE FROM incidents")
    cur.execute("DELETE FROM threat_intel_cache")
    cur.execute("DELETE FROM ai_explanations")
    conn.commit()
    print("[*] Cleared existing tables.")

    # 2. Insert log_events (Supplying ingested_at explicitly for database schema)
    events_tuples = []
    for _, row in df.iterrows():
        event_time_str = str(row["event_time"])
        events_tuples.append((
            event_time_str,
            event_time_str,  # ingested_at
            str(row["host"]),
            str(row["source_ip"]),
            str(row["destination_ip"]),
            int(row["source_port"]),
            int(row["destination_port"]),
            str(row["username"]),
            str(row["event_type"]),
            str(row["action"]),
            str(row["protocol"]),
            str(row["service"]),
            str(row["method"]),
            str(row["path"]),
            int(row["status_code"]),
            str(row["severity"]),
            str(row["message"]),
            str(row["user_agent"]),
            str(row["raw_message"]),
            str(row["parser_name"]),
            str(row["parse_status"])
        ))

    cur.executemany("""
        INSERT INTO log_events (
            event_time, ingested_at, host, source_ip, destination_ip,
            source_port, destination_port, username, event_type, action,
            protocol, service, method, path, status_code,
            severity, message, user_agent, raw_message, parser_name, parse_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, events_tuples)
    print(f"[+] Inserted {len(events_tuples):,} log events into database.")

    # 3. Insert Correlated Alerts for the Dashboard & Alerts page
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    earlier_str = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")

    alerts_data = [
        (
            "SQL Injection Exploit Attempt in Web API",
            "Multiple SQL injection injection vectors matched WAF signatures against endpoint /api/v1/users.",
            "CRITICAL",
            "INVESTIGATING",
            "Rule: WAF SQLi Signature #4032",
            "185.220.101.5",
            "admin_inject",
            24,
            9.2,
            now_str,
            now_str,
            now_str
        ),
        (
            "Cobalt Strike C2 Beaconing Detected",
            "Anomalous outbound HTTPS heartbeats to known command-and-control server with matching JA3 fingerprint.",
            "CRITICAL",
            "NEW",
            "ML Anomaly + Threat Intel",
            "103.251.167.20",
            "svchost_exec",
            18,
            9.6,
            now_str,
            now_str,
            now_str
        ),
        (
            "Distributed SSH Brute Force Campaign",
            "Over 120 failed SSH authentication attempts within 10 minutes targeting root and admin accounts.",
            "HIGH",
            "OPEN",
            "Rule: SSH Auth Failure Threshold",
            "45.33.22.11",
            "root",
            128,
            7.8,
            earlier_str,
            earlier_str,
            earlier_str
        ),
        (
            "Volumetric SYN Flood Against Public VIP",
            "Inbound TCP SYN packets exceeded 2,500 pkts/sec threshold on port 443.",
            "HIGH",
            "INVESTIGATING",
            "DDoS Shield Rate Limiter",
            "198.51.100.12",
            "botnet_client",
            86,
            7.5,
            now_str,
            now_str,
            now_str
        ),
        (
            "Host Reconnaissance Port Scan (Nmap SYN)",
            "Systematic sequential port probe across ports 1-1024 from unauthorized foreign IP address.",
            "MEDIUM",
            "OPEN",
            "Suricata IDS: ET SCAN",
            "194.26.29.112",
            "scanner_agent",
            42,
            5.4,
            now_str,
            now_str,
            now_str
        ),
        (
            "Privilege Escalation Attempt on Production Host",
            "Unauthorized sudo invocation and attempt to modify sensitive /etc/shadow file.",
            "HIGH",
            "NEW",
            "Linux Auditd Monitor",
            "192.168.1.105",
            "devuser",
            6,
            8.1,
            now_str,
            now_str,
            now_str
        ),
        (
            "Unusual Tor Exit Node Traffic Connection",
            "Outbound network request routed toward confirmed public Tor relay router.",
            "MEDIUM",
            "RESOLVED",
            "Threat Intelligence Feed",
            "89.248.165.74",
            "anonymous",
            9,
            4.8,
            earlier_str,
            earlier_str,
            earlier_str
        )
    ]

    cur.executemany("""
        INSERT INTO alerts (
            title, description, severity, status, detection_type,
            source_ip, username, event_count, risk_score,
            created_at, updated_at, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, alerts_data)
    print(f"[+] Inserted {len(alerts_data)} alerts into database.")

    # 4. Insert Incidents
    incidents_data = [
        (
            "INC-2026-001",
            "Active Web Application SQL Injection & Data Exfiltration Attempt",
            "Attacker sourced from 185.220.101.5 launched automated SQL injection payloads targeting customer records API.",
            "CRITICAL",
            "P1",
            "INVESTIGATING",
            9.2,
            "SOC Detection Engine",
            now_str,
            now_str
        ),
        (
            "INC-2026-002",
            "Coordinated External SSH Brute Force Campaign",
            "Large-scale dictionary attack against edge bastion nodes from malicious IP clusters in ASN 4134.",
            "HIGH",
            "P2",
            "OPEN",
            7.8,
            "Fail2Ban / Syslog Analyzer",
            earlier_str,
            now_str
        ),
        (
            "INC-2026-003",
            "Suspicious C2 Beaconing from Internal Workstation",
            "Host 10.0.0.15 communicating with suspicious foreign IP 103.251.167.20 on high port 8443.",
            "CRITICAL",
            "P1",
            "NEW",
            9.5,
            "Network Traffic Analyzer",
            now_str,
            now_str
        )
    ]

    cur.executemany("""
        INSERT INTO incidents (
            incident_number, title, description, severity, priority, status,
            risk_score, source, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, incidents_data)
    print(f"[+] Inserted {len(incidents_data)} security incidents.")

    # 5. Populate Threat Intelligence Cache for Key Malicious IPs
    ti_ips = [
        ("185.220.101.5", 98, "Tor Project Exit Node / Known Scanner", "NL", "AbuseIPDB"),
        ("45.33.22.11", 86, "Reported for continuous SSH & RDP brute forcing", "US", "AbuseIPDB"),
        ("103.251.167.20", 99, "Confirmed Malicious C2 Beacon Controller", "RU", "ThreatConnect"),
        ("194.26.29.112", 74, "High velocity port scanner and vulnerability probe", "BG", "AbuseIPDB"),
        ("89.248.165.74", 65, "Known proxy / anonymization service", "DE", "AbuseIPDB")
    ]

    ti_cache_data = []
    exp_str = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
    for ip, score, desc, country, provider in ti_ips:
        res_json = json.dumps({
            "ip": ip,
            "abuse_confidence_score": score,
            "country_code": country,
            "usage_type": "Data Center/Web Hosting/Transit",
            "isp": f"Tier-1 Host ({country})",
            "domain": f"host-{ip.replace('.', '-')}.net",
            "total_reports": random.randint(140, 850),
            "description": desc,
            "is_whitelisted": False,
            "last_reported_at": now_str
        })
        ti_cache_data.append((ip, provider, res_json, now_str, exp_str))

    cur.executemany("""
        INSERT INTO threat_intel_cache (
            ip_address, provider, result, lookup_timestamp, expiration
        ) VALUES (?, ?, ?, ?, ?)
    """, ti_cache_data)
    print(f"[+] Inserted {len(ti_cache_data)} threat intelligence reputation records.")

    # 6. Populate AI Explanations for Alert 1 and Alert 2
    ai_explanations_data = [
        (
            1,  # Alert 1: SQLi
            "qwen2.5-coder:32b",
            "v1.0",
            "Automated SQL injection probe attempting data extraction via UNION query syntax.",
            json.dumps({
                "summary": "External threat actor (185.220.101.5) conducted a high-frequency injection probe against the /api/v1/users endpoint. Payloads show classic SQL UNION attacks aiming to retrieve password hashes.",
                "possible_attack_type": "SQL Injection (CWE-89)",
                "confidence": "HIGH (0.94)",
                "investigation_steps": [
                    "Verify if any database responses returned HTTP 200 or unexpected payload length",
                    "Review database query logs around timestamp to ensure queries were parameterized",
                    "Block IP 185.220.101.5 at the border firewall",
                    "Inspect WAF rules for automated IP banning"
                ],
                "evidence_summary": "URI pattern matched 'UNION SELECT username,password_hash' with 403 Forbidden enforcement.",
                "recommended_actions": [
                    "Add immediate IP shun rule in edge firewall",
                    "Verify ORM sanitization on users query handler"
                ]
            }),
            "HIGH",
            "SUCCESS",
            now_str
        ),
        (
            2,  # Alert 2: C2 Beaconing
            "qwen2.5-coder:32b",
            "v1.0",
            "Confirmed Command & Control beaconing behavior between internal host and known malicious foreign infrastructure.",
            json.dumps({
                "summary": "Internal endpoint 10.0.0.15 is exhibiting recurring beacon communication to 103.251.167.20. The interval and TLS JA3 signature strongly align with Cobalt Strike beaconing framework.",
                "possible_attack_type": "Command and Control Beaconing (MITRE ATT&CK T1071.001)",
                "confidence": "CRITICAL (0.98)",
                "investigation_steps": [
                    "Immediately isolate workstation 10.0.0.15 from the internal VLAN",
                    "Capture volatile memory dump (RAM) on 10.0.0.15 for forensic analysis",
                    "Check parent-child process hierarchy of any running PowerShell or script engines",
                    "Blacklist domain and IP 103.251.167.20 across enterprise DNS/firewall"
                ],
                "evidence_summary": "Regular 60-second beacon intervals, matched malicious JA3 TLS fingerprint, foreign destination in known threat feed.",
                "recommended_actions": [
                    "Quarantine host 10.0.0.15",
                    "Rotate domain credentials used on the affected host"
                ]
            }),
            "CRITICAL",
            "SUCCESS",
            now_str
        )
    ]

    cur.executemany("""
        INSERT INTO ai_explanations (
            alert_id, model_name, prompt_version, summary,
            explanation, confidence, generation_status, generated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, ai_explanations_data)
    print(f"[+] Inserted {len(ai_explanations_data)} AI Security Explanations.")

    conn.commit()
    conn.close()
    print("[+] Database seeding completed successfully!\n")


# -----------------------------------------------------------------------------
# Main Execution Entrypoint
# -----------------------------------------------------------------------------

def main():
    # 1. Generate realistic dataset with zero missing cells and distinct columns
    logs = generate_mock_security_logs(target_count=1450)

    # 2. Save CSV files to data/ and backend/data/
    save_logs_to_csv(logs, [CSV_PATH_DATA, CSV_PATH_BACKEND])

    # 3. Perform Pandas Data Analysis
    df = perform_data_analysis(CSV_PATH_DATA)

    # 4. Generate Matplotlib Visualizations
    output_viz_doc = os.path.join(DOCS_IMG_DIR, "soc_dashboard_visualization.png")
    generate_soc_visualizations(df, output_viz_doc)

    # 5. Seed the database
    seed_database(df, DB_PATH)

    print("=================================================================")
    print("  SUCCESS! Clean Dataset Generated, Analyzed, Visualized & Seeded")
    print(f"  - Dataset CSV (Root Data) : {CSV_PATH_DATA}")
    print(f"  - Dataset CSV (Backend)   : {CSV_PATH_BACKEND}")
    print(f"  - Data Visualizations     : {output_viz_doc}")
    print(f"  - SQLite Database         : {DB_PATH}")
    print("  - Live Dashboard          : http://localhost:5173")
    print("=================================================================")


if __name__ == "__main__":
    main()
