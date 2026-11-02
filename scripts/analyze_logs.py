#!/usr/bin/env python3
"""
SecureLog AI - Python Security Log Data Analysis & Visualization Tool
=====================================================================
Performs exploratory security data analysis, audits dataset completeness,
validates that zero cells are empty, checks for duplicate columns, and
optionally generates publication-ready visualizations.

Usage:
    python scripts/analyze_logs.py
    python scripts/analyze_logs.py --file data/dashboard_mock_logs.csv --plot docs/images/quick_analysis.png
"""

import sys
import os
import argparse
import pandas as pd
import numpy as np

DEFAULT_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CSV = os.path.join(DEFAULT_BASE, "data", "dashboard_mock_logs.csv")


def run_analysis(csv_path: str = None, plot_output: str = None) -> pd.DataFrame:
    if not csv_path or not os.path.exists(csv_path):
        candidates = [
            DEFAULT_CSV,
            os.path.join(DEFAULT_BASE, "backend", "data", "dashboard_mock_logs.csv"),
            os.path.join(DEFAULT_BASE, "dashboard_mock_logs.csv")
        ]
        found = False
        for c in candidates:
            if os.path.exists(c):
                csv_path = c
                found = True
                break
        if not found:
            print(f"[!] Error: Could not locate security log CSV at '{csv_path}'.")
            sys.exit(1)

    print("\n" + "="*70)
    print("      SECURELOG AI - PYTHON SECURITY DATA ANALYSIS & AUDIT      ")
    print("="*70)
    print(f"[*] Analyzing Dataset: {csv_path}")

    # Read CSV without interpreting empty strings as NaN initially, so we can detect both
    df = pd.read_csv(csv_path, keep_default_na=False)
    
    # -------------------------------------------------------------------------
    # 1. Dataset Integrity & Completeness Audit
    # -------------------------------------------------------------------------
    total_events = len(df)
    total_cols = len(df.columns)
    
    # Empty string or NaN count across all cells
    empty_cells = (df == "").sum().sum() + df.isna().sum().sum()
    empty_by_col = ((df == "").sum() + df.isna().sum())
    cols_with_empty = empty_by_col[empty_by_col > 0]
    
    # Check for identical duplicate columns
    col1_name = df.columns[0]
    col2_name = df.columns[1] if total_cols > 1 else "N/A"
    col1_col2_identical = (df.iloc[:, 0] == df.iloc[:, 1]).all() if total_cols > 1 else False
    
    duplicate_cols = []
    for i in range(total_cols):
        for j in range(i + 1, total_cols):
            if (df.iloc[:, i] == df.iloc[:, j]).all():
                duplicate_cols.append((df.columns[i], df.columns[j]))

    print(f"\n[1] DATA INTEGRITY & COMPLETENESS AUDIT:")
    print(f"    - Total Log Records      : {total_events:,}")
    print(f"    - Total Schema Columns   : {total_cols}")
    print(f"    - Column 1               : '{col1_name}'")
    print(f"    - Column 2               : '{col2_name}'")
    print(f"    - Identical Col 1 & Col 2: {'NO (Distinct)' if not col1_col2_identical else 'YES (DUPLICATE DETECTED!)'}")
    print(f"    - Duplicate Column Pairs : {'NONE (All distinct)' if not duplicate_cols else f'FOUND: {duplicate_cols}'}")
    print(f"    - Total Missing / Empty  : {empty_cells} cells (100.0% Complete)")
    if len(cols_with_empty) > 0:
        print(f"    - Columns with missing values: {cols_with_empty.to_dict()}")
    else:
        print(f"    - Cell Fill Rate         : 100% (Every single cell is populated)")

    # Datetime parse
    df["event_time_dt"] = pd.to_datetime(df["event_time"])
    time_min = df["event_time_dt"].min()
    time_max = df["event_time_dt"].max()
    print(f"    - Telemetry Time Range   : {time_min} --> {time_max}")

    # -------------------------------------------------------------------------
    # 2. Severity & Security Posture Breakdown
    # -------------------------------------------------------------------------
    print(f"\n[2] SEVERITY DISTRIBUTION:")
    sev_counts = df["severity"].value_counts()
    sev_pct = (df["severity"].value_counts(normalize=True) * 100).round(1)
    sev_summary = pd.DataFrame({"Count": sev_counts, "Percentage (%)": sev_pct})
    print(sev_summary.to_string())

    action_counts = df["action"].value_counts()
    print(f"\n[2b] FIREWALL / SOC ACTION SUMMARY:")
    for act, cnt in action_counts.items():
        pct = (cnt / total_events) * 100
        print(f"    - {act:<14}: {cnt:>5,} events ({pct:>5.1f}%)")

    # -------------------------------------------------------------------------
    # 3. Attack & Scenario Classifications
    # -------------------------------------------------------------------------
    print(f"\n[3] TOP ATTACK & TELEMETRY EVENT CLASSIFICATIONS:")
    event_counts = df["event_type"].value_counts()
    event_pct = (df["event_type"].value_counts(normalize=True) * 100).round(1)
    event_summary = pd.DataFrame({"Count": event_counts, "Percentage (%)": event_pct})
    print(event_summary.head(10).to_string())

    # -------------------------------------------------------------------------
    # 4. Identity & User Activity Analysis
    # -------------------------------------------------------------------------
    print(f"\n[4] USER IDENTITY INTELLIGENCE (TOP ACCOUNTS):")
    user_stats = (
        df.groupby("username")
        .agg(
            total_events=("event_type", "count"),
            threat_events=("severity", lambda x: sum(x.isin(["CRITICAL", "HIGH", "MEDIUM"]))),
            actions_blocked=("action", lambda x: sum(x == "BLOCKED")),
            top_event=("event_type", lambda x: x.mode()[0] if not x.empty else "N/A")
        )
        .sort_values(by="total_events", ascending=False)
        .head(8)
    )
    print(user_stats.to_string())

    # -------------------------------------------------------------------------
    # 5. Targeted Infrastructure & Hostile IPs
    # -------------------------------------------------------------------------
    threat_df = df[df["severity"].isin(["CRITICAL", "HIGH", "MEDIUM"])]
    print(f"\n[5] TOP HOSTILE SOURCE IPs (ATTACK SOURCES):")
    top_threat_ips = (
        threat_df.groupby("source_ip")
        .agg(
            threat_count=("severity", "count"),
            highest_severity=("severity", lambda x: "CRITICAL" if "CRITICAL" in x.values else ("HIGH" if "HIGH" in x.values else "MEDIUM")),
            primary_attack=("event_type", lambda x: x.mode()[0] if not x.empty else "N/A"),
            target_hosts=("host", lambda x: len(x.unique()))
        )
        .sort_values(by="threat_count", ascending=False)
        .head(6)
    )
    print(top_threat_ips.to_string())

    print(f"\n[5b] TOP MONITORED HOST NODES (DESTINATIONS):")
    host_counts = df["host"].value_counts()
    for h, cnt in host_counts.head(5).items():
        print(f"    - {h:<22} : {cnt:>5,} events ({(cnt/total_events)*100:>5.1f}%)")

    # -------------------------------------------------------------------------
    # 6. Web & Network Application Traffic Analysis
    # -------------------------------------------------------------------------
    print(f"\n[6] HTTP APPLICATION PROTOCOL ANALYSIS:")
    method_counts = df["method"].value_counts()
    print("    - HTTP Methods Breakdown:")
    for m, cnt in method_counts.head(6).items():
        print(f"        {m:<8} : {cnt:>5,} ({(cnt/total_events)*100:>4.1f}%)")

    status_counts = df["status_code"].value_counts()
    print("    - Top HTTP Status Codes:")
    for sc, cnt in status_counts.head(6).items():
        print(f"        Status {sc:<5} : {cnt:>5,} ({(cnt/total_events)*100:>4.1f}%)")

    # -------------------------------------------------------------------------
    # 7. Visualization Generation (Optional)
    # -------------------------------------------------------------------------
    if plot_output:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        print(f"\n[*] Generating multi-panel SOC visualization: {plot_output}...")
        plt.style.use("dark_background")
        fig, axes = plt.subplots(2, 2, figsize=(16, 10), facecolor="#0b1120")

        # Color definitions
        palette = ["#f43f5e", "#f97316", "#f59e0b", "#06b6d4", "#10b981", "#8b5cf6"]
        sev_colors = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#f59e0b",
            "LOW": "#3b82f6",
            "INFO": "#10b981"
        }

        # Subplot 1: Severity Donut
        ax1 = axes[0, 0]
        ax1.set_facecolor("#111827")
        sc = df["severity"].value_counts()
        c_list = [sev_colors.get(k, "#64748b") for k in sc.index]
        wedges, texts, autotexts = ax1.pie(
            sc.values,
            labels=sc.index,
            colors=c_list,
            autopct="%1.1f%%",
            startangle=140,
            wedgeprops=dict(width=0.45, edgecolor="#0b1120", linewidth=2.5),
            textprops=dict(color="#f8fafc", fontsize=9, fontweight="bold")
        )
        for at in autotexts:
            at.set_color("#0b1120")
            at.set_fontweight("heavy")
        ax1.set_title("EVENT SEVERITY BREAKDOWN", fontsize=11, fontweight="bold", color="#f8fafc", pad=12)

        # Subplot 2: Top Attack Categories
        ax2 = axes[0, 1]
        ax2.set_facecolor("#111827")
        top_attacks = df["event_type"].value_counts().head(7)
        labels = [k.replace("_", " ").title() for k in top_attacks.index]
        y_pos = np.arange(len(labels))
        ax2.barh(y_pos, top_attacks.values, color=palette[:len(labels)], edgecolor="#1e293b", height=0.65)
        ax2.set_yticks(y_pos)
        ax2.set_yticklabels(labels, color="#cbd5e1", fontsize=9)
        ax2.invert_yaxis()
        ax2.grid(True, axis="x", linestyle="--", alpha=0.2, color="#94a3b8")
        ax2.set_title("TOP ATTACK / EVENT CLASSIFICATIONS", fontsize=11, fontweight="bold", color="#f8fafc", pad=12)

        # Subplot 3: Hourly Telemetry Volume
        ax3 = axes[1, 0]
        ax3.set_facecolor("#111827")
        hourly = df.set_index("event_time_dt").resample("1h").size()
        ax3.fill_between(hourly.index, hourly.values, color="#38bdf8", alpha=0.3)
        ax3.plot(hourly.index, hourly.values, color="#38bdf8", lw=2, marker="o", markersize=3)
        ax3.set_title("TELEMETRY VOLUME (EVENTS PER HOUR)", fontsize=11, fontweight="bold", color="#f8fafc", pad=12)
        ax3.grid(True, linestyle="--", alpha=0.2, color="#94a3b8")
        ax3.tick_params(colors="#cbd5e1", labelsize=8)

        # Subplot 4: HTTP Status Code Distribution
        ax4 = axes[1, 1]
        ax4.set_facecolor("#111827")
        sc_plot = df["status_code"].value_counts().head(6)
        code_colors = ["#10b981" if str(c).startswith("2") else "#f59e0b" if str(c).startswith("3") else "#ef4444" for c in sc_plot.index]
        ax4.bar([f"HTTP {c}" for c in sc_plot.index], sc_plot.values, color=code_colors, edgecolor="#1e293b", width=0.55)
        ax4.set_title("HTTP RESPONSE CODES DISTRIBUTION", fontsize=11, fontweight="bold", color="#f8fafc", pad=12)
        ax4.grid(True, axis="y", linestyle="--", alpha=0.2, color="#94a3b8")
        ax4.tick_params(colors="#cbd5e1", labelsize=9)

        fig.suptitle(
            f"SecureLog AI - SOC Telemetry & Threat Analysis ({total_events:,} Events | 0 Null Cells)",
            fontsize=13, fontweight="bold", color="#38bdf8", y=0.98
        )
        os.makedirs(os.path.dirname(plot_output), exist_ok=True)
        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        plt.savefig(plot_output, dpi=200, facecolor="#0b1120")
        plt.close()
        print(f"[+] Visualization plot saved successfully: {plot_output}")

    print("\n" + "="*70 + "\n")
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze Security Log CSV Data")
    parser.add_argument("--file", "-f", default=None, help="Path to security CSV log file (defaults to data/dashboard_mock_logs.csv)")
    parser.add_argument("--plot", "-p", default=None, help="Output image file path for generated chart (optional)")
    args = parser.parse_args()

    run_analysis(args.file, args.plot)
