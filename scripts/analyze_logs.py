"""
analyze_logs.py

Purpose:
    Analyze authentication logs for indicators of a brute-force attack.

Usage:
    python analyze_logs.py sample_logs/redacted_log.txt

Author: Keith
"""

import argparse
import re
from collections import Counter, defaultdict

# Example log format:
# 2026-04-02 08:14:21 Failed login admin from 192.168.10.25

LOG_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<status>Failed|Successful)\s+login\s+'
    r'(?P<user>\S+)\s+from\s+'
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
)


def analyze_log(filepath):
    failed_counts = Counter()
    successful_logins = []
    timeline = defaultdict(list)

    with open(filepath, "r") as file:
        for line in file:
            match = LOG_PATTERN.search(line)

            if not match:
                continue

            data = match.groupdict()

            timestamp = data["timestamp"]
            status = data["status"]
            username = data["user"]
            ip = data["ip"]

            timeline[ip].append((timestamp, status))

            if status == "Failed":
                failed_counts[ip] += 1
            else:
                successful_logins.append((timestamp, username, ip))

    return failed_counts, successful_logins, timeline


def print_report(failed_counts, successful_logins, timeline):

    print("=" * 60)
    print("Authentication Log Analysis")
    print("=" * 60)

    print("\nFailed Login Counts")

    for ip, count in failed_counts.most_common():
        print(f"{ip:<16} {count}")

    print("\nSuspicious IP Addresses (10+ failures)")

    suspicious = []

    for ip, count in failed_counts.items():
        if count >= 10:
            suspicious.append(ip)
            print(f"• {ip} ({count} failed attempts)")

    if not suspicious:
        print("None detected.")

    print("\nSuccessful Logins")

    if successful_logins:
        for timestamp, user, ip in successful_logins:
            print(f"{timestamp} | {user} | {ip}")
    else:
        print("No successful logins found.")

    print("\nPotential Brute Force Indicators")

    for ip in suspicious:
        print(f"\n{ip}")

        events = timeline[ip]

        print(f"Total Events: {len(events)}")

        print("Timeline:")

        for timestamp, status in events[:10]:
            print(f"  {timestamp} - {status}")

        if len(events) > 10:
            print("  ...")

    print("\nAnalysis Complete.")


def main():

    parser = argparse.ArgumentParser(
        description="Analyze authentication logs for brute-force attacks."
    )

    parser.add_argument(
        "logfile",
        help="Path to authentication log"
    )

    args = parser.parse_args()

    failed_counts, successful_logins, timeline = analyze_log(args.logfile)

    print_report(failed_counts, successful_logins, timeline)


if __name__ == "__main__":
    main()
