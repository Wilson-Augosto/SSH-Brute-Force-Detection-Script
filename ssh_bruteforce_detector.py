import re
import csv
from collections import defaultdict
from datetime import datetime

LOG_FILE = "sample_auth.log"     # change this to /var/log/auth.log if you're on Linux
THRESHOLD = 3                    # suspicious if >= this number of failures
OUTPUT_CSV = "ssh_alerts.csv"

# Regex for common SSH failure lines
FAILED_RE = re.compile(r"Failed password .* from (?P<ip>\d+\.\d+\.\d+\.\d+)")
ACCEPTED_RE = re.compile(r"Accepted password .* from (?P<ip>\d+\.\d+\.\d+\.\d+)")

failed_counts = defaultdict(int)
success_counts = defaultdict(int)

def parse_log_line(line: str):
    failed_match = FAILED_RE.search(line)
    if failed_match:
        return ("FAILED", failed_match.group("ip"))

    accepted_match = ACCEPTED_RE.search(line)
    if accepted_match:
        return ("SUCCESS", accepted_match.group("ip"))

    return (None, None)

def main():
    with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            status, ip = parse_log_line(line)
            if not status:
                continue
            if status == "FAILED":
                failed_counts[ip] += 1
            elif status == "SUCCESS":
                success_counts[ip] += 1

    suspicious = {ip: c for ip, c in failed_counts.items() if c >= THRESHOLD}

    print("=== SSH Brute-Force Detector ===")
    print(f"Log File: {LOG_FILE}")
    print(f"Threshold: {THRESHOLD} failed attempts\n")

    if not suspicious:
        print("✅ No suspicious IPs detected.")
    else:
        print("🚨 Suspicious IPs detected:")
        for ip, count in sorted(suspicious.items(), key=lambda x: x[1], reverse=True):
            successes = success_counts.get(ip, 0)
            print(f"- {ip}: {count} failed attempts | {successes} successful logins")

    # Export CSV report
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["timestamp", "ip_address", "failed_attempts", "successful_logins", "flagged"])
        now = datetime.now().isoformat(timespec="seconds")

        # include all IPs found (failed or success)
        all_ips = set(failed_counts.keys()) | set(success_counts.keys())
        for ip in sorted(all_ips):
            fails = failed_counts.get(ip, 0)
            succ = success_counts.get(ip, 0)
            flagged = "YES" if fails >= THRESHOLD else "NO"
            writer.writerow([now, ip, fails, succ, flagged])

    print(f"\n📄 Report saved: {OUTPUT_CSV}")

if __name__ == "__main__":
    main()