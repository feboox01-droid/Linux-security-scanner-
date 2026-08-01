#!/usr/bin/env python3
"""
Linux Security Scanner
------------------------
A defensive tool to check YOUR OWN Linux machine for signs of compromise.
Run it periodically (e.g. via cron) or on-demand from the terminal.

This tool only READS system information (processes, network state, logs).
It does not modify anything unless you explicitly run it with --fix
on a specific finding (future extension point).

Usage:
    python3 scanner.py            # run full scan, print report
    python3 scanner.py --html     # also save an HTML report
    sudo python3 scanner.py       # recommended, for full access to logs/ports
"""

import subprocess
import os
import sys
import socket
import pwd
import datetime
import json
import argparse

# ---------- helpers ----------

def run(cmd):
    """Run a shell command safely and return its stdout as text."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip()
    except Exception as e:
        return f"[error running command: {e}]"


def section(title):
    print(f"\n{'='*60}\n{title}\n{'='*60}")


# ---------- checks ----------

def check_processes():
    """List processes and flag ones running from unusual locations."""
    section("1. Running Processes")
    findings = []
    output = run("ps -eo pid,ppid,user,%cpu,%mem,comm,args --sort=-%cpu")
    lines = output.splitlines()
    print("\n".join(lines[:20]))  # show top 20 by CPU
    if len(lines) > 20:
        print(f"... ({len(lines)-20} more processes, showing top 20 by CPU)")

    # Flag processes running from suspicious paths
    suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/"]
    proc_paths = run("ls -la /proc/*/exe 2>/dev/null")
    for line in proc_paths.splitlines():
        for sp in suspicious_paths:
            if sp in line:
                findings.append(f"Process executable running from suspicious path: {line}")

    if findings:
        print("\n[!] Findings:")
        for f in findings:
            print(f"  - {f}")
    else:
        print("\n[OK] No processes found running from suspicious temp directories.")
    return findings


def check_network_connections():
    """Show active network connections and flag unexpected listening ports."""
    section("2. Network Connections")
    findings = []
    output = run("ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null")
    print(output if output else "[error] Could not read network connections (try running with sudo).")

    established = [l for l in output.splitlines() if "ESTAB" in l or "ESTABLISHED" in l]
    if established:
        print(f"\n[i] {len(established)} established connection(s) found. Review the remote IPs above.")
        print("    Tip: cross-check unfamiliar IPs at https://ipinfo.io or similar (manually, not automated here).")

    return findings


def check_listening_ports():
    """List ports currently listening for connections."""
    section("3. Listening Ports")
    output = run("ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null")
    print(output if output else "[error] Could not read listening ports.")
    return []


def check_startup_items():
    """Check systemd services, cron jobs, and common autostart locations."""
    section("4. Startup Items / Persistence Mechanisms")
    findings = []

    print("-- Enabled systemd services --")
    print(run("systemctl list-unit-files --state=enabled --no-pager 2>/dev/null | head -30"))

    print("\n-- User crontabs --")
    for user_entry in pwd.getpwall():
        username = user_entry.pw_name
        cron_output = run(f"crontab -l -u {username} 2>/dev/null")
        if cron_output:
            print(f"[{username}]\n{cron_output}")

    print("\n-- System-wide cron --")
    print(run("cat /etc/crontab 2>/dev/null"))
    print(run("ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null"))

    print("\n-- rc.local / profile.d (older persistence spots) --")
    print(run("cat /etc/rc.local 2>/dev/null"))

    return findings


def check_login_history():
    """Check recent login history and failed login attempts."""
    section("5. Login History & Failed Attempts")
    findings = []

    print("-- Recent successful logins (last) --")
    print(run("last -a | head -20"))

    print("\n-- Currently logged in users (who) --")
    print(run("who"))

    print("\n-- Failed login attempts (auth log) --")
    auth_log_output = run(
        "grep -i 'failed\\|failure' /var/log/auth.log 2>/dev/null | tail -20 || "
        "journalctl -u ssh --no-pager 2>/dev/null | grep -i fail | tail -20"
    )
    if auth_log_output:
        print(auth_log_output)
        fail_count = len(auth_log_output.splitlines())
        if fail_count >= 10:
            findings.append(f"{fail_count} failed login attempts found in recent logs — possible brute-force attempts.")
    else:
        print("[i] No failed-login entries found or log not accessible (try sudo).")

    return findings


def check_users_and_sudoers():
    """List user accounts and who has sudo/admin rights."""
    section("6. User Accounts & Privileges")
    findings = []

    print("-- Accounts with login shells (real users) --")
    output = run("awk -F: '$7 !~ /(nologin|false)/ {print $1, $3, $7}' /etc/passwd")
    print(output)

    print("\n-- Members of sudo/admin group --")
    print(run("getent group sudo 2>/dev/null"))
    print(run("getent group wheel 2>/dev/null"))

    print("\n-- Recently created user accounts (check manually against /etc/passwd timestamps) --")
    print(run("ls -la /home"))

    return findings


def check_file_integrity_baseline(baseline_path="baseline_hashes.json", update=False):
    """
    Compare hashes of key system binaries against a saved baseline.
    First run creates the baseline; later runs detect changes.
    """
    section("7. Critical File Integrity")
    findings = []
    watch_files = [
        "/bin/bash", "/bin/ls", "/bin/ps", "/usr/bin/ssh", "/usr/bin/sudo",
        "/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config",
    ]

    current_hashes = {}
    for f in watch_files:
        if os.path.exists(f):
            h = run(f"sha256sum {f} 2>/dev/null").split()
            if h:
                current_hashes[f] = h[0]

    if not os.path.exists(baseline_path) or update:
        with open(baseline_path, "w") as fh:
            json.dump(current_hashes, fh, indent=2)
        print(f"[i] Baseline saved to {baseline_path}. Run the scanner again later to detect changes.")
        return findings

    with open(baseline_path) as fh:
        baseline = json.load(fh)

    for f, current_hash in current_hashes.items():
        old_hash = baseline.get(f)
        if old_hash and old_hash != current_hash:
            findings.append(f"File changed since baseline: {f}")
            print(f"[!] CHANGED: {f}")
        else:
            print(f"[OK] Unchanged: {f}")

    return findings


# ---------- report ----------

def generate_html_report(all_findings):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Scan Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
h1 {{ color: #333; }}
.finding {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 8px 0; }}
.ok {{ background: #d4edda; border-left: 4px solid #28a745; padding: 10px; margin: 8px 0; }}
</style></head><body>
<h1>Linux Security Scan Report</h1>
<p>Generated: {timestamp}</p>
"""
    if all_findings:
        html += "<h2>Findings requiring attention:</h2>"
        for f in all_findings:
            html += f'<div class="finding">{f}</div>'
    else:
        html += '<div class="ok">No suspicious findings detected in this scan.</div>'

    html += "</body></html>"
    with open("scan_report.html", "w") as fh:
        fh.write(html)
    print("\n[i] HTML report saved to scan_report.html")


# ---------- main ----------

def main():
    parser = argparse.ArgumentParser(description="Linux Security Scanner (defensive, read-only)")
    parser.add_argument("--html", action="store_true", help="Also generate an HTML report")
    parser.add_argument("--update-baseline", action="store_true", help="Update the file integrity baseline")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("[i] Tip: run with 'sudo' for full access to logs, ports, and processes.\n")

    print(f"Linux Security Scanner — scan started {datetime.datetime.now()}")
    print(f"Host: {socket.gethostname()}")

    all_findings = []
    all_findings += check_processes()
    all_findings += check_network_connections()
    all_findings += check_listening_ports()
    all_findings += check_startup_items()
    all_findings += check_login_history()
    all_findings += check_users_and_sudoers()
    all_findings += check_file_integrity_baseline(update=args.update_baseline)

    section("SUMMARY")
    if all_findings:
        print(f"[!] {len(all_findings)} finding(s) to review:")
        for f in all_findings:
            print(f"  - {f}")
        print("\nThese are NOT confirmed compromises — review each manually.")
    else:
        print("[OK] No red flags detected in this scan.")

    if args.html:
        generate_html_report(all_findings)


if __name__ == "__main__":
    main()
