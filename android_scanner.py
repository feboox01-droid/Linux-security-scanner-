#!/usr/bin/env python3
"""
Android Security Scanner (via ADB)
------------------------------------
A defensive tool to check YOUR OWN Android phone for signs of compromise.
Runs from your computer over a USB (or wireless) ADB connection.
No app needs to be installed on the phone.

Requirements:
    - adb installed on this computer (sudo apt install android-tools-adb)
    - USB debugging enabled on the phone, phone connected and authorized

Usage:
    python3 android_scanner.py
    python3 android_scanner.py --html
"""

import subprocess
import datetime
import argparse
import sys


def adb(cmd):
    """Run an adb shell command and return stdout as text."""
    try:
        result = subprocess.run(
            f"adb shell {cmd}", shell=True, capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()
    except Exception as e:
        return f"[error running adb command: {e}]"


def section(title):
    print(f"\n{'='*60}\n{title}\n{'='*60}")


def check_device_connected():
    result = subprocess.run("adb devices", shell=True, capture_output=True, text=True)
    lines = [l for l in result.stdout.strip().splitlines() if l and "List of devices" not in l]
    if not lines or "device" not in result.stdout:
        print("[!] No device found. Make sure:")
        print("    - USB debugging is enabled on the phone")
        print("    - Phone is connected and you tapped 'Allow' on the popup")
        print("    - Run 'adb devices' manually to check status")
        sys.exit(1)
    print(f"[OK] Device connected: {lines[0]}")


def check_installed_apps():
    """List all installed packages, separating system vs user-installed."""
    section("1. Installed Apps")
    findings = []

    user_apps = adb("pm list packages -3").replace("package:", "").splitlines()
    print(f"[i] {len(user_apps)} user-installed apps found (excluding system apps).\n")
    for app in sorted(user_apps):
        print(f"  - {app}")

    return findings, user_apps


def check_install_source(user_apps):
    """Check if apps were installed from outside the Play Store."""
    section("2. App Install Sources (sideloaded apps)")
    findings = []

    for app in user_apps:
        installer = adb(f"pm list packages -i {app}").strip()
        if "installer=" in installer:
            source = installer.split("installer=")[-1].strip()
            if source in ("null", "") or "vending" not in source:
                findings.append(f"{app} — installed from non-Play-Store source ({source or 'unknown'})")

    if findings:
        print("[!] Apps NOT installed via Play Store (review these carefully):")
        for f in findings:
            print(f"  - {f}")
    else:
        print("[OK] All apps appear to be installed via Play Store.")

    return findings


def check_device_admin_apps():
    """List apps with Device Admin privileges — a common spyware persistence method."""
    section("3. Device Admin Apps (deep control)")
    findings = []

    output = adb("dumpsys device_policy")
    print(output[:3000] if output else "[i] Could not read device policy info.")

    if "Admin" in output:
        findings.append("Device has active Device Admin apps — verify each one is something you installed intentionally.")

    return findings


def check_accessibility_services():
    """List apps with Accessibility Service access — commonly abused by spyware/stalkerware."""
    section("4. Accessibility Services (can read screen, simulate taps)")
    findings = []

    output = adb("settings get secure enabled_accessibility_services")
    print(f"Enabled accessibility services:\n{output if output else '(none)'}")

    if output and output != "null":
        findings.append(f"Accessibility services enabled: {output} — confirm you recognize and trust every one.")

    return findings


def check_root_status():
    """Check whether the device is rooted (increases risk if unintentional)."""
    section("5. Root Status")
    findings = []

    su_check = adb("which su")
    build_tags = adb("getprop ro.build.tags")

    if su_check or "test-keys" in build_tags:
        print("[!] Device may be rooted or running a non-standard build.")
        findings.append("Device shows signs of root access (su binary found or test-keys build) — if you didn't root it yourself, this is a serious concern.")
    else:
        print("[OK] No root indicators found.")

    return findings


def check_unknown_sources_setting():
    """Check if 'install from unknown sources' is enabled globally (older Android)."""
    section("6. Unknown Sources Setting")
    findings = []

    output = adb("settings get secure install_non_market_apps")
    print(f"install_non_market_apps = {output}")
    if output == "1":
        findings.append("Installing from unknown sources is globally enabled — consider disabling unless needed.")

    return findings


def check_running_services():
    """Show currently running background services — useful for spotting unfamiliar persistent processes."""
    section("7. Running Background Services")
    output = adb("dumpsys activity services | grep -i 'ProcessRecord\\|packageName' | head -40")
    print(output if output else "[i] Could not retrieve running services.")
    return []


def generate_html_report(all_findings):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Android Security Scan Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
h1 {{ color: #333; }}
.finding {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 8px 0; }}
.ok {{ background: #d4edda; border-left: 4px solid #28a745; padding: 10px; margin: 8px 0; }}
</style></head><body>
<h1>Android Security Scan Report</h1>
<p>Generated: {timestamp}</p>
"""
    if all_findings:
        html += "<h2>Findings requiring attention:</h2>"
        for f in all_findings:
            html += f'<div class="finding">{f}</div>'
    else:
        html += '<div class="ok">No suspicious findings detected in this scan.</div>'
    html += "</body></html>"
    with open("android_scan_report.html", "w") as fh:
        fh.write(html)
    print("\n[i] HTML report saved to android_scan_report.html")


def main():
    parser = argparse.ArgumentParser(description="Android Security Scanner via ADB (defensive, read-only)")
    parser.add_argument("--html", action="store_true", help="Also generate an HTML report")
    args = parser.parse_args()

    print(f"Android Security Scanner — scan started {datetime.datetime.now()}")
    check_device_connected()

    all_findings = []
    _, user_apps = check_installed_apps()
    all_findings += check_install_source(user_apps)
    all_findings += check_device_admin_apps()
    all_findings += check_accessibility_services()
    all_findings += check_root_status()
    all_findings += check_unknown_sources_setting()
    all_findings += check_running_services()

    section("SUMMARY")
    if all_findings:
        print(f"[!] {len(all_findings)} finding(s) to review:")
        for f in all_findings:
            print(f"  - {f}")
        print("\nThese are NOT confirmed compromises — review each manually.")
        print("If you don't recognize an app or permission, uninstall it or investigate further.")
    else:
        print("[OK] No red flags detected in this scan.")

    if args.html:
        generate_html_report(all_findings)


if __name__ == "__main__":
    main()
