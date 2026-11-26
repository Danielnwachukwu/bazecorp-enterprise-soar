
import time
import subprocess
import json
import re
from datetime import datetime

from automation.notifications.telegram_notifier import TelegramNotifier

notifier = TelegramNotifier()

# BAZE CORP lab network
KALI_IP = "192.168.56.111"
WINDOWS_HOST_ONLY_IP = "192.168.56.1"

SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"
SECURITY_LOG = "Security"

SUSPICIOUS_PATTERNS = [
    r"powershell.*-enc",
    r"encodedcommand",
    r"mimikatz",
    r"sekurlsa",
    r"vssadmin\s+delete",
    r"net\s+user",
    r"net\s+group",
    r"whoami\s+/all",
]


def run_powershell(script):
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=20,
        encoding="utf-8",
        errors="replace",
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell command failed")

    if not result.stdout.strip():
        return []

    data = json.loads(result.stdout)

    if isinstance(data, dict):
        return [data]

    return data if isinstance(data, list) else []


def get_latest_record_id(log_name, event_id):
    script = (
        f"$e = Get-WinEvent -FilterHashtable "
        f"@{{LogName='{log_name}'; Id={event_id}}} "
        f"-MaxEvents 1 -ErrorAction Stop; "
        "$e.RecordId"
    )

    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        timeout=20,
        encoding="utf-8",
        errors="replace",
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Cannot read {log_name} Event ID {event_id}. "
            "Run PowerShell as Administrator. "
            + result.stderr.strip()
        )

    return int(result.stdout.strip())


def get_new_events(log_name, event_id, last_record_id):
    script = (
        f"$events = Get-WinEvent -FilterHashtable "
        f"@{{LogName='{log_name}'; Id={event_id}}} "
        "-MaxEvents 200 -ErrorAction SilentlyContinue; "
        "$events | "
        f"Where-Object {{ $_.RecordId -gt {last_record_id} }} | "
        "Sort-Object RecordId | "
        "Select-Object "
        "RecordId, "
        "@{Name='TimeCreated';Expression={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, "
        "Message | ConvertTo-Json -Depth 3 -Compress"
    )

    return sorted(
        run_powershell(script),
        key=lambda event: int(event.get("RecordId", 0)),
    )


def extract_field(message, field):
    """Extract a field and preserve wrapped values."""
    lines = message.splitlines()
    parts = []
    capturing = False

    for line in lines:
        if re.match(rf"^\s*{re.escape(field)}:\s*", line, re.IGNORECASE):
            value = re.sub(
                rf"^\s*{re.escape(field)}:\s*",
                "",
                line,
                count=1,
                flags=re.IGNORECASE,
            )
            parts = [value.strip()]
            capturing = True
            continue

        if capturing:
            if re.match(r"^\s*[A-Za-z][A-Za-z0-9_ ]*:\s*", line):
                break
            parts.append(line.strip())

    return " ".join(part for part in parts if part).strip() or "Unknown"


def send_telegram_alert(alert):
    response = notifier.send(alert)

    if response is not None:
        response.raise_for_status()

    print("[+] Telegram notification sent.")


def monitor_sysmon_event(event, hostname):
    message = event.get("Message", "")
    command_line = extract_field(message, "CommandLine")

    matched_pattern = next(
        (
            pattern
            for pattern in SUSPICIOUS_PATTERNS
            if re.search(pattern, command_line, re.IGNORECASE)
        ),
        None,
    )

    if not matched_pattern:
        return

    record_id = event.get("RecordId", "Unknown")
    event_time = event.get("TimeCreated", datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S"
    ))

    alert = (
        "BAZE CORP - SUSPECTED PROCESS ACTIVITY\n"
        f"Time: {event_time}\n"
        f"Host: {hostname}\n"
        f"User: {extract_field(message, 'User')}\n"
        f"Process: {extract_field(message, 'Image')}\n"
        f"Command: {command_line}\n"
        f"Sysmon Record ID: {record_id}\n"
        "Status: Requires analyst investigation"
    )

    print(f"[PROCESS ALERT] {command_line}")
    send_telegram_alert(alert)


def monitor_security_event(event, hostname):
    message = event.get("Message", "")

    source_ip = extract_field(message, "Source Address")
    destination_ip = extract_field(message, "Destination Address")
    direction = extract_field(message, "Direction")

    # Only alert on inbound connections from Kali to the Windows host-only IP.
    if (
        source_ip != KALI_IP
        or destination_ip != WINDOWS_HOST_ONLY_IP
        or direction.lower() != "inbound"
    ):
        return

    event_time = event.get("TimeCreated", datetime.now().astimezone().strftime(
        "%Y-%m-%d %H:%M:%S"
    ))

    alert = (
        "BAZE CORP - KALI CONNECTION OBSERVED\n"
        f"Time: {event_time}\n"
        f"Windows Host: {hostname}\n"
        f"Direction: {direction}\n"
        f"Source IP: {source_ip}\n"
        f"Source Port: {extract_field(message, 'Source Port')}\n"
        f"Destination IP: {destination_ip}\n"
        f"Destination Port: {extract_field(message, 'Destination Port')}\n"
        f"Application: {extract_field(message, 'Application Name')}\n"
        f"Process ID: {extract_field(message, 'Process ID')}\n"
        f"Protocol: {extract_field(message, 'Protocol')}\n"
        f"Security Record ID: {event.get('RecordId', 'Unknown')}\n"
        "Status: Connection recorded; requires analyst investigation"
    )

    print(
        f"[NETWORK ALERT] {source_ip} -> "
        f"{destination_ip}:{extract_field(message, 'Destination Port')}"
    )
    send_telegram_alert(alert)


def main():
    print("BAZE CORP - Live Security Monitor")
    print("Monitoring:")
    print("- Sysmon Event ID 1: suspicious process creation")
    print("- Security Event ID 5156: inbound Kali connections")
    print(f"- Kali IP: {KALI_IP}")
    print(f"- Windows host-only IP: {WINDOWS_HOST_ONLY_IP}")
    print("Press Ctrl+C to stop.")

    try:
        last_sysmon_id = get_latest_record_id(SYSMON_LOG, 1)
        last_security_id = get_latest_record_id(SECURITY_LOG, 5156)
    except Exception as exc:
        print(f"[Startup error] {exc}")
        return

    print(f"Starting after Sysmon record ID {last_sysmon_id}.")
    print(f"Starting after Security record ID {last_security_id}.")

    hostname_result = subprocess.run(
        ["hostname"],
        capture_output=True,
        text=True,
        timeout=5,
    )
    hostname = hostname_result.stdout.strip() or "Unknown"

    while True:
        try:
            sysmon_events = get_new_events(
                SYSMON_LOG, 1, last_sysmon_id
            )

            for event in sysmon_events:
                record_id = int(event.get("RecordId", 0))

                if record_id <= last_sysmon_id:
                    continue

                last_sysmon_id = record_id
                monitor_sysmon_event(event, hostname)

            security_events = get_new_events(
                SECURITY_LOG, 5156, last_security_id
            )

            for event in security_events:
                record_id = int(event.get("RecordId", 0))

                if record_id <= last_security_id:
                    continue

                last_security_id = record_id
                monitor_security_event(event, hostname)

            time.sleep(2)

        except KeyboardInterrupt:
            print("\nMonitor stopped.")
            break

        except Exception as exc:
            print(f"[Monitor error] {exc}")
            time.sleep(5)


if __name__ == "__main__":
    main()
