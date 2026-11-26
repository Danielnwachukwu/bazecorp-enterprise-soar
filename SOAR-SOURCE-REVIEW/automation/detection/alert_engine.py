from colorama import Fore, Style
from datetime import datetime
import uuid

from automation.notifications.telegram_notifier import TelegramNotifier

telegram = TelegramNotifier()

def print_alert(event):

    severity = event.get("Severity", "LOW")

    colors = {
        "LOW": Fore.GREEN,
        "MEDIUM": Fore.YELLOW,
        "HIGH": Fore.RED,
        "CRITICAL": Fore.MAGENTA
    }

    icons = {
        "LOW": "🟢",
        "MEDIUM": "🟡",
        "HIGH": "🔴",
        "CRITICAL": "🚨"
    }

    color = colors.get(severity, Fore.WHITE)
    icon = icons.get(severity, "⚪")

    alert_id = str(uuid.uuid4())[:8].upper()

    telegram_message = f"""
🚨 *{severity} SEVERITY ALERT*

*Detection:* {event.get("Classification")}
*Severity:* {severity}
*MITRE:* {event.get("MITRE ATT&CK")}

*Host:* {event.get("Host")}
*User:* {event.get("User")}

*Time:* {event.get("Time")}

*Command:*
`{event.get("Command Line")}`

Alert ID: {alert_id}
"""
    print()

    print(color + "█" * 78)
    print(f"{icon}  {severity} SEVERITY ALERT")
    print("█" * 78)
    print(Style.RESET_ALL)

    print(f"Alert ID          : {alert_id}")
    print(f"Generated         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    print()

    print("EVENT INFORMATION")
    print("-----------------")

    print(f"Event Time        : {event.get('Time')}")
    print(f"Host              : {event.get('Host')}")
    print(f"User              : {event.get('User')}")

    print()

    print("PROCESS INFORMATION")
    print("-------------------")

    print(f"Image             : {event.get('Image')}")
    print(f"Parent Image      : {event.get('Parent Image')}")
    print(f"Command Line      : {event.get('Command Line')}")

    print()

    print("THREAT ANALYSIS")
    print("----------------")

    print(f"Detection         : {event.get('Classification')}")
    print(f"Severity          : {severity}")
    print(f"MITRE ATT&CK      : {event.get('MITRE ATT&CK')}")

    print()

    print("INVESTIGATION CHECKLIST")
    print("-----------------------")

    if severity == "CRITICAL":

        print("[!] Isolate the endpoint immediately")
        print("[!] Acquire volatile memory")
        print("[!] Disable affected account")
        print("[!] Notify Incident Response Team")
        print("[!] Search environment for similar activity")

    elif severity == "HIGH":

        print("[+] Review PowerShell Operational Logs")
        print("[+] Review Sysmon Event Logs")
        print("[+] Examine parent-child process relationship")
        print("[+] Check persistence mechanisms")
        print("[+] Validate network connections")

    elif severity == "MEDIUM":

        print("[+] Review executed command")
        print("[+] Investigate parent process")
        print("[+] Validate user activity")
        print("[+] Determine if execution is expected")

    else:

        print("[+] Record activity")
        print("[+] Continue monitoring")

        print()

    # Send Telegram Notification
    try:
        telegram.send(telegram_message)
    except Exception as e:
        print(Fore.RED + f"[Telegram Error] {e}")

    print(color + "■" * 78)
    print(Style.RESET_ALL)

    