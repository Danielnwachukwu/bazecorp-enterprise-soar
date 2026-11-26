"""
============================================================
SPLUNK THREAT HUNTING AUTOMATION ENGINE
Author: Daniel Nwachukwu
Version: 2.0
============================================================
"""

import json
import sys
from pathlib import Path
from colorama import Fore, Style, init

from .alert_engine import print_alert
from ..notifications.report_generator import generate_report

init(autoreset=True)

# ============================================================
# FILE PATHS
# ============================================================

BASE_DIR = Path(__file__).parent.parent

INPUT_FILE = BASE_DIR / "datasets" / "recon_events.json"
OUTPUT_FILE = BASE_DIR / "datasets" / "parsed_recon_events.json"

# ============================================================
# DETECTION DATABASE
# ============================================================

DETECTION_RULES = {

    # ====================================================
    # WINDOWS DISCOVERY
    # ====================================================

    "whoami.exe": {

        "classification": "User Discovery",

        "severity": "HIGH",

        "mitre": "T1033"

    },

    "hostname.exe": {

        "classification": "System Discovery",

        "severity": "MEDIUM",

        "mitre": "T1082"

    },

    "ipconfig.exe": {

        "classification": "Network Configuration Discovery",

        "severity": "MEDIUM",

        "mitre": "T1016"

    },

    "systeminfo.exe": {

        "classification": "System Information Discovery",

        "severity": "MEDIUM",

        "mitre": "T1082"

    },

    "tasklist.exe": {

        "classification": "Process Discovery",

        "severity": "MEDIUM",

        "mitre": "T1057"

    },

    "net.exe": {

        "classification": "Network Enumeration",

        "severity": "MEDIUM",

        "mitre": "T1018"

    },

    "net1.exe": {

        "classification": "Network Enumeration",

        "severity": "MEDIUM",

        "mitre": "T1018"

    },

    "arp.exe": {

        "classification": "ARP Discovery",

        "severity": "LOW",

        "mitre": "T1016"

    },

    "route.exe": {

        "classification": "Route Discovery",

        "severity": "LOW",

        "mitre": "T1016"

    },

    "netstat.exe": {

        "classification": "Network Connections Discovery",

        "severity": "MEDIUM",

        "mitre": "T1049"

    },

    "schtasks.exe": {

        "classification": "Scheduled Task Enumeration",

        "severity": "HIGH",

        "mitre": "T1053"

    },

    # ====================================================
    # LOLBINS
    # ====================================================

    "certutil.exe": {

        "classification": "LOLBin - CertUtil",

        "severity": "HIGH",

        "mitre": "T1105"

    },

    "bitsadmin.exe": {

        "classification": "LOLBin - BITSAdmin",

        "severity": "HIGH",

        "mitre": "T1197"

    },

    "mshta.exe": {

        "classification": "LOLBin - MSHTA",

        "severity": "HIGH",

        "mitre": "T1218.005"

    },

    "rundll32.exe": {

        "classification": "LOLBin - RunDLL32",

        "severity": "HIGH",

        "mitre": "T1218.011"

    },

    "regsvr32.exe": {

        "classification": "LOLBin - Regsvr32",

        "severity": "HIGH",

        "mitre": "T1218.010"

    },

    "wmic.exe": {

        "classification": "LOLBin - WMIC",

        "severity": "HIGH",

        "mitre": "T1047"

    },

    "curl.exe": {

        "classification": "File Download",

        "severity": "HIGH",

        "mitre": "T1105"

    },

    "cmd.exe": {

        "classification": "Windows Command Shell",

        "severity": "MEDIUM",

        "mitre": "T1059.003"

    },

    # ====================================================
    # POWERSHELL
    # ====================================================

    "powershell.exe": {

        "classification": "PowerShell Execution",

        "severity": "HIGH",

        "mitre": "T1059.001"

    }

}

# ============================================================
# POWERSHELL COMMAND DATABASE
# ============================================================

POWERSHELL_RULES = {

    "get-process": {

        "classification": "PowerShell Process Discovery",

        "severity": "MEDIUM",

        "mitre": "T1057"

    },

    "get-service": {

        "classification": "PowerShell Service Discovery",

        "severity": "MEDIUM",

        "mitre": "T1007"

    },

    "get-localuser": {

        "classification": "PowerShell Account Discovery",

        "severity": "MEDIUM",

        "mitre": "T1087"

    },

    "whoami /groups": {

        "classification": "Permission Group Discovery",

        "severity": "MEDIUM",

        "mitre": "T1069"

    },

    "whoami /priv": {

        "classification": "Privilege Discovery",

        "severity": "HIGH",

        "mitre": "T1069"

    },

    "ipconfig": {

        "classification": "Network Configuration Discovery",

        "severity": "MEDIUM",

        "mitre": "T1016"

    },

    "systeminfo": {

        "classification": "System Information Discovery",

        "severity": "MEDIUM",

        "mitre": "T1082"

    }

}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def load_events(start_line=0):
    """
    Load JSONL events.

    Supports:
    1. Raw synthetic telemetry
    2. Splunk exported events containing a "result" field
    """

    events = []

    with open(INPUT_FILE, "r", encoding="utf-8") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            obj = json.loads(line)

            if "result" in obj:
                events.append(obj["result"])

            else:
                events.append(obj)

    if start_line > 0:
        return events[start_line:]

    return events

def get_default_detection():

    return {

        "classification": "Unknown Activity",

        "severity": "LOW",

        "mitre": "N/A"

    }

# ============================================================
# DETECTION ENGINE
# ============================================================
def detect_event(event):
    """
    Detect attack techniques using
    Image and CommandLine fields.
    """

    image = event.get("Image", "").lower()
    command = event.get("CommandLine", "").lower()

    detection = get_default_detection()

    # =================================================
    # LOLBIN COMMAND DETECTION
    # =================================================

    if "certutil.exe" in image:

        if "-urlcache" in command:

            return {
                "classification": "LOLBin Download",
                "severity": "CRITICAL",
                "mitre": "T1105"
            }

        elif "-encode" in command:

            return {
                "classification": "LOLBin Encoding",
                "severity": "HIGH",
                "mitre": "T1027"
            }

        elif "-decode" in command:

            return {
                "classification": "LOLBin Decoding",
                "severity": "HIGH",
                "mitre": "T1140"
            }

    elif "mshta.exe" in image:

        if "http" in command:

            return {
                "classification": "Remote HTA Execution",
                "severity": "CRITICAL",
                "mitre": "T1218.005"
            }

    elif "rundll32.exe" in image:

        if "javascript:" in command:

            return {
                "classification": "JavaScript LOLBin Execution",
                "severity": "CRITICAL",
                "mitre": "T1218.011"
            }

    elif "regsvr32.exe" in image:

        if "http" in command:

            return {
                "classification": "Remote Scriptlet Execution",
                "severity": "CRITICAL",
                "mitre": "T1218.010"
            }

    # =================================================
    # PowerShell Detection
    # =================================================

    if "powershell.exe" in image:

        for keyword, rule in POWERSHELL_RULES.items():

            if keyword in command:
                return rule

        return DETECTION_RULES["powershell.exe"]

    # =================================================
    # Windows Executable Detection
    # =================================================

    for keyword, rule in DETECTION_RULES.items():

        if keyword in image:
            return rule

    return detection
# ============================================================
# EVENT PROCESSOR
# ============================================================

def process_events(events):

    parsed_events = []

    statistics = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    print()
    print("=" * 75)
    print(Fore.CYAN + "        SPLUNK THREAT HUNTING AUTOMATION ENGINE")
    print("=" * 75)

    for event in events:

        detection = detect_event(event)

        parsed = {

            "Time": (
                event.get("Time")
                or event.get("_time")
                or "Unknown"
            ),

            "Host": (
                event.get("Host")
                or event.get("host")
                or "Unknown"
            ),

            "User": (
                event.get("User")
                or event.get("user")
                or "Unknown"
            ),

            "Image": (
                event.get("Image")
                or ""
            ),

            "Parent Image": (
                event.get("ParentImage")
                or event.get("Parent Image")
                or ""
            ),

            "Command Line": (
                event.get("CommandLine")
                or event.get("Command Line")
                or ""
            ),

            "Classification": detection["classification"],

            "Severity": detection["severity"],

            "MITRE ATT&CK": detection["mitre"]

        }

        parsed_events.append(parsed)

        severity = detection["severity"]

        if severity not in statistics:

            statistics[severity] = 0

        statistics[severity] += 1

        # ----------------------------------------------------
        # SOC ALERT ENGINE
        # ----------------------------------------------------

        print_alert(parsed)

    return parsed_events, statistics

# ============================================================
# REPORT WRITER
# ============================================================

def save_report(parsed_events):

    existing_events = []

    # --------------------------------------------------------
    # Load existing parsed events if they exist
    # --------------------------------------------------------

    if OUTPUT_FILE.exists():

        try:

            with open(
                OUTPUT_FILE,
                "r",
                encoding="utf-8"
            ) as infile:

                existing_events = json.load(infile)

                if not isinstance(existing_events, list):

                    existing_events = []

        except (
            json.JSONDecodeError,
            OSError
        ):

            existing_events = []


    # --------------------------------------------------------
    # Prevent duplicate events
    # --------------------------------------------------------

    combined_events = existing_events + parsed_events

    unique_events = []
    seen = set()

    for event in combined_events:

        # Build a stable identity for each event
        event_key = (
            event.get("Time"),
            event.get("Host"),
            event.get("User"),
            event.get("Image"),
            event.get("Parent Image"),
            event.get("Command Line"),
            event.get("Technique"),
            event.get("MITRE ATT&CK")
        )

        if event_key not in seen:
            seen.add(event_key)
            unique_events.append(event)

    combined_events = unique_events

    # --------------------------------------------------------
    # Save cumulative parsed dataset
    # --------------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as outfile:

        json.dump(
            combined_events,
            outfile,
            indent=4
        )

    print()
    print(Fore.GREEN + "[✓] JSON Report Saved")
    print(
        Fore.WHITE
        + f"Saved to: {OUTPUT_FILE.name}"
    )
    print(
        Fore.WHITE
        + f"Total Parsed Events: {len(combined_events)}"
    )


# ============================================================
# SUMMARY
# ============================================================

def print_summary(statistics, total_events):
    print()
    print("=" * 75)
    print(Fore.CYAN + "SUMMARY")
    print("=" * 75)

    print(Fore.MAGENTA + f"CRITICAL : {statistics.get('CRITICAL',0)}")
    print(Fore.RED + f"HIGH     : {statistics.get('HIGH',0)}")
    print(Fore.YELLOW + f"MEDIUM   : {statistics.get('MEDIUM',0)}")
    print(Fore.GREEN + f"LOW      : {statistics.get('LOW',0)}")

    print()

    print("=" * 75)
    print(Fore.CYAN + "Automation Complete")
    print("=" * 75)

    print()
    print(f"Events Processed : {total_events}")
    print(f"Output File      : {OUTPUT_FILE.name}")

    print()


# ============================================================
# MAIN PROGRAM
# ============================================================

def main():

    try:

        start_line = 0

        if "--start-line" in sys.argv:

            index = sys.argv.index("--start-line")

            if index + 1 < len(sys.argv):

                start_line = int(sys.argv[index + 1])


        events = load_events(start_line)

        parsed_events, statistics = process_events(events)

        save_report(parsed_events)

        generate_report(
            parsed_events,
            statistics
        )

        print_summary(
            statistics,
            len(parsed_events)
        )

    except FileNotFoundError:

        print()
        print(Fore.RED + "[ERROR] Input file not found.")
        print(Fore.YELLOW + f"Expected file: {INPUT_FILE}")
        print()

    except json.JSONDecodeError:

        print()
        print(Fore.RED + "[ERROR] Invalid JSON format.")
        print()

    except Exception as e:

        print()
        print(Fore.RED + "[UNEXPECTED ERROR]")
        print(Fore.RED + str(e))
        print()

        # ==========================================================
# PROGRAM ENTRY POINT
# ==========================================================

if __name__ == "__main__":
    main()