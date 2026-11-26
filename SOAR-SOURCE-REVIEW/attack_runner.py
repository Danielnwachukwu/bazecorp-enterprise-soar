import subprocess
import sys
import time
from pathlib import Path
from colorama import Fore, init

init(autoreset=True)

ROOT = Path(__file__).parent
PYTHON = sys.executable

print("=" * 90)
print(Fore.CYAN + "          SPLUNK ATTACK AUTOMATION FRAMEWORK")
print("=" * 90)
print()

# ----------------------------------------------------
# Start Watcher
# ----------------------------------------------------

watcher = ROOT / "automation" / "watcher.py"

watcher_process = None

if watcher.exists():
    print(Fore.GREEN + "[+] Starting Threat Hunting Watcher...\n")

    watcher_process = subprocess.Popen(
        [PYTHON, str(watcher)]
    )

    time.sleep(2)

else:
    print(Fore.YELLOW + "[!] watcher.py not found. Continuing without live monitoring.\n")

# ----------------------------------------------------
# Attack Modules
# ----------------------------------------------------

attacks = [

   (
    "Windows PowerShell Recon",
    ROOT / "automation" / "attack_framework" / "powershell_simulator.py"
),
    (
        "Windows LOLBin Attack",
        ROOT / "automation" / "attack_framework" / "lolbin_simulator.py"
    ),

    (
        "Kali Reconnaissance",
        ROOT / "automation" / "attack_framework" / "kali_simulator.py"
    )

]

results = []

for attack_name, script in attacks:

    print(Fore.YELLOW + "-" * 90)
    print(Fore.CYAN + attack_name)
    print("-" * 90)

    if not script.exists():

        print(Fore.RED + f"[X] Script not found:\n{script}\n")
        results.append((attack_name, "Missing"))
        continue

    print(Fore.GREEN + "[+] Launching...\n")

    try:

        completed = subprocess.run(
            [PYTHON, str(script)],
            check=False
        )

        if completed.returncode == 0:
            results.append((attack_name, "Success"))
        else:
            results.append((attack_name, f"Exit Code {completed.returncode}"))

    except Exception as e:

        print(Fore.RED + str(e))
        results.append((attack_name, "Failed"))

    print()
    print(Fore.GREEN + "[✓] Finished\n")

    time.sleep(3)

# ----------------------------------------------------
# Summary
# ----------------------------------------------------

print("=" * 90)
print(Fore.CYAN + "EXECUTION SUMMARY")
print("=" * 90)

for name, status in results:

    colour = Fore.GREEN if status == "Success" else Fore.RED
    print(colour + f"{name:<35} : {status}")

print()
print(Fore.GREEN + "ALL ATTACKS COMPLETED")
print("=" * 90)