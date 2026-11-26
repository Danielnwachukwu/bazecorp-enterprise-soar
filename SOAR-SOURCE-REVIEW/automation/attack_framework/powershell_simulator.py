import subprocess
import random
import time
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

print(Fore.RED + "=" * 80)
print(" POWERSHELL ATTACK SIMULATOR")
print("=" * 80)

commands = [

    (
        "Privilege Enumeration",
        'powershell -Command "whoami /priv"',
        "Privilege Discovery",
        "LOW",
        "T1069"
    ),

    (
        "Group Enumeration",
        'powershell -Command "whoami /groups"',
        "Account Discovery",
        "LOW",
        "T1069"
    ),

    (
        "Process Enumeration",
        'powershell -Command "Get-Process"',
        "Process Discovery",
        "MEDIUM",
        "T1057"
    ),

    (
        "Service Enumeration",
        'powershell -Command "Get-Service"',
        "Service Discovery",
        "MEDIUM",
        "T1007"
    ),

    (
        "Network Configuration",
        'powershell -Command "ipconfig /all"',
        "Network Discovery",
        "MEDIUM",
        "T1016"
    ),

    (
        "System Information",
        'powershell -Command "systeminfo"',
        "System Discovery",
        "MEDIUM",
        "T1082"
    )

]

random.shuffle(commands)

success = 0
failed = 0

start = datetime.now()

print(Fore.CYAN)
print(f"Attack Started : {start}")
print()

for number, (title, command, tactic, severity, mitre) in enumerate(commands, start=1):

    print(Fore.YELLOW + "-" * 80)
    print(f"STEP {number}")
    print("-" * 80)

    print(f"Technique : {title}")
    print(f"Tactic    : {tactic}")
    print(f"Severity  : {severity}")
    print(f"MITRE     : {mitre}")
    print(f"Command   : {command}")

    try:

        subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )

        success += 1
        print(Fore.GREEN + "\n[✓] Simulation Complete")

    except Exception as e:

        failed += 1
        print(Fore.RED + str(e))

    delay = round(random.uniform(2, 5), 2)

    print(Fore.MAGENTA)
    print(f"\nSleeping {delay} seconds...\n")

    time.sleep(delay)

print(Fore.CYAN + "=" * 80)
print(" POWERSHELL SIMULATION SUMMARY")
print("=" * 80)

print()
print(f"Started : {start}")
print(f"Ended   : {datetime.now()}")
print()

print(Fore.GREEN + f"Successful : {success}")
print(Fore.RED + f"Failed     : {failed}")
print(Fore.YELLOW + f"Executed   : {len(commands)}")

print()
print(Fore.CYAN + "=" * 80)
print(" Simulation Complete")
print("=" * 80)