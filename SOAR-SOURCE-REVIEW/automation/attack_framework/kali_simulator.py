import subprocess
import random
import time
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

TARGET = "192.168.56.1"

print()
print("=" * 80)
print(Fore.RED + " KALI RECONNAISSANCE ATTACK SIMULATOR")
print("=" * 80)

start = datetime.now()

commands = [

    {
        "phase": "Host Discovery",
        "technique": "Active Scanning",
        "mitre": "T1595",
        "severity": "LOW",
        "command": f"ping -c 4 {TARGET}"
    },

]

success = 0
failed = 0

for step, attack in enumerate(commands, start=1):

    print()
    print(Fore.YELLOW + "-" * 80)
    print(Fore.CYAN + f"PHASE {step}")
    print("-" * 80)

    print(f"Technique : {attack['technique']}")
    print(f"Severity  : {attack['severity']}")
    print(f"MITRE     : {attack['mitre']}")
    print(f"Command   : {attack['command']}")
    print()

    try:

        subprocess.run(
            attack["command"],
            shell=True,
            check=True
        )

        success += 1

        print(Fore.GREEN + "[✓] Phase Completed")

    except subprocess.CalledProcessError:

        failed += 1

        print(Fore.RED + "[X] Phase Failed")

    delay = round(random.uniform(2,4),2)

    print()
    print(f"Sleeping {delay} seconds...")
    time.sleep(delay)

print()
print(Fore.CYAN + "=" * 80)
print(" ATTACK SUMMARY")
print("=" * 80)

print()
print(f"Started : {start}")
print(f"Finished: {datetime.now()}")

print()
print(Fore.GREEN + f"Successful : {success}")
print(Fore.RED + f"Failed     : {failed}")
print(Fore.YELLOW + f"Executed   : {len(commands)}")

print()
print(Fore.CYAN + "=" * 80)
print(" Reconnaissance Complete")
print("=" * 80)