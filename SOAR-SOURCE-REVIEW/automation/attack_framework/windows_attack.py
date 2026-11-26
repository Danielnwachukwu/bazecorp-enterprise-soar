import subprocess
import random
import time
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

print(Fore.RED + "=" * 80)
print(" WINDOWS RECONNAISSANCE ATTACK SIMULATOR")
print("=" * 80)

commands = [

    ("Current User", "whoami", "Account Discovery"),

    ("Hostname", "hostname", "System Discovery"),

    ("IP Configuration", "ipconfig /all", "Network Discovery"),

    ("System Information", "systeminfo", "System Discovery"),

    ("Running Processes", "tasklist", "Process Discovery"),

    ("User Accounts", "net user", "Account Discovery"),

    ("Network Sessions", "net session", "Network Discovery"),

    ("ARP Cache", "arp -a", "Network Discovery"),

    ("Routing Table", "route print", "Network Discovery"),

    ("Network Connections", "netstat -ano", "Network Discovery")

]

random.shuffle(commands)

success = 0
failed = 0

start = datetime.now()

print()
print(Fore.CYAN + f"Attack Started : {start}")
print()

for number, (title, command, phase) in enumerate(commands, start=1):

    print(Fore.YELLOW + "-" * 80)
    print(f"STEP {number}")
    print("-" * 80)

    print(f"Attack Phase : {phase}")
    print(f"Activity     : {title}")
    print(f"Command      : {command}")

    try:

        subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )

        success += 1

        print(Fore.GREEN + "\n[✓] Command Executed Successfully")

    except Exception as e:

        failed += 1

        print(Fore.RED + str(e))

    delay = round(random.uniform(1.5,5.5),2)

    print(Fore.MAGENTA)
    print(f"Sleeping for {delay} seconds...\n")

    time.sleep(delay)

finish = datetime.now()

print()
print(Fore.CYAN + "=" * 80)
print(" ATTACK SUMMARY")
print("=" * 80)

print()

print(f"Attack Started : {start}")
print(f"Attack Ended   : {finish}")

print()

print(Fore.GREEN + f"Successful Commands : {success}")

print(Fore.RED + f"Failed Commands     : {failed}")

print(Fore.YELLOW + f"Total Commands      : {len(commands)}")

print()

print(Fore.CYAN + "=" * 80)
print(" Reconnaissance Simulation Complete")
print("=" * 80)