import sys
import time
import subprocess
from pathlib import Path


# ============================================================
# WAZUH THREAT HUNTING LIVE MONITOR
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

WATCH_FILE = BASE_DIR / "datasets" / "recon_events.json"

print("=" * 70)
print(" WAZUH THREAT HUNTING LIVE MONITOR ")
print("=" * 70)
print()

print(f"Monitoring: {WATCH_FILE}")
print()


# ============================================================
# WAIT FOR TELEMETRY FILE
# ============================================================

while not WATCH_FILE.exists():

    print("[!] Waiting for recon_events.json...")

    time.sleep(2)


# ============================================================
# INITIAL EVENT COUNT
# ============================================================

def get_event_count():

    try:

        with open(WATCH_FILE, "r", encoding="utf-8") as file:

            return sum(
                1
                for line in file
                if line.strip()
            )

    except Exception:

        return 0


processed_count = get_event_count()


print(f"[+] Existing telemetry: {processed_count} events")
print("[+] Monitor started.")
print("[+] Waiting for new telemetry...")
print()


# ============================================================
# LIVE MONITOR
# ============================================================

while True:

    try:

        current_count = get_event_count()


        # ----------------------------------------------------
        # NEW TELEMETRY DETECTED
        # ----------------------------------------------------

        if current_count > processed_count:

            new_events = current_count - processed_count

            print("=" * 70)
            print("[+] NEW TELEMETRY DETECTED")
            print(time.strftime("%Y-%m-%d %H:%M:%S"))
            print("=" * 70)

            print()
            print(f"[+] Previous events : {processed_count}")
            print(f"[+] Current events  : {current_count}")
            print(f"[+] New events      : {new_events}")
            print()

            print("[+] Launching Threat Hunting Engine...")
            print()

            # ------------------------------------------------
            # Process ONLY new events
            # ------------------------------------------------

            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "automation.detection.parser",
                    "--start-line",
                    str(processed_count)
                ],
                check=False
            )

            # ------------------------------------------------
            # Mark events as processed
            # ------------------------------------------------

            processed_count = current_count

            print()
            print("[+] New telemetry processed.")
            print(f"[+] Total events processed: {processed_count}")
            print("[+] Waiting for new telemetry...")
            print()


        # ----------------------------------------------------
        # FILE RESET
        # ----------------------------------------------------

        elif current_count < processed_count:

            print()
            print("[!] Telemetry file was reset.")
            print("[+] Resetting monitor position...")
            print()

            processed_count = current_count


        time.sleep(1)


    except KeyboardInterrupt:

        print()
        print("=" * 70)
        print(" SPLUNK THREAT HUNTING LIVE MONITOR STOPPED ")
        print("=" * 70)
        print()

        break


    except Exception as e:

        print()
        print("[WATCHER ERROR]")
        print(str(e))
        print()

        time.sleep(2)