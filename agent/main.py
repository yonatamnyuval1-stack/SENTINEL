import time
from datetime import datetime
from event import log_event
from honeyfiles import HoneyfileGuard

def main():
    print("SENTINEL starting...")
    print("Press Ctrl+C to stop.\n")
    log_event("system", "SENTINEL started")
    honey = HoneyfileGuard()
    honey.setup()
    try:
        while True:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{now}] SENTINEL is running")
            time.sleep(3)
    except KeyboardInterrupt:
        honey.stop()
        log_event("system", "SENTINEL stopped by user")
        print("\nSENTINEL stopped.")
if __name__ == "__main__":
    main()