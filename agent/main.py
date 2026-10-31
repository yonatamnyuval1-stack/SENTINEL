import time
from datetime import datetime
from event import log_event
from honeyfiles import HoneyfileGuard
from persistence import PersistenceWatch
from process_watch import ProcessWatch
from network_watch import NetworkWatch
def main():
    print("SENTINEL starting...")
    print("Press Ctrl+C to stop.\n")
    log_event("system", "SENTINEL started")
    honey = HoneyfileGuard()
    honey.setup()
    persist = PersistenceWatch()
    persist.setup()
    process = ProcessWatch()
    process.setup()
    network = NetworkWatch()
    network.setup()
    try:
        while True:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{now}] SENTINEL is running")
            time.sleep(3)
    except KeyboardInterrupt:
        network.stop()
        process.stop()
        persist.stop()
        honey.stop()
        log_event("system", "SENTINEL stopped by user")
        print("\nSENTINEL stopped.")
if __name__ == "__main__":
    main()