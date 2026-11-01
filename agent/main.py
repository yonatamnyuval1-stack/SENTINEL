import time
from datetime import datetime
from event import log_event
from honeyfiles import HoneyfileGuard
from persistence import PersistenceWatch
from process_watch import ProcessWatch
from network_watch import NetworkWatch
from control import bump_heartbeat, load_control
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
    on = {
        "honey": True,
        "persistence": True,
        "process": True,
        "network": True,
    }
    parts = {
        "honey": honey,
        "persistence": persist,
        "process": process,
        "network": network,
    }
    try:
        while True:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            bump_heartbeat()
            wanted = load_control()
            for name, watcher in parts.items():
                want = bool(wanted.get(name, True))
                if want and not on[name]:
                    watcher.setup()
                    on[name] = True
                    log_event("system", name + " started")
                elif (not want) and on[name]:
                    watcher.stop()
                    on[name] = False
                    log_event("system", name + " stopped")
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