from manager import Manager
from cracks.portscan import PortScanCrack
from cracks.arpspoof import ARPSpoofCrack
from cracks.dnsspoof import DNSSpoofCrack
from gui import start_gui
from threading import Thread


def main():
    cracks = [
        PortScanCrack(),
        ARPSpoofCrack(),
        DNSSpoofCrack()
    ]

    manager = Manager(cracks)
    manager_thread = Thread(target=manager.start, daemon=True)
    manager_thread.start()

    start_gui()

if __name__ == "__main__":
    main()
