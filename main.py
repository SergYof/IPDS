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

    gui_thread = Thread(target=start_gui, daemon=True)
    gui_thread.start()

    Manager(cracks).start()

if __name__ == "__main__":
    main()
