from cracks.arpspoof import ARPSpoofCrack
from cracks.mitm import MITMCrack
from cracks.portscan import PortScanCrack
from cracks.dnsspoof import DNSSpoofCrack
from manager import Manager
manager = Manager()
def main() -> None:
    manager = Manager()
    manager.start([
            PortScanCrack(),
            DNSSpoofCrack(),
            ARPSpoofCrack(),
            MITMCrack(),
        ])
    

if __name__ == "__main__":
    main()