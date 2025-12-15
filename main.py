from .manager import Manager
from .cracks.Port_Scanning.portscan import PortScanCrack

manager = Manager()

portscanning = PortScanCrack()

manager.run(portscanning)