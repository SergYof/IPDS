from .base import Crack
from scapy.all import TCP, UDP, IP

class PortScanCrack(Crack):
  def __init__(self):
    super().__init__("Port Scanning")

  def identify(self):
    portMap = {}

    for packet in self.packets:
        if not packet.haslayer(IP):
            continue

        src_ip = packet[IP].src

        isTCP = packet.haslayer(TCP)
        isUDP = packet.haslayer(UDP)

        if not (isTCP or isUDP):
            continue

        if src_ip not in portMap:
            portMap[src_ip] = {}

        port = packet[TCP].dport if isTCP else packet[UDP].dport
        portMap[src_ip][port] = True

    results = sorted([k for k, v in portMap.items() if len(v) >= 2000])
    
    if len(results) >= 1:
      print(f"Found {len(results)} suspicious dicks")