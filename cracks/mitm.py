from .base import Crack
from scapy.layers.l2 import ARP
from scapy.plist import PacketList


class MITMCrack(Crack):    
    arp_table = {}
    
    def __init__(self):
        super().__init__("MITM")

    def identify(self, packetChunk: PacketList):

        alerts: list[tuple[str, str, str]] = []
        for packet in packetChunk:
            if not (packet.haslayer(ARP) and packet[ARP].op == 2):
                continue
            
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc

            if ip in self.arp_table and self.arp_table[ip] != mac:
                alerts.append(("MITM", f"Suspicious ARP response - MAC mismatch! {ip} was {self.arp_table[ip]}, but in the response is {mac}", "HIGH"))
            else:
                self.arp_table[ip] = mac
        
        return alerts