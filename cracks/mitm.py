from .base import Crack
from scapy.layers.l2 import ARP

class MITMCrack(Crack):    
    def __init__(self):
        super().__init__("MITM")

    def identify(self):
        arp_table = {}

        for packet in self.packets:
            if not (packet.haslayer(ARP) and packet[ARP].op == 2):
                break
            
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc

            if ip in arp_table and arp_table[ip] != mac:
                print("MITM DETECTED")
                print(ip, arp_table[ip], mac)
            else:
                arp_table[ip] = mac
