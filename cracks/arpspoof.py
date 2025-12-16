from scapy.layers.l2 import ARP
from .base import Crack

class ARPSpoofCrack(Crack):
    def __init__(self):
        super().__init__("ARP Spoofing")
        self.ip_mac_table = {}

    def identify(self):        
        for packet in self.packets:
            if not packet.haslayer(ARP):
                pass
            
            arp = packet[ARP]

            if arp.op == 2:  
                ip = arp.psrc
                mac = arp.hwsrc

                if ip in self.ip_mac_table:
                    if self.ip_mac_table[ip] != mac:
                        print(f"[!] ARP Spoofing detected!")
                        print(f"    IP {ip} changed from {self.ip_mac_table[ip]} to {mac}")
                else:
                    self.ip_mac_table[ip] = mac