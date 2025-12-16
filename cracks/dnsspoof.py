from .base import Crack
from scapy.all import DNS, UDP

class DNSSpoofCrack(Crack):
  
  trustedDomains = {
    "google.com": "216.239.38.120", "facebook.com": "157.240.196.35", "ihasabucket.com": "75.119.206.170"}

  def __init__(self):
      super().__init__("DNS Spoofing")

      
  def identify(self):    
    for packet in self.packets:
      if not (packet.haslayer(UDP) or packet[UDP].dport != 53):
        pass
      
      if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 1:
        dns_layer = packet.getlayer(DNS)

      for i in range(dns_layer.ancount):
        ans = dns_layer.an[i]
        if ans.type == 1:
          domain = ans.rrname.decode().rstrip('.')
          ip_address = ans.rdata

          if domain in self.trustedDomains:
            trusted = self.trustedDomains[domain]
            if ip_address != trusted:
              print("[!] DNS Spoofing detected for domain:", domain, "with IP:", ip_address)
          else:
            print("[!] DNS response for unknown domain:", domain, "with IP:", ip_address)