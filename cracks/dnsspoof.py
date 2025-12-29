from base import Crack
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP


class DNSSpoofCrack(Crack):
    # 1. Cleaned up dictionary formatting
    trusted_domains = {
        "google.com": "216.239.38.120",
        "facebook.com": "157.240.196.35",
        "ihasabucket.com": "75.119.206.170"
    }

    def __init__(self):
        super().__init__("DNS Spoofing")

    def identify(self):
        for packet in self.packets:
            # 2. Simplified logic: Check if it is UDP port 53 (DNS)
            if not packet.haslayer(UDP) or packet[UDP].dport != 53:
                continue  # Skip if not DNS

            # 3. Check if it is a DNS Response (qr == 1)
            if packet.haslayer(DNS) and packet[DNS].qr == 1:
                dns_layer = packet[DNS]

                # 4. Fixed indentation: This loop must be inside the if block
                for i in range(dns_layer.ancount):
                    ans = dns_layer.an[i]

                    # Type 1 is an 'A' record (IPv4)
                    if ans.type == 1:
                        # Decode bytes and strip trailing dot
                        domain = ans.rrname.decode().rstrip('.')
                        ip_address = ans.rdata

                        if domain in self.trusted_domains:
                            trusted_ip = self.trusted_domains[domain]

                            if ip_address != trusted_ip:
                                print(
                                    f"[!] DNS Spoofing detected for domain: {domain} | Expected: {trusted_ip} | Got: {ip_address}")
                        else:
                            print(f"[!] DNS response for unknown domain: {domain} | IP: {ip_address}")