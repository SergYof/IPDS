from base import Crack
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP
import dns.resolver  # Import the DNS resolver library (dnspython)


class DNSSpoofCrack(Crack):
    def __init__(self):
        super().__init__("DNS Spoofing")

        # Configure a resolver to use a Trusted DNS Server (e.g., Google 8.8.8.8)
        # This bypasses your local network's potentially poisoned DNS cache.
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']

    def identify(self, packetChunk):
        
        alerts: list[tuple[str, str, str]] = []
        for packet in packetChunk:
            # Check for UDP port 53
            if not packet.haslayer(UDP) or packet[UDP].dport != 53:
                continue

            # Check if it is a DNS Response (qr == 1)
            if packet.haslayer(DNS) and packet[DNS].qr == 1:
                dns_layer = packet[DNS]

                for i in range(dns_layer.ancount):
                    ans = dns_layer.an[i]

                    # Type 1 is an 'A' record (IPv4)
                    if ans.type == 1:
                        domain = ans.rrname.decode().rstrip('.')
                        captured_ip = ans.rdata

                        # Perform the dynamic check
                        valid, msg = self.verify_dynamic(domain, captured_ip)
                        if valid:
                            continue
                        if msg.find("Error") == -1: # that's not an error
                            alerts.append(("DNS", msg, "HIGH"))
                        else:
                            alerts.append(("DNS", msg, "LOW"))
        
        return alerts


    def verify_dynamic(self, domain, captured_ip):
        """
        Queries a trusted DNS server for the domain and compares the result
        with the captured packet's IP.
        """
        try:
            # Query the trusted nameserver for the real IPs
            answers = self.resolver.resolve(domain, 'A')
            trusted_ips = [r.to_text() for r in answers]

            # Check if the captured IP exists in the list of trusted IPs
            if captured_ip not in trusted_ips:
                return False, f"[!] POTENTIAL SPOOF: {domain}\n\tPacket IP: {captured_ip}\n\tTrusted IPs: {", ".join(trusted_ips)}"
            
            return True, ""

        except dns.resolver.NXDOMAIN:
            print(f"[!] Domain does not exist (NXDOMAIN): {domain}")
        except dns.resolver.Timeout:
            print(f"[?] Timeout verifying {domain}")
        except Exception as e:
            print(f"[?] Error verifying {domain}: {e}")
        
        return False, f"Error validating {domain} - given {captured_ip}" # if there's an error validating