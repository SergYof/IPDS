from collections import defaultdict
import time
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from cracks.base import Crack

class DNSSpoofCrack(Crack):
    TTL = 10

    def __init__(self):
        super().__init__("DNS Spoofing")
        self.requests = {}
        self.responders = defaultdict(set)

    def on_packet(self, pkt, context):
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
            return []

        dns = pkt[DNS]
        if dns.id == 0:
            return []

        alerts = []
        now = time.time()

        self._cleanup(now)

        if dns.qr == 0:
            qname = dns.qd.qname if dns.qd else None
            self.requests[(pkt[IP].src, dns.id, qname)] = now

        else:
            client = pkt[IP].dst
            server = pkt[IP].src
            qname = dns.qd.qname if dns.qd else None
            key = (client, dns.id, qname)

            if key in self.requests:
                responders = self.responders[key]
                responders.add(server)

                if len(responders) >= 2:
                    alerts.append((
                        "DNS Spoofing",
                        server,
                        f"Multiple DNS responders for {qname}"
                    ))

        return alerts

    def _cleanup(self, now):
        self.requests = {k: t for k, t in self.requests.items() if now - t <= self.TTL}
        self.responders = {k: v for k, v in self.responders.items() if k in self.requests}