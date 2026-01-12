from collections import defaultdict, deque
from time import time
from scapy.layers.l2 import ARP
from cracks.base import Crack

class ARPSpoofCrack(Crack):
    WINDOW = 10
    MIN_REPLIES = 5

    def __init__(self):
        super().__init__("ARP Spoof")

        self.state = defaultdict(lambda: {
            "replies": deque(),
            "alerted": False
        })

    def on_packet(self, pkt, context):
        if not pkt.haslayer(ARP):
            return []

        arp = pkt[ARP]
        if arp.op != 2:  # Only check ARP replies (is-at)
            return []

        now = time()
        attacker_mac = arp.hwsrc
        claimed_ip = arp.psrc

        entry = self.state[attacker_mac]
        entry["replies"].append((now, claimed_ip))

        while entry["replies"] and now - entry["replies"][0][0] > self.WINDOW:
            entry["replies"].popleft()

        if len(entry["replies"]) >= self.MIN_REPLIES and not entry["alerted"]:
            entry["alerted"] = True
            context.arp_mitm_macs.add(attacker_mac)

            return [(
                "ARP Spoofing",
                attacker_mac,
                f"MAC {attacker_mac} impersonating {claimed_ip}"
            )]

        return []
