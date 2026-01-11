from scapy.sendrecv import sniff
from time import time

from engine.flow_manager import FlowManager
from bus.alert_bus import ALERT_BUS
from bus.packet_bus import PACKET_BUS
from utils.geoip import lookup
from context import Context  # Add this

class Manager:
    def __init__(self, cracks):
        self.cracks = cracks
        self.flow_mgr = FlowManager()
        self.context = Context()  # Shared context

    def process_packet(self, pkt):
        flow = self.flow_mgr.get_flow(pkt)
        suspicious = False

        for crack in self.cracks:
            alerts = crack.on_packet(pkt, self.context if "ARP" in crack.name or "Port" in crack.name else flow)
            # Use context for ARP/PortScan, flow for DNS
            for alert in alerts:
                suspicious = True
                self._publish_alert(crack, alert)

        PACKET_BUS.publish(pkt, suspicious=suspicious)
        self.flow_mgr.expire_flows()

    def _publish_alert(self, crack, alert):
        attack, attacker, details = alert

        ALERT_BUS.publish({
            "attack": attack,
            "time": time(),
            "attacker": attacker,
            "victim": "N/A",
            "geo": lookup(attacker) if hasattr(crack, 'name') and 'ARP' not in crack.name else "Local MAC",
            "details": details
        })

    def start(self):
        sniff(
            prn=self.process_packet,
            store=False,
            promisc=True
        )