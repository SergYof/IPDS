from typing import List
from cracks.base import Crack
from scapy.plist import PacketList
from scapy.sendrecv import sniff
from threading import Thread

ATTACK_CHECK_INTERVAL = 5   # how frequently the chunks are scanned  

class Manager:
    def runOnce(self, crack: Crack, packetChunk: PacketList):   # check one packet chunk for one crack type
        crack.identify(packetList)  # TODO: take action if detected

    def start(self, cracks: List[Crack]):
        # keep running
        while True:
            print("Sniffing packets")
            packetLst = sniff(timeout=ATTACK_CHECK_INTERVAL, quiet=True)    # sniff for some time

            for crack in cracks:
                # TODO: use threads
                t = Thread(target=self.runOnce, args=(crack, packetLst))
                t.run()