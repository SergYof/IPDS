from typing import List
from cracks.base import Crack
from scapy.plist import PacketList
from scapy.sendrecv import sniff
from threading import Thread

ATTACK_CHECK_INTERVAL = 5   # how frequently the chunks are scanned  

class Manager:
    def runOnce(self, crack: Crack, packetChunk: PacketList):   # check one packet chunk for one crack type
        crack.identify(packetChunk)  # TODO: take action if detected


    def start(self, cracks: List[Crack]):
        # keep running
        while True:
            print("Sniffing packets")
            packetLst = sniff(timeout=ATTACK_CHECK_INTERVAL, quiet=True)    # sniff for some time
            
            threadList: list[Thread] = []
            for crack in cracks:    # launch parallel crack checking
                threadList.append(Thread(target=self.runOnce, args=(crack, packetLst)))
                threadList[-1].run()
            
            for t in threadList:    # stop the checks
                t.join()
            
            # the results must be outputted by the functions
            # there must be calls to add_alert() function from GUI