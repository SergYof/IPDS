import time
from cracks.base import Crack
from scapy.all import sniff

class Manager:
  def one(self, crack: Crack):
    return crack.identify()
  
  def pipe(self, cracks: list[Crack]):
    cracks[0].update(sniff(count=1000, timeout=1))
    
    for crack in cracks:
      try:
        crack.identify()
      except Exception as e:
        print(f"Error in {crack.__class__.__name__}: {e}")
        
    cracks[0].clear()
      
  def persistent(self, intervalSeconds: int, cracks: list[Crack]):
    print("---------\n")
    while True:
      self.pipe(cracks)
      time.sleep(intervalSeconds)
  