from abc import ABC, abstractmethod

from scapy.plist import PacketList

class Crack(ABC):
  packets: PacketList = []
  
  def __init__(self, name: str):
    print(f"[!] {name.upper()} STARTED ")
    self.packets = []

  @abstractmethod
  def identify(self): 
    """Method to defend the crack script"""
    pass
  
  def clear(self):
    self.packets = []
    
  def update(self, data: PacketList):
    self.packets = data