from abc import ABC, abstractmethod


class Crack(ABC):
  def __init__(self, name: str):
    print(f"[!] {name.upper()} STARTED ")


  @abstractmethod
  def identify(self): 
    """Method to defend the crack script"""
    pass