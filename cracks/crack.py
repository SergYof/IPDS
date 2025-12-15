from abc import ABC, abstractmethod

class Crack(ABC):
  @abstractmethod
  def attack(): 
    """Method to attack the crack script"""
    pass

  @abstractmethod
  def defend(): 
    """Method to defent the crack script"""
    pass