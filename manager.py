from cracks.crack import Crack

class Manager:
  def run(crack: Crack):
    crack.attack()
    crack.defend()