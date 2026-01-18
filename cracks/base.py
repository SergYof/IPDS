# cracks/base.py
class Crack:
    def __init__(self, name):
        print(f"[!] {name.upper()} STARTED")
        self.name = name

    def on_packet(self, pkt, context):
        return []