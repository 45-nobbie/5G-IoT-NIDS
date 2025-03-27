from scapy.all import sniff, Ether
from scapy.layers.inet import UDP

class ScapyCapture:
    def __init__(self, interface="eth0", port=5000):
        self.interface = interface
        self.port = port
        self.filter = f"udp port {self.port}"
        
    def start(self, callback):
        """Start capturing and pass packets to callback."""
        sniff(iface=self.interface, filter=self.filter, 
              prn=lambda pkt: callback(pkt), store=False)