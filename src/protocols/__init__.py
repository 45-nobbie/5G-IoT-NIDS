from scapy.all import bind_layers
from scapy.layers.inet import UDP
from .fg_nas import NAS

bind_layers(UDP, NAS, dport=5000)
__all__ = ["NAS"]