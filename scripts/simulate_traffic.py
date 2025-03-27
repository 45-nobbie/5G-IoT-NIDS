from scapy.all import *
from scapy.layers.inet import UDP, IP
import time
import random

class NAS(Packet):
    name = "5G_NAS"
    fields_desc = [
        ByteEnumField("message_type", 0x41, {0x41: "Registration Request"}),
        StrFixedLenField("device_id", "", 12)
    ]

devices = [
    {"id": "Legit_Device", "delay": 1.0},
    {"id": "Attacker", "delay": 0.05}  # 20 requests/sec
]

print("📡 Generating 5G traffic...")
try:
    while True:
        for device in devices:
            pkt = IP(dst="127.0.0.1")/UDP(dport=5000)/NAS(device_id=device["id"])
            send(pkt, verbose=0)
            time.sleep(device["delay"])
except KeyboardInterrupt:
    print("\nTraffic generation stopped.")