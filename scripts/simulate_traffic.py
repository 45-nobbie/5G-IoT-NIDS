from scapy.all import IP, UDP, send
import sys

sys.path.append("../src")


from src.protocols import NAS
import time

devices = [
    {"id": "Legit_Device", "delay": 1.0},  # 1 req/sec
    {"id": "Attacker", "delay": 0.05}      # 20 req/sec
]

print("📡 Simulating 5G traffic...")
try:
    while True:
        for device in devices:
            pkt = IP(dst="127.0.0.1")/UDP(dport=5000)/NAS(device_id=device["id"])
            send(pkt, verbose=0)
            time.sleep(device["delay"])
except KeyboardInterrupt:
    print("\nTraffic stopped.")