from scapy.all import *
from scapy.layers.inet import UDP
from collections import defaultdict
import time
import os

# Custom 5G NAS layer
class NAS(Packet):
    name = "5G_NAS"
    fields_desc = [
        ByteEnumField("message_type", 0, {
            0x41: "Registration Request",
            0x42: "Authentication Request"
        }),
        StrFixedLenField("device_id", "", 12)
    ]

# Bind to UDP port 5000
bind_layers(UDP, NAS, dport=5000)

# Detection engine
request_counts = defaultdict(int)
last_reset = time.time()
alert_threshold = 10  # 10 requests per second

def detect_attack(pkt):
    global last_reset
    
    # Reset counters every second
    if time.time() - last_reset > 1:
        request_counts.clear()
        last_reset = time.time()
    
    if NAS in pkt and pkt[NAS].message_type == 0x41:
        device_id = pkt[NAS].device_id.decode().strip('\x00')
        request_counts[device_id] += 1
        
        if request_counts[device_id] > alert_threshold:
            print(f"\n🚨 ALERT: Attack detected from {device_id} ({request_counts[device_id]} req/sec)!")
            
def monitor():
    print("🔍 Monitoring 5G traffic on port 5000...")
    print("Device ID         | Requests/sec")
    print("-------------------------------")
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        for device_id, count in request_counts.items():
            print(f"{device_id:<17} | {count}")
        time.sleep(0.2)

if __name__ == "__main__":
    import threading
    threading.Thread(target=monitor, daemon=True).start()
    sniff(prn=detect_attack, filter="udp port 5000", store=0)