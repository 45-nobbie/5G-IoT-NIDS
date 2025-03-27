from capture.scapy_capture import ScapyCapture
from protocols import NAS
from rule_engine import RuleEngine

def main():
    # Initialize components
    capture = ScapyCapture(interface="lo", port=5000)  # Use loopback for testing
    engine = RuleEngine()
    
    # Start capture
    print("🚀 Starting 5G-IoT NIDS (Scapy)...")
    def debug_process(pkt):
        print(f"📦 Received packet: {pkt.summary()}")
        engine.process_packet(pkt)

    capture.start(debug_process)
    capture.start(engine.process_packet)

if __name__ == "__main__":
    main()