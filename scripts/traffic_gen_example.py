#!/usr/bin/env python3

# scripts/traffic_gen_example.py
# Example script for generating test traffic using Scapy.
# Based on report sections 4.1 and 4.3

import sys
import argparse
import logging
from scapy.all import sendp, Ether, IP, UDP, TCP, Raw # Base layers
from scapy.layers.inet import IP # Import IP layer specifically if needed

# --- IMPORTANT ---
# You need to import your custom protocol layers from src/protocols/
# after adding src to the Python path or installing the project.
# Example:
# Assuming your project root is in PYTHONPATH
# from src.protocols.nas import NASLayer, NAS_MESSAGE_TYPES # Example NAS import
# from src.protocols.coap import CoAP, COAP_TYPES, COAP_CODES # Example CoAP import
# from src.protocols.mqtt import MQTT, MQTT_TYPES # Example MQTT import

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("TrafficGen")

def send_malformed_nas(iface, dst_ip, dst_mac):
    """ Sends a potentially malformed NAS message (Example) """
    logger.info("Sending example malformed NAS packet...")
    # This requires the NASLayer definition from src/protocols/nas.py
    # Crafting meaningful malformed packets requires understanding the protocol spec.
    try:
        from src.protocols.nas import NASLayer # Try importing custom layer
        # Example: Sending a RegistrationRequest with potentially invalid fields
        # NOTE: This NASLayer structure is a simplified placeholder!
        malformed_nas = NASLayer(security_header_type=0, message_type=0x41) # 0x41 = RegistrationRequest
        # TODO: Add invalid Information Elements or lengths based on TS 24.501

        # Encapsulate (Example: NAS directly over IP/UDP for testing, adjust as needed)
        # Real NAS is often inside NGAP over SCTP, or directly protected.
        packet = Ether(dst=dst_mac)/IP(dst=dst_ip)/UDP(dport=7777, sport=7777)/malformed_nas

        sendp(packet, iface=iface, verbose=0)
        logger.info("Malformed NAS packet sent.")
    except ImportError:
        logger.error("Could not import NASLayer from src.protocols.nas. Ensure it's defined and PYTHONPATH is set.")
    except Exception as e:
        logger.error(f"Error crafting/sending malformed NAS: {e}")


def send_coap_flood(iface, dst_ip, dst_mac, count=10):
    """ Sends a flood of CoAP GET requests (Example DoS) """
    logger.info(f"Sending CoAP GET flood ({count} packets)...")
    try:
        from src.protocols.coap import CoAP # Try importing custom layer

        # Example CoAP GET request
        coap_get = CoAP(type=0, code=1, msg_id=12345) # CON, GET
        # TODO: Add Uri-Path option to target a resource

        packet = Ether(dst=dst_mac)/IP(dst=dst_ip)/UDP(dport=5683, sport=12345)/coap_get

        for i in range(count):
            # Vary message ID slightly if needed
            packet[CoAP].msg_id = 10000 + i
            sendp(packet, iface=iface, verbose=0)
            # time.sleep(0.01) # Optional small delay

        logger.info("CoAP flood sent.")
    except ImportError:
        logger.error("Could not import CoAP layer from src.protocols.coap. Ensure it's defined and PYTHONPATH is set.")
    except Exception as e:
        logger.error(f"Error crafting/sending CoAP flood: {e}")


def main():
    parser = argparse.ArgumentParser(description="5G Shield Traffic Generation Script")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to send packets from")
    parser.add_argument("--dst-ip", required=True, help="Destination IP address")
    parser.add_argument("--dst-mac", required=True, help="Destination MAC address (use 'ff:ff:ff:ff:ff:ff' for broadcast if IP is local broadcast)")
    parser.add_argument("--scenario", required=True, choices=["malformed-nas", "coap-flood"], help="Traffic scenario to generate")
    parser.add_argument("--count", type=int, default=10, help="Number of packets to send for flood scenarios")

    args = parser.parse_args()

    # Add project source to Python path to allow importing protocol layers
    # This is a common way for scripts outside the main package
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    logger.info(f"Added {project_root} to PYTHONPATH")
    # Now imports like 'from src.protocols.nas import NASLayer' should work


    logger.info(f"Starting traffic generation scenario: {args.scenario}")
    logger.info(f"Interface: {args.interface}, Dst IP: {args.dst_ip}, Dst MAC: {args.dst_mac}")

    if args.scenario == "malformed-nas":
        send_malformed_nas(args.interface, args.dst_ip, args.dst_mac)
    elif args.scenario == "coap-flood":
        send_coap_flood(args.interface, args.dst_ip, args.dst_mac, args.count)
    else:
        logger.error(f"Unknown scenario: {args.scenario}")
        sys.exit(1)

    logger.info("Traffic generation complete.")

if __name__ == "__main__":
    import os
    # Add project root to sys.path to find src module
    project_root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, project_root_path)
    main()