#!/usr/bin/env python3

# scripts/traffic_gen_example.py
# Sends a single, simple CoAP GET packet using manual first byte calculation.

import sys
import os
import argparse
import logging
import time
from scapy.all import sendp, Ether, IP, UDP, Raw, RandShort, RawVal # Import necessary layers

# --- Add project root to sys.path ---
# This allows importing custom layers from src/protocols
project_root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root_path not in sys.path:
    sys.path.insert(0, project_root_path)
    print(f"Added {project_root_path} to PYTHONPATH") # Debug print

# --- Try importing the custom CoAP layer ---
try:
    # Make sure src/protocols/coap.py and src/protocols/__init__.py are set up correctly
    from src.protocols.coap import CoAP # Import the modified CoAP layer
    print("Successfully imported CoAP layer from src.protocols.coap") # Debug print
except ImportError as e:
    print(f"ERROR: Could not import CoAP layer. Ensure src/protocols/coap.py exists and is importable.")
    print(f"ImportError: {e}")
    print(f"Current sys.path: {sys.path}")
    sys.exit(1)
except Exception as e:
     print(f"An unexpected error occurred during CoAP import: {e}")
     sys.exit(1)


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SimpleTrafficGen")

def send_basic_coap_get(iface, dst_ip="127.0.0.1", dst_port=5683, src_port=None):
    """ Sends a basic CoAP GET request using manual first byte calc """
    if src_port is None:
         src_port = RandShort() # Use a random source port if none provided

    logger.info(f"Crafting CoAP GET packet (manual first byte): {iface} -> {dst_ip}:{dst_port} from port {src_port}")

    try:
        # --- Calculate the first byte manually ---
        coap_version = 1  # Version 1 (binary 01xx xxxx)
        coap_type = 0     # Type CON (binary xx00 xxxx)
        token_length = 2  # Let's use a 2-byte token (binary xxxx 0010)

        # Shift bits into position: (Ver << 6) | (Type << 4) | (TKL)
        # Ver = 1 -> 01000000
        # Type = 0 -> 00000000
        # TKL = 2 -> 00000010
        first_byte_val = (coap_version << 6) | (coap_type << 4) | token_length
        # Calculation: (1 << 6) | (0 << 4) | 2 = 64 | 0 | 2 = 66
        # Binary: 01000010
        logger.info(f"Calculated first_byte: Version={coap_version}, Type={coap_type}, TKL={token_length} => Value={first_byte_val} (0x{first_byte_val:02X})")

        # --- Create the token with the correct length ---
        coap_token = os.urandom(token_length)
        logger.info(f"Generated token (length {token_length}): {coap_token.hex()}")

        # --- Craft the CoAP layer ---
        # Assign the calculated byte value directly
        # Assign the correctly sized token
        coap_request = CoAP(
            first_byte=first_byte_val, # Assign calculated byte
            code='GET',                # Still use string for code, ByteEnumField handles it okay usually
            msg_id=RandShort(),        # Random message ID
            token=RawVal(coap_token)           # Assign the generated token matching token_length
            # No payload for this request
        )

        # Build the full packet stack
        # Use Ether()/IP()/UDP() for loopback sending
        packet = Ether()/IP(dst=dst_ip)/UDP(dport=dst_port, sport=src_port)/coap_request

        logger.info(f"Packet Summary: {packet.summary()}")
        # Display detailed CoAP fields before sending (optional debug)
        # logger.info("CoAP Layer Details:")
        # coap_request.show() # Show fields of the crafted CoAP layer

        # Send at Layer 2 using sendp
        sendp(packet, iface=iface, verbose=0) # verbose=0 hides Scapy's default send confirmation

        logger.info("CoAP GET packet sent successfully.")

    except Exception as e:
        logger.error(f"Error crafting or sending CoAP packet: {e}", exc_info=True)


def main():
    parser = argparse.ArgumentParser(description="Simple CoAP GET Traffic Generator (Manual First Byte)")
    # Interface is needed by sendp even for loopback in some OS/Scapy versions
    parser.add_argument("-i", "--interface", required=True, help="Network interface to use for sending (e.g., 'lo' for loopback)")
    parser.add_argument("--dst-ip", default="127.0.0.1", help="Destination IP address (default: 127.0.0.1)")
    parser.add_argument("--dst-port", type=int, default=5683, help="Destination UDP port (default: 5683)")

    args = parser.parse_args()

    send_basic_coap_get(iface=args.interface, dst_ip=args.dst_ip, dst_port=args.dst_port)


if __name__ == "__main__":
    main()