# src/protocols/coap.py
# Basic CoAP (Constrained Application Protocol) definition using Scapy
# Ref: RFC 7252 - Using manual first byte calculation for build robustness

from scapy.packet import Packet, bind_layers
# Import ByteField instead of BitField for the first byte
from scapy.fields import ByteField, ByteEnumField, ShortField, FieldLenField, StrLenField
from scapy.layers.inet import UDP
import logging

logger = logging.getLogger(__name__)

# CoAP Message Types (Keep for reference/dissection later)
COAP_TYPES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}

# CoAP Method/Response Codes (Keep for reference/dissection later)
COAP_CODES = {
    0: "Empty", # Special case
    1: "GET", 2: "POST", 3: "PUT", 4: "DELETE", # Methods
    65: "2.01 Created", 68: "2.04 Changed", 69: "2.05 Content", # Success Codes
    128: "4.00 Bad Request", 131: "4.03 Forbidden", 132: "4.04 Not Found", # Client Error Codes
    # ... Add more codes as needed
}

# --- Modified CoAP Layer ---
class CoAP(Packet):
    """
    Scapy layer for CoAP.
    NOTE: Uses a single ByteField for the first byte (Ver, Type, TKL)
    to improve robustness during packet building. Dissection would
    require manually parsing this 'first_byte' field.
    """
    name = "CoAP"
    fields_desc = [
        # --- Replace version, type, token_len with a single byte ---
        # Ver (2 bits), Type (2 bits), Token Length (4 bits)
        ByteField("first_byte", 0), # Manually calculated during build
        # --- Keep remaining fields ---
        ByteEnumField("code", 1, COAP_CODES), # 0.01 GET is default
        ShortField("msg_id", 0),
        # Token length needs to be explicitly handled by the builder script,
        # as length_of cannot easily refer back to parts of first_byte.
        FieldLenField("token", None), # Removed length_of for build simplicity
        # Payload calculation is simplified, dissection needs improvement.
        StrLenField("payload", "", length_from=lambda pkt: calculate_payload_len(pkt)),
    ]

    # post_build handles adding the payload marker if payload exists
    def post_build(self, p, pay):
        # Minimal payload handling: if payload exists, add 0xFF marker + payload
        if pay:
            p += b'\xff' + pay
        # Update CoAP header length if needed (usually handled by Scapy)
        return p

# --- SIMPLIFIED calculate_payload_len ---
# Since pkt.token_len doesn't exist anymore, we simplify drastically for now.
# Proper dissection would need to parse first_byte to get token length,
# then parse options to find the real start of the payload.
def calculate_payload_len(pkt):
     """
     Placeholder payload length calculation.
     WARNING: Highly inaccurate without parsing first_byte and options.
     Returns 0 for simplicity in initial tests.
     """
     return 0 # Simplification - assume no payload for basic dissection

# Bind CoAP layer to UDP ports 5683 (standard) and 5684 (standard DTLS)
# This tells Scapy: if a UDP packet has sport or dport 5683/5684, try dissecting the payload as CoAP.
bind_layers(UDP, CoAP, dport=5683)
bind_layers(UDP, CoAP, sport=5683)
bind_layers(UDP, CoAP, dport=5684) # Add CoAPs DTLS port too
bind_layers(UDP, CoAP, sport=5684)

logger.info("Modified CoAP Scapy layer (manual first byte) loaded and bound to UDP ports 5683/5684.")