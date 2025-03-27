from scapy.packet import Packet
from scapy.fields import ByteEnumField, StrFixedLenField

class NAS(Packet):
    name = "5G_NAS"
    fields_desc = [
        ByteEnumField("message_type", 0x41, {
            0x41: "Registration Request",
            0x42: "Authentication Request"
        }),
        StrFixedLenField("device_id", "", 12)
    ]
    
    def extract_padding(self, s):
        return "", s  # No payload