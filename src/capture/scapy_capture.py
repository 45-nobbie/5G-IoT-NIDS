import logging
from scapy.all import sniff, Scapy_Exception

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def start_capture(interface, packet_handler_callback, stop_event):
    """
    Starts packet capture on the specified interface using Scapy.

    Args:
        interface (str): The network interface name to capture packets from.
        packet_handler_callback (callable): The function to call for each captured packet.
                                            This function should accept one argument: the packet.
        stop_event (threading.Event): An event to signal when to stop capturing.
    """
    logger.info(f"Starting packet capture on interface: {interface}")
    try:
        # The 'stop_filter' lambda checks the stop_event on each packet arrival.
        # 'prn' specifies the callback function for each packet.
        # 'store=0' prevents Scapy from storing packets in memory.
        # 'iface' specifies the interface.
        sniff(iface=interface,
              prn=packet_handler_callback,
              stop_filter=lambda x: stop_event.is_set(),
              store=0)
        logger.info("Packet capture stopped.")
    except Scapy_Exception as e:
        logger.error(f"Scapy error during capture on interface {interface}: {e}")
        # Handle specific errors like interface not found, permissions, etc.
        if "No such device" in str(e):
             logger.error(f"Interface '{interface}' not found. Please check the interface name.")
        elif "Permission denied" in str(e):
             logger.error("Permission denied. Please run the script with sufficient privileges (e.g., sudo).")
        else:
             logger.error("An unexpected Scapy error occurred.")
    except Exception as e:
        logger.error(f"An unexpected error occurred during packet capture: {e}")