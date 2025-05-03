import argparse
import logging
import sys
import signal
import threading
import time
from scapy.all import Packet, Ether # Base packet class

# Import local modules
from capture.scapy_capture import start_capture
# from capture.dpdk_capture import start_dpdk_capture # If you implement DPDK capture
from rule_engine import RuleEngine
import protocols # To load custom layer definitions implicitly
from state_manager import StateManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("5G_Shield_Main")

# Global stop event for graceful shutdown
stop_event = threading.Event()

def signal_handler(sig, frame):
    """Handles termination signals."""
    logger.info(f"Signal {sig} received. Stopping NIDS...")
    stop_event.set()

def process_packet(packet, rule_engine, state_manager):
    """
    Callback function to process each captured packet.
    This function contains the core processing pipeline stages
    after capture: Dissection -> State Update -> Rule Matching -> Alerting.
    """
    if not isinstance(packet, Packet):
         logger.warning("Received non-Scapy packet object. Skipping.")
         return

    logger.debug(f"Processing packet: {packet.summary()}")

    # 1. Dissection (Handled automatically by Scapy if layers are bound correctly)
    # Custom layers in src/protocols/ should be loaded via the import.
    # Scapy attempts dissection when accessing layers (e.g., packet[TCP]).

    # 2. State Update (Update FSMs before rule matching)
    try:
        state_manager.update_state(packet_info=rule_engine._extract_packet_info(packet)) # Use engine's helper
    except Exception as e:
         logger.error(f"Error during state update: {e}")


    # 3. Rule Matching
    matched_rules = []
    try:
        matched_rules = rule_engine.match(packet)
    except Exception as e:
        logger.error(f"Error during rule matching: {e}")

    # 4. Alerting/Logging
    if matched_rules:
        for rule in matched_rules:
            log_alert(rule, packet, rule_engine) # Pass rule_engine to access extraction logic

def log_alert(rule, packet, rule_engine):
    """Generates and logs an alert based on a matched rule."""
    alert_message = {
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        "rule_id": rule.get('id', 'N/A'),
        "severity": rule.get('severity', 'INFO'),
        "description": rule.get('description', 'No description'),
        "action": rule.get('action', 'ALERT'),
        "protocol": rule.get('protocol', 'ANY'),
        # Add relevant packet details from extracted info
        "packet_details": {}
    }
    # Extract details specified in the rule's log_details section
    packet_info = rule_engine._extract_packet_info(packet)
    if packet_info:
        for detail_key in rule.get("log_details", []):
             if detail_key in packet_info:
                  # Handle non-serializable Scapy fields if necessary
                  value = packet_info[detail_key]
                  if isinstance(value, Packet): # Avoid logging nested packets directly
                      value = value.summary()
                  try: # Basic check for serializability
                       import json
                       json.dumps({detail_key: value})
                       alert_message["packet_details"][detail_key] = value
                  except TypeError:
                       alert_message["packet_details"][detail_key] = f"<{type(value).__name__} object>"
             else:
                  alert_message["packet_details"][detail_key] = "N/A"
    else:
         alert_message["packet_details"]["error"] = "Could not extract packet info"


    # Log the alert (e.g., print as JSON, send to syslog, etc.)
    import json
    logger.warning(f"ALERT: {json.dumps(alert_message)}") # Use warning level for alerts

    # TODO: Implement actual actions like DROP (would need integration with firewall/packet filtering)

def main():
    parser = argparse.ArgumentParser(description="5G Shield NIDS")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to capture packets from")
    parser.add_argument("-r", "--rules", required=True, help="Path to the YAML rule file")
    parser.add_argument("-t", "--timeout", type=int, default=300, help="State timeout in seconds for inactive flows (default: 300)")
    # parser.add_argument("--use-dpdk", action="store_true", help="Enable DPDK for packet capture (requires setup)") # Optional DPDK flag

    args = parser.parse_args()

    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("Starting 5G Shield NIDS...")
    logger.info(f"Monitoring interface: {args.interface}")
    logger.info(f"Loading rules from: {args.rules}")
    logger.info(f"State timeout: {args.timeout} seconds")

    # Initialize components
    try:
         state_manager = StateManager(state_timeout=args.timeout)
         rule_engine = RuleEngine(args.rules)
         if not rule_engine.rules:
              logger.error("Failed to load rules. Exiting.")
              sys.exit(1)
    except Exception as e:
         logger.error(f"Failed to initialize NIDS components: {e}")
         sys.exit(1)


    # Start state pruning thread
    pruning_thread = threading.Thread(target=lambda: periodic_pruning(state_manager, stop_event), daemon=True)
    pruning_thread.start()


    # Choose capture method
    use_dpdk = False # Add logic based on args.use_dpdk and dpdk_init check if needed
    if use_dpdk:
        # dpdk_init.initialize_dpdk() # If implemented
        # start_dpdk_capture(...)
        logger.error("DPDK capture not implemented in this skeleton.")
        sys.exit(1)
    else:
        # Start Scapy capture in a separate thread
        capture_thread = threading.Thread(target=start_capture,
                                          args=(args.interface,
                                                lambda pkt: process_packet(pkt, rule_engine, state_manager),
                                                stop_event),
                                          daemon=True) # Daemon thread exits if main thread exits
        capture_thread.start()

    # Keep main thread alive while capture thread runs, or until stop signal
    while not stop_event.is_set():
        try:
            # Keep the main thread alive, maybe sleep briefly
            time.sleep(1)
            # Optionally check if capture thread is alive
            if not capture_thread.is_alive() and not stop_event.is_set():
                 logger.error("Capture thread appears to have stopped unexpectedly. Exiting.")
                 stop_event.set()

        except KeyboardInterrupt: # Handle Ctrl+C in main thread if signal handler doesn't catch it first
            logger.info("Ctrl+C detected in main thread. Stopping NIDS...")
            stop_event.set()

    # Wait for capture thread to finish
    logger.info("Waiting for capture thread to complete...")
    capture_thread.join(timeout=5.0) # Wait max 5 seconds
    if capture_thread.is_alive():
         logger.warning("Capture thread did not stop gracefully.")

    logger.info("5G Shield NIDS stopped.")
    sys.exit(0)


def periodic_pruning(state_manager, stop_event):
     """ Periodically calls the state manager's pruning function. """
     prune_interval = 60 # Check every 60 seconds
     logger.info(f"State pruning thread started. Checking every {prune_interval} seconds.")
     while not stop_event.wait(timeout=prune_interval):
          try:
               state_manager.prune_inactive_states()
          except Exception as e:
               logger.error(f"Error during periodic state pruning: {e}")
     logger.info("State pruning thread stopped.")


if __name__ == "__main__":
    main()