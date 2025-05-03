# src/main.py
import argparse
import logging
import sys
import signal
import threading
import time
from scapy.all import Packet, Ether # Base packet class

# Import local modules
# Ensure this path allows importing capture, rule_engine etc.
try:
    from capture.scapy_capture import start_capture
    # from capture.dpdk_capture import start_dpdk_capture # If you implement DPDK capture
    from rule_engine import RuleEngine
    import protocols # To load custom layer definitions implicitly
    from state_manager import StateManager
except ImportError as e:
     print(f"Error importing local modules: {e}")
     print("Ensure you are running from the project root directory or PYTHONPATH is set correctly.")
     sys.exit(1)


# --- CHANGE 1: Set Logging Level to DEBUG ---
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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

    # DEBUG log for every packet received by the handler
    logger.debug(f"Processing packet received by handler: {packet.summary()}")

    # 1. Dissection (Handled by Scapy based on bound layers)

    # 2. State Update
    try:
        # Use engine's helper to get packet info for state update
        packet_info_for_state = rule_engine._extract_packet_info(packet)
        if packet_info_for_state: # Only update state if info could be extracted
             state_manager.update_state(packet_info=packet_info_for_state)
        else:
             logger.debug("Skipping state update due to failed packet info extraction.")
    except Exception as e:
         logger.error(f"Error during state update: {e}", exc_info=True) # Add exc_info for traceback

    # 3. Rule Matching
    matched_rules = []
    try:
        # packet object itself is passed to match now
        matched_rules = rule_engine.match(packet)
    except Exception as e:
        logger.error(f"Error during rule matching: {e}", exc_info=True) # Add exc_info for traceback

    # 4. Alerting/Logging
    if matched_rules:
        logger.debug(f"Found {len(matched_rules)} matching rules for packet: {packet.summary()}")
        # Pass the raw packet to log_alert for info extraction
        for rule in matched_rules:
            log_alert(rule, packet, rule_engine) # Pass rule, packet, and engine
    # else: # Optional: Log when no rules match
        # logger.debug(f"No rules matched for packet: {packet.summary()}")


# --- CHANGE 2: Make log_alert more robust ---
def log_alert(rule, packet, rule_engine):
    """Generates and logs an alert based on a matched rule."""
    # Check if the rule object is valid and has an ID
    if not isinstance(rule, dict) or not rule.get('id'):
        logger.error(f"Invalid or incomplete rule object received by log_alert: {rule}. Cannot generate alert.")
        return # Exit if rule is invalid

    rule_id = rule.get('id', 'N/A') # Should have ID due to check above

    alert_message = {
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        "rule_id": rule_id,
        # Use defaults only if keys are missing in the valid rule dict
        "severity": rule.get('severity', 'INFO'),
        "description": rule.get('description', 'No description provided'),
        "action": rule.get('action', 'ALERT'),
        "protocol": rule.get('protocol', 'ANY'),
        "packet_details": {}
    }

    # Extract packet info *once* here for logging details
    packet_info = None
    try:
         packet_info = rule_engine._extract_packet_info(packet)
    except Exception as e:
         logger.error(f"Error extracting packet info within log_alert for rule {rule_id}: {e}", exc_info=True)
         alert_message["packet_details"]["error"] = "Failed to extract packet info for alert."

    if packet_info:
        # Extract details specified in the rule's log_details section
        for detail_key in rule.get("log_details", []):
             if detail_key in packet_info:
                  # Handle non-serializable Scapy fields if necessary
                  value = packet_info[detail_key]
                  # Basic check for Scapy layers/packets in values
                  if isinstance(value, Packet):
                      value = f"<{type(value).__name__} Summary: {value.summary()}>"

                  # Ensure value is serializable before adding
                  try:
                       import json
                       json.dumps({detail_key: value}) # Test serialization
                       alert_message["packet_details"][detail_key] = value
                  except TypeError:
                       logger.warning(f"Could not serialize field '{detail_key}' (type: {type(value)}) for rule {rule_id}. Storing representation.")
                       alert_message["packet_details"][detail_key] = repr(value) # Store representation instead
             else:
                  # Log that a requested detail was not found in packet_info
                  logger.debug(f"Detail '{detail_key}' requested by rule {rule_id} not found in extracted packet_info.")
                  alert_message["packet_details"][detail_key] = "N/A (Not Found)"
    # else: # Error message already added if packet_info failed extraction
    #    pass


    # Log the alert (e.g., print as JSON, send to syslog, etc.)
    import json
    # Log actual matched alerts as WARNING, potential errors as ERROR
    logger.warning(f"ALERT: {json.dumps(alert_message)}")

    # TODO: Implement actual actions like DROP


# main function remains the same...
def main():
    parser = argparse.ArgumentParser(description="5G Shield NIDS")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to capture packets from")
    parser.add_argument("-r", "--rules", required=True, help="Path to the YAML rule file")
    parser.add_argument("-t", "--timeout", type=int, default=300, help="State timeout in seconds for inactive flows (default: 300)")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("Starting 5G Shield NIDS...")
    logger.info(f"Monitoring interface: {args.interface}")
    logger.info(f"Loading rules from: {args.rules}")
    logger.info(f"State timeout: {args.timeout} seconds")

    try:
         state_manager = StateManager(state_timeout=args.timeout)
         rule_engine = RuleEngine(args.rules)
         if not rule_engine.rules:
              logger.error("Rule file loaded, but no rules found or rules list is empty. Exiting.")
              sys.exit(1)
         # Add check for rule file parsing errors? RuleEngine init logs errors.
    except Exception as e:
         logger.error(f"Failed to initialize NIDS components: {e}", exc_info=True)
         sys.exit(1)

    pruning_thread = threading.Thread(target=lambda: periodic_pruning(state_manager, stop_event), daemon=True)
    pruning_thread.start()

    use_dpdk = False
    if use_dpdk:
        logger.error("DPDK capture not implemented.")
        sys.exit(1)
    else:
        # Pass rule_engine and state_manager to the callback closure
        def packet_processor_callback(pkt):
             process_packet(pkt, rule_engine, state_manager)

        capture_thread = threading.Thread(target=start_capture,
                                          args=(args.interface,
                                                packet_processor_callback, # Use the callback
                                                stop_event),
                                          daemon=True)
        capture_thread.start()

    while not stop_event.is_set():
        try:
            time.sleep(1)
            if not capture_thread.is_alive() and not stop_event.is_set():
                 logger.error("Capture thread appears to have stopped unexpectedly. Exiting.")
                 stop_event.set()
        except KeyboardInterrupt:
            logger.info("Ctrl+C detected in main thread. Stopping NIDS...")
            stop_event.set()

    logger.info("Waiting for capture thread to complete...")
    capture_thread.join(timeout=5.0)
    if capture_thread.is_alive():
         logger.warning("Capture thread did not stop gracefully.")

    logger.info("5G Shield NIDS stopped.")
    sys.exit(0)

# periodic_pruning function remains the same...
def periodic_pruning(state_manager, stop_event):
     """ Periodically calls the state manager's pruning function. """
     prune_interval = 60 # Check every 60 seconds
     logger.info(f"State pruning thread started. Checking every {prune_interval} seconds.")
     while not stop_event.wait(timeout=prune_interval):
          try:
               logger.debug("Running periodic state pruning...")
               state_manager.prune_inactive_states()
               logger.debug("State pruning finished.")
          except Exception as e:
               logger.error(f"Error during periodic state pruning: {e}", exc_info=True)
     logger.info("State pruning thread stopped.")

if __name__ == "__main__":
    main()