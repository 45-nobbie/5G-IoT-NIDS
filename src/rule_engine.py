import yaml
import logging
# import src.state_manager # Import state manager when created

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class RuleEngine:
    def __init__(self, rule_file):
        self.rules = self._load_rules(rule_file)
        # self.state_manager = state_manager.StateManager() # Initialize state manager

    def _load_rules(self, rule_file):
        """Loads rules from a YAML file."""
        try:
            with open(rule_file, 'r') as f:
                rules = yaml.safe_load(f)
                if not isinstance(rules, list):
                    logger.error(f"Rule file {rule_file} should contain a list of rules.")
                    return []
                logger.info(f"Successfully loaded {len(rules)} rules from {rule_file}")
                # TODO: Add validation for rule structure here
                return rules
        except FileNotFoundError:
            logger.error(f"Rule file not found: {rule_file}")
            return []
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML rule file {rule_file}: {e}")
            return []
        except Exception as e:
            logger.error(f"An unexpected error occurred loading rules: {e}")
            return []

    def match(self, packet):
        """
        Matches a dissected packet against the loaded rules.

        Args:
            packet (scapy.packet.Packet): The dissected packet object.

        Returns:
            list: A list of rules that matched the packet.
        """
        matched_rules = []
        if not self.rules:
            return matched_rules

        # --- Prepare packet information for matching ---
        # This needs to extract relevant fields from different layers
        # For example: ip.src, tcp.dport, nas.message_type, mqtt.client_id etc.
        # This extraction logic will become complex as protocol dissectors are added.
        packet_info = self._extract_packet_info(packet)
        if not packet_info:
            return matched_rules # Cannot process if basic info extraction fails

        # --- Iterate through rules ---
        for rule in self.rules:
            try:
                if self._evaluate_rule(rule, packet_info):
                    matched_rules.append(rule)
            except Exception as e:
                logger.warning(f"Error evaluating rule ID '{rule.get('id', 'N/A')}': {e}")
                # Continue processing other rules

        return matched_rules

   # Inside the RuleEngine class in src/rule_engine.py

    def _extract_packet_info(self, packet):
        """ Extracts key information from packet layers into a flat dictionary. """
        info = {'raw_packet': packet} # Keep raw packet if needed for deep inspection
        # Ensure necessary protocol modules are loaded for Scapy's dissection
        try:
             # Import CoAP locally within method if not globally available or just rely on Scapy bindings
             from .protocols.coap import CoAP # Adjusted import relative to src
        except ImportError:
             logger.debug("CoAP layer class not available for extraction check.")
             CoAP = None # Define as None if import fails

        try:
            # --- Standard Headers ---
            if packet.haslayer("Ether"):
                info["src_mac"] = packet["Ether"].src
                info["dst_mac"] = packet["Ether"].dst
            if packet.haslayer("IP"):
                info["src_ip"] = packet["IP"].src
                info["dst_ip"] = packet["IP"].dst
                info["protocol"] = packet["IP"].proto # Protocol number (e.g., 6=TCP, 17=UDP)
            elif packet.haslayer("IPv6"):
                 info["src_ip"] = packet["IPv6"].src
                 info["dst_ip"] = packet["IPv6"].dst
                 info["protocol"] = packet["IPv6"].nh # Next Header (similar to proto)

            # --- L4 Headers ---
            if packet.haslayer("TCP"):
                info["src_port"] = packet["TCP"].sport
                info["dst_port"] = packet["TCP"].dport
                info["protocol_l4"] = "TCP"
                # Example: Extracting TCP flags (common for rules)
                # Scapy represents flags as a FlagValue object, convert to string
                info["tcp_flags"] = str(packet["TCP"].flags)
            elif packet.haslayer("UDP"):
                info["src_port"] = packet["UDP"].sport
                info["dst_port"] = packet["UDP"].dport
                info["protocol_l4"] = "UDP"
            elif packet.haslayer("SCTP"): # Assuming scapy.contrib.sctp is potentially loaded
                 try:
                      from scapy.layers.sctp import SCTP # Check if SCTP layer exists
                      if packet.haslayer(SCTP):
                           info["src_port"] = packet[SCTP].sport
                           info["dst_port"] = packet[SCTP].dport
                           info["protocol_l4"] = "SCTP"
                 except ImportError:
                      logger.debug("SCTP layer not available in Scapy.")


            # --- Custom Protocol Layers (Add checks here) ---

            # Check for CoAP Layer (using the imported class)
            if CoAP and packet.haslayer(CoAP):
                info["protocol_l7"] = "CoAP" # Indicate L7 protocol found
                try:
                     # CoAP fields are enums, access their names using getattr lookup if needed
                     # or just get the raw value. Let's get the value.
                     info["coap_version"] = packet[CoAP].version
                     info["coap_type"] = packet[CoAP].type
                     info["coap_code"] = packet[CoAP].code
                     info["coap_msg_id"] = packet[CoAP].msg_id
                     info["coap_token_len"] = packet[CoAP].token_len
                     if packet[CoAP].token:
                          info["coap_token"] = packet[CoAP].token.hex() # Store token as hex string
                     # Basic payload check (may be inaccurate without full dissection)
                     if packet[CoAP].payload:
                          info["payload_len"] = len(packet[CoAP].payload)

                except AttributeError as e:
                     logger.debug(f"Attribute error extracting CoAP fields: {e}")
                except Exception as e:
                     logger.warning(f"Error extracting CoAP fields: {e}")


            # TODO: Add extraction for other custom protocol layers (NAS, NGAP, MQTT)
            # when their dissectors are implemented. Example:
            # if packet.haslayer(NASLayer):
            #    info["protocol_l7"] = "NAS"
            #    info["nas_message_type"] = packet[NASLayer].message_type # Example

        except AttributeError as e:
            logger.debug(f"Attribute error extracting packet info: {e} - Packet Summary: {packet.summary()}")
        except Exception as e:
            logger.warning(f"Unexpected error extracting packet info: {e}")
            return info # Return partially extracted info if possible
        return info
        """ Extracts key information from packet layers into a flat dictionary. """
        info = {'raw_packet': packet} # Keep raw packet if needed for deep inspection
        try:
            # Example extraction - This needs to be significantly expanded
            if packet.haslayer("IP"):
                info["src_ip"] = packet["IP"].src
                info["dst_ip"] = packet["IP"].dst
            if packet.haslayer("TCP"):
                info["src_port"] = packet["TCP"].sport
                info["dst_port"] = packet["TCP"].dport
                info["protocol_l4"] = "TCP"
            elif packet.haslayer("UDP"):
                info["src_port"] = packet["UDP"].sport
                info["dst_port"] = packet["UDP"].dport
                info["protocol_l4"] = "UDP"
            elif packet.haslayer("SCTP"): # Assuming scapy.contrib.sctp is loaded
                 info["src_port"] = packet["SCTP"].sport
                 info["dst_port"] = packet["SCTP"].dport
                 info["protocol_l4"] = "SCTP"

            # TODO: Add extraction for custom protocol layers (NAS, NGAP, CoAP, MQTT)
            # Example:
            # if packet.haslayer(NASLayer): # Assuming NASLayer is imported
            #    info["nas_message_type"] = packet[NASLayer].message_type
            #    # Extract other relevant NAS fields...
            # if packet.haslayer(MQTT): # Assuming MQTT layer is imported
            #   info["mqtt_message_type"] = packet[MQTT].type
              # Extract other relevant MQTT fields...

        except AttributeError as e:
            logger.debug(f"Attribute error extracting packet info: {e} - Packet Summary: {packet.summary()}")
        except Exception as e:
            logger.warning(f"Unexpected error extracting packet info: {e}")
            return None # Indicate failure
        return info


    # Inside the RuleEngine class in src/rule_engine.py

   
    # Inside the RuleEngine class in src/rule_engine.py

    def _evaluate_rule(self, rule, packet_info):
        """Evaluates a single rule against the extracted packet information."""
        rule_id = rule.get('id', 'N/A') # Get rule ID for logging
        logger.debug(f"--- Evaluating Rule ID: {rule_id} ---")

        # Check if packet_info is available
        if not packet_info:
            logger.debug(f"[{rule_id}] Skipping evaluation: packet_info is missing.")
            return False

        # Log the packet info being used for this rule evaluation
        # Be cautious with logging raw_packet in production (can be large)
        packet_summary = packet_info.get('raw_packet', None).summary() if packet_info.get('raw_packet') else "N/A"
        logger.debug(f"[{rule_id}] Packet Info: { {k:v for k,v in packet_info.items() if k != 'raw_packet'} }") # Log info dict without raw packet
        logger.debug(f"[{rule_id}] Packet Summary: {packet_summary}")


        # Check Protocol Match (if specified) - Basic check for now
        target_protocol = rule.get("protocol", "ANY").upper()
        packet_protocol_match = False
        if target_protocol == "ANY":
             packet_protocol_match = True
        elif target_protocol == "UDP" and packet_info.get("protocol_l4") == "UDP":
             packet_protocol_match = True
        elif target_protocol == "TCP" and packet_info.get("protocol_l4") == "TCP":
             packet_protocol_match = True
        elif target_protocol == "IP" and ("src_ip" in packet_info or "dst_ip" in packet_info):
             packet_protocol_match = True
        # TODO: Add more robust protocol matching based on extracted L7 info etc.
        else:
             # Placeholder: Assume match if specific protocol isn't checked above
             # This might need refinement depending on how L7 protocols are identified
             packet_protocol_match = True # Revisit this logic

        if not packet_protocol_match:
            logger.debug(f"[{rule_id}] Skipping: Protocol mismatch (Rule: {target_protocol}, Packet L4: {packet_info.get('protocol_l4', 'N/A')})")
            return False
        else:
             logger.debug(f"[{rule_id}] Protocol match OK (Rule: {target_protocol})")


        # --- Condition Evaluation ---
        conditions = rule.get("conditions", [])
        if not conditions:
             logger.debug(f"[{rule_id}] MATCHED: Rule has no conditions (protocol match was sufficient).")
             return True # A rule with no conditions implicitly matches if protocol matches

        all_conditions_met = True
        logger.debug(f"[{rule_id}] Evaluating {len(conditions)} conditions...")
        for idx, condition in enumerate(conditions):
            field = condition.get("field")
            operator = condition.get("operator", "==").lower() # Default operator
            value = condition.get("value")
            state_var = condition.get("state") # Check for stateful condition

            log_prefix = f"[{rule_id}][Cond {idx+1}]" # Prefix for condition logs

            if not field and not state_var:
                logger.warning(f"{log_prefix} Condition has no 'field' or 'state'. Skipping condition.")
                continue # Skip malformed condition

            actual_value = None
            value_found = False # Flag to check if we found the field/state

            if state_var:
                # TODO: Get state from State Manager
                # flow_id = self._get_flow_identifier(packet_info)
                # actual_value = self.state_manager.get_state(flow_id, state_var)
                actual_value = "PlaceholderState_Needs_Implementation" # Placeholder
                value_found = True # Assume state exists for placeholder logic
                logger.debug(f"{log_prefix} State Condition: '{state_var}' {operator} '{value}'. Actual State='{actual_value}'")

            elif field:
                 # Check if field exists in extracted info
                if field in packet_info:
                    actual_value = packet_info[field]
                    value_found = True
                    logger.debug(f"{log_prefix} Field Condition: '{field}' ('{actual_value}') {operator} '{value}'")
                else:
                     logger.debug(f"{log_prefix} Field Condition: Field '{field}' NOT FOUND in packet_info.")
                     # For 'exists'/'not exists' operators, this is okay. For others, it's a failure.
                     if operator not in ["exists", "not exists"]:
                          all_conditions_met = False
                          break # Stop evaluating conditions for this rule if required field missing


            # --- Perform Comparison ---
            condition_met = False
            try:
                # Handle operators that don't need 'actual_value' if field/state wasn't found
                if operator == "exists":
                     condition_met = value_found
                elif operator == "not exists":
                     condition_met = not value_found
                # Handle operators that require 'actual_value'
                elif value_found: # Only compare if we actually found a value
                     if operator == "==":
                         condition_met = (str(actual_value) == str(value))
                     elif operator == "!=":
                         condition_met = (str(actual_value) != str(value))
                     elif operator == ">":
                         condition_met = (float(actual_value) > float(value))
                     elif operator == "<":
                         condition_met = (float(actual_value) < float(value))
                     elif operator == ">=":
                         condition_met = (float(actual_value) >= float(value))
                     elif operator == "<=":
                         condition_met = (float(actual_value) <= float(value))
                     elif operator == "contains":
                         condition_met = (str(value) in str(actual_value))
                     elif operator == "not contains":
                         condition_met = (str(value) not in str(actual_value))
                     # TODO: Add more operators (regex, bitwise checks?)
                     else:
                         logger.warning(f"{log_prefix} Unsupported operator '{operator}'")
                         condition_met = False
                else:
                     # Field/state not found, and operator required it
                     condition_met = False

            except (ValueError, TypeError) as e:
                 logger.warning(f"{log_prefix} Type error comparing '{actual_value}' ({type(actual_value)}) with '{value}' ({type(value)}) using operator '{operator}': {e}")
                 condition_met = False # Comparison failed

            # Log outcome of this condition
            logger.debug(f"{log_prefix} Condition Met: {condition_met}")

            if not condition_met:
                all_conditions_met = False
                break # No need to check other conditions for this rule

        # --- Final Result ---
        logger.debug(f"[{rule_id}] Overall conditions met: {all_conditions_met}")
        if all_conditions_met:
             logger.info(f"MATCHED Rule ID: '{rule_id}', Description: '{rule.get('description', '')}'")
             # TODO: Stateful update logic
             return True
        else:
             return False

    # Helper function placeholder
    # def _get_flow_identifier(self, packet_info):
    #    # Logic to create a unique ID for a flow/session/UE
    #    # e.g., based on src_ip, dst_ip, src_port, dst_port, ue_id
    #    return f"{packet_info.get('src_ip')}-{packet_info.get('dst_ip')}" # Simplistic example