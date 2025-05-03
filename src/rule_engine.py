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

    def _extract_packet_info(self, packet):
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


    def _evaluate_rule(self, rule, packet_info):
        """Evaluates a single rule against the extracted packet information."""
        # Check if packet_info is available
        if not packet_info:
            return False

        # --- Rule Type Handling ---
        rule_type = rule.get("type", "Semantic").lower() # Default to Semantic

        # Check Protocol Match (if specified)
        # This needs refinement based on how protocol layers are identified in packet_info
        target_protocol = rule.get("protocol", "ANY").upper()
        packet_protocol_match = False
        if target_protocol == "ANY":
             packet_protocol_match = True
        # else:
             # TODO: Logic to check if packet_info contains indicators of the target_protocol
             # Example: if target_protocol == "NAS" and "nas_message_type" in packet_info: packet_protocol_match = True
             # Placeholder: Assume match for now if not ANY
             packet_protocol_match = True # Needs implementation

        if not packet_protocol_match:
            return False


        # --- Condition Evaluation ---
        conditions = rule.get("conditions", [])
        if not conditions: # A rule with no conditions implicitly matches (if protocol matches)
             return True

        all_conditions_met = True
        for condition in conditions:
            field = condition.get("field")
            operator = condition.get("operator", "==").lower() # Default operator
            value = condition.get("value")
            state_var = condition.get("state") # Check for stateful condition

            if not field and not state_var:
                logger.warning(f"Rule ID '{rule.get('id', 'N/A')}' has condition without 'field' or 'state'. Skipping condition.")
                continue # Skip malformed condition

            actual_value = None
            is_state_condition = False

            if state_var:
                is_state_condition = True
                # TODO: Get state from State Manager
                # Requires identifying the flow/entity (e.g., based on IP/Port/UE ID)
                # flow_id = self._get_flow_identifier(packet_info)
                # actual_value = self.state_manager.get_state(flow_id, state_var)
                actual_value = "PlaceholderState_Needs_Implementation" # Placeholder
                logger.debug(f"Evaluating state condition: {state_var} {operator} {value} (Actual: {actual_value})")

            elif field:
                 # Check if field exists in extracted info
                if field not in packet_info:
                     all_conditions_met = False # Field required by rule is missing
                     logger.debug(f"Field '{field}' not found in packet_info for rule '{rule.get('id', 'N/A')}'")
                     break # Stop evaluating conditions for this rule
                actual_value = packet_info[field]
                logger.debug(f"Evaluating field condition: {field} ('{actual_value}') {operator} {value}")


            # --- Perform Comparison ---
            condition_met = False
            try:
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
                elif operator == "exists":
                     condition_met = (actual_value is not None) # Checks if field/state was found
                elif operator == "not exists":
                     condition_met = (actual_value is None) # Checks if field/state was missing
                # TODO: Add more operators (regex, bitwise checks?)
                else:
                    logger.warning(f"Unsupported operator '{operator}' in rule '{rule.get('id', 'N/A')}'")
                    condition_met = False

            except (ValueError, TypeError) as e:
                 logger.warning(f"Type error comparing '{actual_value}' ({type(actual_value)}) with '{value}' ({type(value)}) using operator '{operator}' in rule '{rule.get('id', 'N/A')}': {e}")
                 condition_met = False # Comparison failed

            if not condition_met:
                all_conditions_met = False
                break # No need to check other conditions for this rule

        # --- Final Result ---
        if all_conditions_met:
             logger.info(f"MATCHED Rule ID: '{rule.get('id', 'N/A')}', Description: '{rule.get('description', '')}'")
             # TODO: If stateful rule matched, potentially update state via State Manager
             # flow_id = self._get_flow_identifier(packet_info)
             # self.state_manager.update_state(flow_id, rule) # Pass rule for context if needed
             return True
        else:
             return False


    # Helper function placeholder
    # def _get_flow_identifier(self, packet_info):
    #    # Logic to create a unique ID for a flow/session/UE
    #    # e.g., based on src_ip, dst_ip, src_port, dst_port, ue_id
    #    return f"{packet_info.get('src_ip')}-{packet_info.get('dst_ip')}" # Simplistic example