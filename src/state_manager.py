# src/state_manager.py
import logging
from collections import defaultdict
import time

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class StateManager:
    """
    Manages protocol states for different flows/entities using Finite State Machines (FSMs).
    This is a placeholder implementation. Specific FSM logic for NAS, NGAP, CoAP, MQTT
    needs to be defined based on protocol specifications.
    """
    def __init__(self, state_timeout=300):
        """
        Initializes the state manager.

        Args:
            state_timeout (int): Timeout in seconds after which inactive states are pruned.
        """
        # Stores state for different flows. Key: flow_id, Value: dict of state variables
        self.flow_states = defaultdict(lambda: {"last_seen": time.time()})
        self.state_timeout = state_timeout
        # TODO: Define FSM structures (states, transitions) for each protocol
        # Example FSM definition structure (conceptual)
        self.fsm_definitions = {
            "MQTT": {
                "states": ["DISCONNECTED", "CONNECT_SENT", "CONNECTED", "SUBSCRIBE_SENT"],
                "transitions": {
                    ("DISCONNECTED", "MQTT_CONNECT"): "CONNECT_SENT",
                    ("CONNECT_SENT", "MQTT_CONNACK_ACCEPT"): "CONNECTED",
                    ("CONNECTED", "MQTT_SUBSCRIBE"): "SUBSCRIBE_SENT",
                    ("CONNECTED", "MQTT_DISCONNECT"): "DISCONNECTED",
                    # ... other transitions and error conditions
                },
                "initial_state": "DISCONNECTED",
                "state_variable": "mqtt_connection_state" # Key used in flow_states
            },
            "NAS_REG": {
                 "states": ["DEREGISTERED", "REGISTER_INITIATED", "AUTHENTICATING", "SEC_MODE_INITIATED", "REGISTERED"],
                 "transitions": {
                      # ... NAS Registration state transitions based on NAS messages
                 },
                 "initial_state": "DEREGISTERED",
                 "state_variable": "nas_registration_state"
            }
            # Add FSM definitions for NGAP procedures, CoAP interactions etc.
        }
        logger.info("State Manager Initialized.")


    def _get_flow_identifier(self, packet_info):
        """
        Generates a unique identifier for a communication flow based on packet info.
        This needs refinement based on protocols (e.g., include UE ID for NAS/NGAP).
        """
        # Simple IP-Port based flow ID (suitable for TCP/UDP)
        src_ip = packet_info.get("src_ip", "N/A")
        dst_ip = packet_info.get("dst_ip", "N/A")
        src_port = packet_info.get("src_port", "N/A")
        dst_port = packet_info.get("dst_port", "N/A")
        l4_proto = packet_info.get("protocol_l4", "N/A")

        # TODO: Enhance for 5G - Use SUPI/GUTI/AMF UE NGAP ID/RAN UE NGAP ID when available
        # Example: if "ue_id" in packet_info: return packet_info["ue_id"]

        # Ensure consistent order for bidirectional flows
        if src_ip == "N/A" or dst_ip == "N/A":
             return None # Cannot identify flow

        if (src_ip, src_port) > (dst_ip, dst_port):
            return f"{l4_proto}-{dst_ip}:{dst_port}-{src_ip}:{src_port}"
        else:
            return f"{l4_proto}-{src_ip}:{src_port}-{dst_ip}:{dst_port}"


    def update_state(self, packet_info):
        """
        Updates the state for the relevant flow based on the incoming packet
        and defined FSM transitions.
        """
        flow_id = self._get_flow_identifier(packet_info)
        if not flow_id:
            logger.debug("Could not determine flow ID for state update.")
            return

        self.flow_states[flow_id]["last_seen"] = time.time()

        # --- Determine relevant FSM based on packet protocol ---
        protocol = "UNKNOWN"
        event = "UNKNOWN_EVENT"
        # TODO: Determine protocol and map packet to an FSM 'event'
        # Example:
        # if packet_info.get("mqtt_message_type"):
        #    protocol = "MQTT"
        #    event = f"MQTT_{packet_info['mqtt_message_type']}"
        #    if event == "MQTT_CONNACK" and packet_info.get("connack_retcode") == 0:
        #        event = "MQTT_CONNACK_ACCEPT" # More specific event
        # elif packet_info.get("nas_message_type"):
        #    protocol = "NAS_REG" # Assuming we track NAS registration
        #    event = f"NAS_{packet_info['nas_message_type']}"

        if protocol != "UNKNOWN" and protocol in self.fsm_definitions:
            fsm = self.fsm_definitions[protocol]
            state_var = fsm["state_variable"]
            current_state = self.flow_states[flow_id].get(state_var, fsm["initial_state"])

            transition_key = (current_state, event)
            if transition_key in fsm["transitions"]:
                next_state = fsm["transitions"][transition_key]
                self.flow_states[flow_id][state_var] = next_state
                logger.debug(f"State transition for flow '{flow_id}': {current_state} --({event})--> {next_state}")
            else:
                # Optional: Log unexpected event for the current state
                logger.debug(f"No transition defined for flow '{flow_id}' from state '{current_state}' on event '{event}'")
        else:
            logger.debug(f"No relevant FSM found or packet protocol undetermined for flow '{flow_id}'")


    def get_state(self, packet_info, state_variable_name):
        """
        Retrieves the current value of a specific state variable for the flow
        associated with the packet.
        """
        flow_id = self._get_flow_identifier(packet_info)
        if not flow_id or flow_id not in self.flow_states:
            # If no state exists, return the initial state if defined, else None
            for proto, fsm in self.fsm_definitions.items():
                 if fsm["state_variable"] == state_variable_name:
                      return fsm["initial_state"]
            return None # No state found and no matching initial state

        # Return the specific state variable if it exists, else None
        return self.flow_states[flow_id].get(state_variable_name)


    def prune_inactive_states(self):
        """Removes state entries that haven't seen activity beyond the timeout."""
        now = time.time()
        inactive_flows = [
            flow_id for flow_id, state_data in self.flow_states.items()
            if now - state_data.get("last_seen", 0) > self.state_timeout
        ]
        if inactive_flows:
            logger.info(f"Pruning {len(inactive_flows)} inactive state flows.")
            for flow_id in inactive_flows:
                del self.flow_states[flow_id]