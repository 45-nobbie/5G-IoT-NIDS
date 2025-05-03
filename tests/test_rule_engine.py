# tests/test_rule_engine.py
# Placeholder for unit tests for the RuleEngine

import unittest
import os
import yaml
from scapy.all import IP, TCP, UDP, Raw # Basic layers for testing

# Add project src to path to allow importing rule_engine
import sys
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.rule_engine import RuleEngine
# from src.state_manager import StateManager # Import if needed for stateful tests

# Define path to a temporary test rule file
TEST_RULE_FILE = "test_rules.yaml"

# Sample test rules
TEST_RULES = [
    {
        "id": "TEST-TCP-SYN-01", "description": "TCP SYN Packet", "protocol": "TCP",
        "type": "Header", "conditions": [{"field": "tcp.flags", "value": "S"}], # Assuming flags are extracted
        "action": "ALERT", "severity": "LOW", "log_details": ["src_ip", "dst_ip"]
    },
    {
        "id": "TEST-IP-Match-01", "description": "Specific Source IP", "protocol": "IP",
        "type": "Header", "conditions": [{"field": "src_ip", "value": "192.168.1.100"}],
        "action": "ALERT", "severity": "MEDIUM", "log_details": ["src_ip", "dst_ip"]
    },
    # Add semantic and stateful rule examples here when dissectors/state mgr are ready
]


class TestRuleEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Create a temporary rule file for testing."""
        with open(TEST_RULE_FILE, 'w') as f:
            yaml.dump(TEST_RULES, f)
        # cls.state_manager = StateManager() # Init state manager if needed

    @classmethod
    def tearDownClass(cls):
        """Remove the temporary rule file."""
        if os.path.exists(TEST_RULE_FILE):
            os.remove(TEST_RULE_FILE)

    def setUp(self):
        """Create a RuleEngine instance for each test."""
        self.rule_engine = RuleEngine(TEST_RULE_FILE)
        # Inject mock state manager if needed:
        # self.rule_engine.state_manager = self.state_manager

    def test_load_rules(self):
        """Test if rules are loaded correctly."""
        self.assertIsNotNone(self.rule_engine.rules)
        self.assertEqual(len(self.rule_engine.rules), len(TEST_RULES))
        self.assertEqual(self.rule_engine.rules[0]['id'], "TEST-TCP-SYN-01")

    def test_match_ip_rule(self):
        """Test matching a simple IP header rule."""
        # Create a dummy Scapy packet
        packet = IP(src="192.168.1.100", dst="8.8.8.8") / TCP()
        matched = self.rule_engine.match(packet)
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]['id'], "TEST-IP-Match-01")

    def test_no_match(self):
        """Test when no rules should match."""
        packet = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(dport=53)
        matched = self.rule_engine.match(packet)
        self.assertEqual(len(matched), 0)

    # --- TODO: Add more complex tests ---
    # - Test semantic rule matching (requires mocked packet_info with custom fields)
    # - Test stateful rule matching (requires mocked StateManager interaction)
    # - Test various operators (>, <, contains, exists, etc.)
    # - Test rule logic with multiple conditions (AND logic)
    # - Test error handling (malformed rules, missing fields)


# Helper function to mock extracted packet info for semantic/stateful tests
# def mock_packet_info(packet, custom_fields=None, state_values=None):
#     info = RuleEngine(None)._extract_packet_info(packet) # Use extractor logic
#     if custom_fields:
#         info.update(custom_fields)
#     # Mock state manager retrieval within the test case if needed
#     return info


if __name__ == '__main__':
    unittest.main()