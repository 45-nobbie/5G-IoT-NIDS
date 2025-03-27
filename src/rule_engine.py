import os
import yaml

class RuleEngine:
    def __init__(self, rule_file="nas_flood.yaml"):
        # Get absolute path to rules directory
        self.rules_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),  # Project root
            "rules/5g"
        )
        self.rule_file = os.path.join(self.rules_dir, rule_file)
        self.rules = self._load_rules()
        
    def _load_rules(self):
        try:
            with open(self.rule_file, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"❌ Rules file not found: {self.rule_file}")
            return []
    
    def process_packet(self, pkt):
        if pkt.haslayer("NAS"):
            nas = pkt["NAS"]
            try:
                # Debug: Print raw device_id bytes
                print(f"Raw device_id bytes: {nas.device_id}")
                
                device_id = nas.device_id.decode().strip('\x00')
                print(f"Processing packet from: {device_id}")
                
                self.counters[device_id] += 1
                print(f"Current count for {device_id}: {self.counters[device_id]}")
                
                # Check rules
                for rule in self.rules:
                    print(f"Checking rule: {rule['name']} (Threshold: {rule['threshold']})")
                    if self.counters[device_id] > rule["threshold"]:
                        print(f"🚨 ALERT: {device_id} ({self.counters[device_id]}) > {rule['threshold']}")
                        self.counters[device_id] = 0
            except Exception as e:
                print(f"Error processing packet: {e}")