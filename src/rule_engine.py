from collections import defaultdict
import yaml

class RuleEngine:
    def __init__(self, rule_file="rules/5g/nas_flood.yaml"):
        self.rules = self._load_rules(rule_file)
        self.counters = defaultdict(int)
        
    def _load_rules(self, path):
        with open(path, 'r') as f:
            return yaml.safe_load(f)
            
    def process_packet(self, pkt):
        if pkt.haslayer("NAS"):
            nas = pkt["NAS"]
            device_id = nas.device_id.decode().strip('\x00')
            self.counters[device_id] += 1
            
            # Check thresholds
            for rule in self.rules:
                if self.counters[device_id] > rule["threshold"]:
                    print(f"🚨 [ALERT] {device_id}: {self.counters[device_id]} requests (Threshold: {rule['threshold']})")
                    self.counters[device_id] = 0  # Reset counter