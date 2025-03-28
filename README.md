# 5G-IoT-NIDS  
A lightweight, rule-based Network Intrusion Detection System (NIDS) for securing IoT devices on 5G networks.

## Features
- **5G NAS Protocol Parsing**: Custom Scapy layers for parsing 5G NAS packets.
- **Rule-Based Detection**: Configurable YAML-based rules for detecting anomalies.
- **Traffic Simulation**: Simulate legitimate and malicious 5G traffic using Scapy.
- **DPDK Integration**: High-performance packet processing with DPDK (Data Plane Development Kit).
- **Real-Time Monitoring**: Detect and alert on suspicious activity in real-time.

## Project Structure
```
.gitignore               # Ignored files and directories
README.md                # Project documentation
.github/workflows/       # GitHub workflows (CI/CD)
docs/                    # Documentation files
rules/                   # Detection rules in YAML format
samples/                 # Sample data
scripts/                 # Traffic simulation scripts
src/                     # Source code for the NIDS
  ├── capture/           # Packet capture modules
  ├── protocols/         # Custom protocol definitions
  ├── rule_engine.py     # Rule processing engine
  ├── dpdk_init.py       # DPDK initialization
  ├── main.py            # Main entry point for the NIDS
tests/                   # Test cases
```

## Quick Start
1. Clone the repository:
   ```bash
   git clone https://github.com/45-nobbie/5G-IoT-NIDS.git
   cd 5G-IoT-NIDS
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the NIDS:
   ```bash
   python src/main.py
   ```

4. Simulate traffic:
   ```bash
   python scripts/simulate_traffic.py
   ```

## Key Components
### Protocol Parsing
Custom Scapy layers are defined in [`src/protocols/fg_nas.py`](src/protocols/fg_nas.py) to parse 5G NAS packets. These layers are bound to UDP port 5000 in [`src/protocols/__init__.py`](src/protocols/__init__.py).

### Rule Engine
The rule engine in [`src/rule_engine.py`](src/rule_engine.py) processes packets against YAML-based rules, such as those in [`rules/5g/nas_flood.yaml`](rules/5g/nas_flood.yaml).

### Packet Capture
The packet capture module in [`src/capture/scapy_capture.py`](src/capture/scapy_capture.py) uses Scapy to sniff packets and pass them to the rule engine.

### Traffic Simulation
The script [`scripts/simulate_traffic.py`](scripts/simulate_traffic.py) generates both legitimate and malicious 5G NAS traffic for testing purposes.

### DPDK Integration
High-performance packet processing is initialized in [`src/dpdk_init.py`](src/dpdk_init.py) and [`src/dpdk_interface.py`](src/dpdk_interface.py).

## Rules
Detection rules are defined in YAML format under the `rules/` directory. For example:
- [`rules/5g/nas_flood.yaml`](rules/5g/nas_flood.yaml): Detects 5G NAS flood attacks.
- [`rules/5g/nas_rules.yaml`](rules/5g/nas_rules.yaml): Defines thresholds for excessive registration requests.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

