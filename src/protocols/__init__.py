# src/protocols/__init__.py
# This file makes the directory a Python package.
# Import your custom layers here so Scapy can find them.

import logging
logger = logging.getLogger(__name__)

try:
    from .coap import CoAP
    logger.info("Successfully imported CoAP protocol layer.")
except ImportError as e:
    logger.warning(f"Could not import CoAP protocol layer: {e}")

# Example (Add these back as you implement them):
# try:
#     from .nas import NASLayer
#     logger.info("Successfully imported NAS protocol layer.")
# except ImportError as e:
#     logger.warning(f"Could not import NAS protocol layer: {e}")

# try:
#     from .ngap import NGAPSCTPPayload # Import the top-level NGAP wrapper
#     logger.info("Successfully imported NGAP protocol layer.")
# except ImportError as e:
#     logger.warning(f"Could not import NGAP protocol layer: {e}")

# try:
#     from .mqtt import MQTT
#     logger.info("Successfully imported MQTT protocol layer.")
# except ImportError as e:
#     logger.warning(f"Could not import MQTT protocol layer: {e}")

logger.info("Custom protocol definitions initialized.")