from cffi import FFI
import sys

ffi = FFI()

# Define DPDK functions and constants
ffi.cdef("""
    int rte_eal_init(int argc, char **argv);
    void rte_exit(int exit_code, const char *format, ...);
    struct rte_mbuf;
    uint16_t rte_eth_rx_burst(uint8_t port_id, uint16_t queue_id,
                             struct rte_mbuf **rx_pkts, const uint16_t nb_pkts);
""")

# Load DPDK library
try:
    dpdk = ffi.dlopen("libdpdk.so")
except OSError as e:
    print(f"Error loading DPDK: {e}")
    sys.exit(1)

def initialize_dpdk():
    eal_args = ["progname",  # Dummy first argument
                "-l", "0-1",  # Use cores 0 and 1
                "--log-level=8"]
    
    # Convert args to C-friendly format
    argc = len(eal_args)
    argv = [ffi.new("char[]", arg.encode()) for arg in eal_args]
    
    # Initialize DPDK
    ret = dpdk.rte_eal_init(argc, ffi.new("char *[]", argv))
    if ret < 0:
        dpdk.rte_exit(1, "DPDK initialization failed")

if __name__ == "__main__":
    initialize_dpdk()
    print("✅ DPDK initialized successfully!")