from cffi import FFI

ffi = FFI()

# Define DPDK functions
ffi.cdef("""
    int rte_eal_init(int argc, char **argv);
    void rte_exit(int exit_code, const char *format, ...);
""")

# Load DPDK library
dpdk = ffi.dlopen("libdpdk.so")

def initialize_dpdk():
    args = ["progname", "-l", "0-1", "--log-level=8"]
    argv = [ffi.new("char[]", arg.encode()) for arg in args]
    ret = dpdk.rte_eal_init(len(args), ffi.new("char *[]", argv))
    if ret < 0:
        dpdk.rte_exit(1, "DPDK init failed")