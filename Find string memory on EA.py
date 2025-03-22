import ctypes
import psutil
import win32api
import win32process
import win32con

PROCESS_ALL_ACCESS = 0x1F0FFF
TARGET_PROCESS_NAME = "EALauncher.exe" 
TARGET_STRING = "shoushou1106"  # Change this to the target string

def get_process_pid(name):
    """ Get the PID of the target process """
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == name.lower():
            return proc.info['pid']
    return None

def read_process_memory(process, address, size):
    """ Read memory from a process """
    buffer = ctypes.create_string_buffer(size)
    bytesRead = ctypes.c_size_t()
    ctypes.windll.kernel32.ReadProcessMemory(process, address, buffer, size, ctypes.byref(bytesRead))
    return buffer.raw

def scan_memory(pid, target_string):
    """ Scan process memory to find the target string """
    process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not process:
        print("Failed to open process. Check permissions.")
        return

    memory_regions = []
    SYSTEM_INFO = ctypes.windll.kernel32.SYSTEM_INFO()
    ctypes.windll.kernel32.GetSystemInfo(ctypes.byref(SYSTEM_INFO))

    address = SYSTEM_INFO.lpMinimumApplicationAddress
    max_address = SYSTEM_INFO.lpMaximumApplicationAddress

    while address < max_address:
        try:
            mbi = win32process.VirtualQueryEx(process, address)
            if mbi.State == win32con.MEM_COMMIT and mbi.Protect in (win32con.PAGE_READWRITE, win32con.PAGE_READONLY):
                memory_regions.append((address, mbi.RegionSize))
            address += mbi.RegionSize
        except:
            address += 0x1000  # Skip invalid memory regions

    print(f"Found {len(memory_regions)} memory regions. Starting scan...")

    found_addresses = []
    for base_addr, size in memory_regions:
        try:
            data = read_process_memory(process, base_addr, size)
            if target_string.encode() in data:
                offset = data.index(target_string.encode())
                found_address = base_addr + offset
                found_addresses.append(found_address)
                print(f"Found '{target_string}' at address: 0x{found_address:X}")
        except:
            continue

    ctypes.windll.kernel32.CloseHandle(process)
    return found_addresses

def read_memory_values(pid, addresses):
    """ Read memory values at specific addresses """
    process = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    for addr in addresses:
        try:
            data = read_process_memory(process, addr,16)  # Read 16 bytes
            print(f"Memory at 0x{addr:X}: {data.hex()}")
        except:
            print(f"Failed to read memory at 0x{addr:X}")
    ctypes.windll.kernel32.CloseHandle(process)

# Get the EA process PID
pid = get_process_pid(TARGET_PROCESS_NAME)
if pid:
    print(f"Found process {TARGET_PROCESS_NAME}, PID: {pid}")
    addresses = scan_memory(pid, TARGET_STRING)
    if addresses:
        read_memory_values(pid, addresses)
else:
    print("EA process not found. Check process name.")
