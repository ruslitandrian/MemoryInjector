import ctypes
import time
import sys
from ctypes import wintypes
import pymem
import time
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox


def allocate_newmem():
    global pm
    # start address to search for free memory
    base_address = 0x13FF10000
    end_address = 0x16FFFFFFF
    # Get process ID
    pid = pm.process_id
    if not pid:
        
        messagebox.showinfo("Warning","Game not found")
        return None

    # Open the process
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        messagebox.showinfo("Warning",f"Failed to open process with pid {pid}")
        return None

    # Attempt to allocate memory starting at 0x13FFF0000
    allocated_address = None
    current_address = base_address

    # max_attempts = 100  # Avoid infinite loop

    while current_address < end_address:
        allocated_address = kernel32.VirtualAllocEx(h_process,ctypes.c_void_p(current_address),PAGE_SIZE,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE)

        if allocated_address:
            # print(f"Successfully allocated at {hex(current_address)}")
            return h_process, allocated_address

        current_address += PAGE_SIZE  # increase the address to 4096 bytes for next try

    if allocated_address is None:
        messagebox.showinfo("Warning","Failed to allocate the new memory")
        kernel32.CloseHandle(h_process)
        return None
def free_memory(h_process, allocated_address): #free up the memory 
    free_success = kernel32.VirtualFreeEx(h_process, allocated_address, 0, MEM_RELEASE)
     # Cleanup
    kernel32.CloseHandle(h_process)
    return free_success
def find_matched_address(pattern, start_address, end_address): # Find the memory address that matched the byte pattern
    scan_size = 0x1000
    for addr in range(start_address, end_address, scan_size):  
        try:
            # Read the memory
            memory_dump = pm.read_bytes(addr, scan_size)

            # Find the pattern
            pattern_offset = memory_dump.find(pattern)

            if pattern_offset != -1:
                match_address = addr + pattern_offset
                return match_address
        except pymem.exception.MemoryReadError:
            continue  # ignore invalid address
    return None
def mov_eax_memory_bytes(instruction_address, target_address): # get the bytes of the opcode "mov eax,[target_address]"
    # Opcode
    opcode = 0x8B
    # ModR/M byte
    modrm = 0x05
    # Instruction length (fixed at 6 bytes)
    instruction_length = 6
    # Calculate displacement
    displacement = target_address - (instruction_address + instruction_length)
    # Convert displacement to 4-byte little-endian
    displacement_bytes = displacement.to_bytes(4, byteorder='little', signed=False)
    # Combine into byte sequence
    machine_code = bytes([opcode, modrm]) + displacement_bytes
    
    return machine_code
def calculate_jmp_bytes(opcode_addr: int, target_addr: int) -> str: # get the byte of opcode "opcode_address: jmp target_address"

    instruction_length = 5
    rip = opcode_addr + instruction_length
    offset = target_addr - rip
    
    if offset > 0x7FFFFFFF or offset < -0x80000000:
        raise ValueError(f"Offset {hex(offset)} exceeds 32-bit signed range (±2 GB). Use an indirect jump (e.g., FF 25).")
    
    offset_bytes = offset.to_bytes(4, byteorder='little', signed=True)
    jmp_bytes = b'\xE9' + offset_bytes
    return jmp_bytes
def on_window_close():
    global pm,matchtime_address,inject_address,ori_data
    if not inject_flag:
        exit(1)
    try:
        pm = pymem.Pymem(process_name)
    except:
        exit(1)
    try:
        pm.write_float(matchtime_address, 0.0)
        pm.write_bytes(inject_address, ori_data, len(ori_data))
    except:
        exit(1)
    pm.close_process()
    free_memory(h_process,newmem_address)
    windows.destroy()
    sys.exit()
def ON_action():
    global inject_flag,pm, matchtime_address
    if not inject_flag:
        ON_button.config(state="disabled")
        INJECT_button.config(state="active")
        status_label.config(text="Not injected", fg="red")
        messagebox.showinfo("Warning","The game not injected yet, please inject the game")
        return
    try:
        pm = pymem.Pymem(process_name)
    except:
        ON_button.config(state="disabled")
        INJECT_button.config(state="active")
        status_label.config(text="Not injected", fg="black")
        messagebox.showinfo("Warning","Game not found")
        inject_flag = False
        return
    try:
        pm.write_float(matchtime_address, 166500.0)
    except:
        ON_button.config(state="disabled")
        INJECT_button.config(state="active")
        status_label.config(text="Not injected", fg="red")
        messagebox.showinfo("Warning","The game not injected yet, please inject the game")
        return
    OFF_button.config(state="active")
    ON_button.config(state="disabled")
    INJECT_button.config(state="disabled")
    status_label.config(text="Enabled", fg="green")
    pm.close_process()
def OFF_action():
    global inject_flag, pm,matchtime_address

    
    
    if not inject_flag:
        OFF_button.config(state="disabled")
        INJECT_button.config(state="active")
        status_label.config(text="Not injected", fg="black")
        messagebox.showinfo("Warning","The game not injected yet, please inject the game")
        return
    
    try:
        pm = pymem.Pymem(process_name)
    except:
        OFF_button.config(state="disabled")
        INJECT_button.config(state="active")
        status_label.config(text="Not injected", fg="black")
        messagebox.showinfo("Warning","Game not found")
        inject_flag = False
        return
    try:
        pm.write_float(matchtime_address, 0.0)
    except:
        OFF_button.config(state="disabled")
        INJECT_button.config(state="active")
        status_label.config(text="Not injected", fg="black")
        messagebox.showinfo("Warning","The game not injected yet, please inject the game")
        return
    pm.close_process()
    ON_button.config(state="active")
    OFF_button.config(state="disabled")
    INJECT_button.config(state="disabled")
    status_label.config(text="Disabled", fg="red")
def inject_game():
    global h_process, newmem_address, inject_flag,pm, newmem_data, inject_address, inject_data, ori_data, matchtime_address, jump_address, end_inject_address

    inject_flag = False

    # initial needed AoB for inject the game
    inject_pattern = b"\x8B\x44\x24\x40\x89\x44\x24\x40" # array of bytes pattern for searching the inject address

    newmem_data = (b"\x83\xf8\x00"   # array of bytes of the inject code in new memmory
                b"\x0f\x84\x04\x00\x00\x00"
                b"\x89\x44\x24\x40"
                b"\x8b\x44\x24\x40"
                b"\x89\x44\x24\x40")

    inject_data = b"\x90\x90\x90" # array of bytes of the inject code in current memmory

    ori_data =  b"\x8b\x44\x24\x40\x89\x44\x24\x40" # array of bytes of the original code in current memmory

    try:
        pm = pymem.Pymem(process_name)
    except:
        messagebox.showinfo("Warning","Game not found")
        inject_flag = False
        return
    
    # Find base address of a process - start address and end address
    start_address, end_address = get_base_address()
    if not start_address:
        messagebox.showinfo("Warning",f"Can not get base address of {process_name}")
        inject_flag = False
        return
    print(f"Base address of FL_2023.exe -> Start address {hex(start_address)} End address {hex(end_address)}")

    # find the inject memory address by pattern b"\x8B\x44\x24\x40\x89\x44\x24\x40"
    inject_address = find_matched_address(inject_pattern,start_address,end_address) 
    if not inject_address:
        messagebox.showinfo("Warning","Can not find the inject address, please close the game and try again")
        inject_flag = False
        return
    print(f"Injected address {hex(inject_address)}")

    # Allocate new memory nearby the base address of the process
    result = allocate_newmem()
    if not result:
        messagebox.showinfo("Warning","Can not allocated new memory, please close the game and try again")
        inject_flag = False
        return
    
    h_process, newmem_address = result

    jump_address = inject_address + 0x8
    matchtime_address = newmem_address + 0x100
    end_inject_address = newmem_address + 0x1B

    newmem_data = mov_eax_memory_bytes(newmem_address, matchtime_address) + newmem_data
    newmem_data = newmem_data + calculate_jmp_bytes(end_inject_address,jump_address)
    inject_data = calculate_jmp_bytes(inject_address,newmem_address) + inject_data

    print(f"New memory region address {hex(newmem_address)}")
    print(f"End memory region address {hex(end_inject_address)}")
    print(f"Match time address {hex(matchtime_address)}")

    print(f"New memory Aob {newmem_data}")
    print(f"Inject Aob {inject_data}")
    print(f"Jump back address {hex(jump_address)}")
    
    

    try:
        pm.write_bytes(newmem_address, newmem_data, len(newmem_data))
        pm.write_float(matchtime_address, 0.0)
        time.sleep(1)
        pm.write_bytes(inject_address, inject_data, len(inject_data))
        pm.close_process()
    except:
        messagebox.showinfo("Warning","Can not inject the game, please close the game and try again")
        inject_flag = False
        return
    inject_flag = True
    ON_button.config(state="active")
    OFF_button.config(state="disabled")
    INJECT_button.config(state="disabled")
    status_label.config(text="Injected", fg="green")
def get_base_address():
    try:
        base_address = pm.process_base.lpBaseOfDll
        end_address = base_address + pm.process_base.SizeOfImage
        return base_address, end_address
    except Exception as e:
        print(f"Can not get base address of {process_name}")
        return None,None

# Load Windows API libraries for allocating new memory
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Define function prototypes 
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

kernel32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
kernel32.VirtualFreeEx.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
#Constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
MEM_RELEASE = 0x8000
PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_SIZE = 0x1000  # 4096 bytes

inject_flag = False
process_name = "FL_2023.exe"

windows = tk.Tk()
windows.title("FL 2023")
windows.protocol("WM_DELETE_WINDOW", on_window_close)

screen_width = windows.winfo_screenwidth()
screen_height = windows.winfo_screenheight()
window_width = 120
window_height = 140
x = (screen_width - window_width) // 2
y = (screen_height - window_height) // 2

# Set the window size and position
windows.geometry(f"{window_width}x{window_height}+{x}+{y}")
windows.resizable(False, False)  # Prevent resizing in both dimensions
windows.wm_attributes("-toolwindow", "1")

ON_button = tk.Button(windows, text="ON", command=ON_action, width=5)
ON_button.grid(row=1, padx=35,pady=7,sticky="w")  # Added padx for extra spacing

OFF_button = tk.Button(windows, text="OFF", command=OFF_action, width=5)
OFF_button.grid(row=2, padx=35,pady=7,sticky="w")  # Added padx for extra spacing

INJECT_button = tk.Button(windows, text="INJECT", command=inject_game)
INJECT_button.grid(row=3, padx=35,sticky="w")  # Added padx for extra spacing

OFF_button.config(state="disabled")
ON_button.config(state="disabled")
status_label = tk.Label(windows, text="Not injected", fg="red")

status_label.grid(row=4, padx= 31, pady=5,sticky="w")

if __name__ == "__main__":
    windows.mainloop()



