import sys
import struct
import re

def find_string(data, s):
    return data.find(s.encode() + b'\x00')

def get_function_prologue(data, start_offset):
    # Search backwards for common ARM64 function prologues
    # We look up to 0x1000 bytes back
    current = start_offset & ~3
    for i in range(0, 0x1000, 4):
        pos = current - i
        if pos < 0: break
        
        chunk = data[pos:pos+4]
        # Common ARM64 prologues
        # STP X29, X30, [SP, #-0x...]!
        if chunk == b'\xfd\x7b\xbe\xa9': # STP X29, X30, [SP,#-0x20]!
            return pos
        if chunk == b'\xfd\x7b\xbf\xa9': # STP X29, X30, [SP,#-0x10]!
            return pos
        if chunk == b'\xfd\x7b\xba\xa9': # STP X29, X30, [SP,#-0x60]!
            return pos
        # CBZ W0, ... (Common for sec_get_vfy_policy)
        if (struct.unpack("<I", chunk)[0] & 0xFF00001F) == 0x34000000:
            # This is a CBZ W0, check if it looks like a function start
            return pos
            
    return None

def extract_pattern(data, offset, length=32):
    # Extract 32 bytes (8 instructions) for a unique pattern
    return data[offset:offset+length].hex(' ')

def analyze(file_path, product_name):
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return
        
    with open(file_path, 'rb') as f:
        data = f.read()
    
    results = {}
    # Prioritize sec_get_vfy_policy as it's the main target
    targets = [
        'sec_get_vfy_policy',
        'get_sboot_state',
        'get_lock_state',
        'seccfg',
        'boot_state'
    ]
    
    for target in targets:
        str_off = find_string(data, target)
        if str_off == -1:
            continue
            
        func_start = get_function_prologue(data, str_off)
        if func_start:
            pattern = extract_pattern(data, func_start)
            results[target] = pattern
            
    if not results:
        # Fallback: search for common known patterns if strings are missing or obfuscated
        # (Though LK usually has these strings)
        print("Warning: No patterns found via string XREFs.")
        
    # Generate the Device config block
    device_config = f"    Device(\n        '{product_name}',\n        '{product_name} Auto-Generated',\n        {{\n"
    
    for name, pattern in results.items():
        # MOV W0, #0; RET (8 bytes)
        # Pad with NOPs to match pattern length (32 bytes = 8 instructions)
        replacement = "00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5"
        
        device_config += f"            '{name}': PatchStage(\n"
        device_config += f"                '{name}',\n"
        device_config += f"                '{pattern}',\n"
        device_config += f"                '{replacement}',\n"
        device_config += f"                match_mode=MatchMode.ALL\n"
        device_config += f"            ),\n"
    
    # If no patterns found, we still output the structure but it might be empty
    device_config += "        }\n    ),"
    
    print("--- GENERATED CONFIG ---")
    print(device_config)
    print("--- END CONFIG ---")

import os
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 analyze_lk.py <lk_file> <product_name>")
        sys.exit(1)
    analyze(sys.argv[1], sys.argv[2])
