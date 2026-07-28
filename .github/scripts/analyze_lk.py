import sys
import struct
import os

def find_string(data, s):
    # Search for the string followed by a null terminator
    return data.find(s.encode() + b'\x00')

def get_function_prologue(data, search_offset):
    # Search backwards from the string's location to find a common ARM64 function prologue.
    # We'll look for common prologue patterns within a reasonable distance (e.g., 0x100 bytes).
    # Common ARM64 prologues often involve saving registers (STP) or conditional branches (CBZ).
    
    # Align search_offset to 4 bytes for instruction boundaries
    current_offset = search_offset & ~3
    
    # Search backwards for a function prologue signature
    for i in range(0, min(current_offset, 0x100), 4): # Search up to 0x100 bytes back
        pos = current_offset - i
        if pos < 0: continue
        
        instruction = data[pos:pos+4]
        if len(instruction) < 4: continue
        
        # STP X29, X30, [SP, #offset]!
        # Common patterns: fd 7b be a9, fd 7b bf a9, fd 7b ba a9
        if instruction in [b'\xfd\x7b\xbe\xa9', b'\xfd\x7b\xbf\xa9', b'\xfd\x7b\xba\xa9']:
            return pos
        
        # CBZ W0, #offset (often seen at the start of sec_get_vfy_policy)
        # Instruction format: 0x34xxxxxx
        # We check for the upper byte and lower 5 bits for CBZ W0
        if (struct.unpack('<I', instruction)[0] & 0xFF00001F) == 0x34000000:
            # This is a CBZ W0 instruction. It's a strong candidate for a function start.
            return pos
            
    # If no common prologue found, try to find the nearest instruction that looks like a function start
    # This is a heuristic and might not always be accurate without full disassembly
    for i in range(0, min(current_offset, 0x20), 4): # Search a smaller window for any instruction
        pos = current_offset - i
        if pos < 0: continue
        # A simple heuristic: if the instruction is not a NOP and not a branch to self, it might be a start
        # This is very weak, but better than nothing if specific prologues aren't found.
        instruction = data[pos:pos+4]
        if len(instruction) == 4 and instruction != b'\x1f\x20\x03\xd5': # Not a NOP
            return pos
            
    return None

def extract_pattern(data, offset, length=32):
    # Extract 32 bytes (8 instructions) for a unique pattern
    # Ensure we don't read beyond the file length
    end_offset = min(offset + length, len(data))
    return data[offset:end_offset].hex(' ')

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
        'boot_state',
        'avb_slot_verify',
        'sec_otp_ver_get'
    ]
    
    for target in targets:
        str_off = find_string(data, target)
        if str_off == -1:
            continue
            
        func_start = get_function_prologue(data, str_off)
        if func_start is not None:
            pattern = extract_pattern(data, func_start)
            results[target] = pattern
        else:
            print(f"Warning: Could not find function prologue for {target} near string offset {hex(str_off)}.")
            
    if not results:
        print("Warning: No patterns found via string XREFs. Consider manual analysis.")
        
    # Generate the Device config block
    device_config = f"    Device(\n        '{product_name}',\n        '{product_name} Auto-Generated',\n        {{\n"
    
    for name, pattern in results.items():
        # MOV W0, #0; RET (8 bytes)
        # Pad with NOPs to match pattern length (32 bytes = 8 instructions)
        # NOP instruction: 1f 20 03 d5
        replacement_hex = "00 00 80 52 c0 03 5f d6" # MOV W0, #0; RET
        
        # Calculate how many NOPs are needed
        current_len_bytes = len(bytes.fromhex(replacement_hex.replace(' ', '')))
        nops_needed_bytes = 32 - current_len_bytes
        
        if nops_needed_bytes < 0:
            print(f"Error: Replacement for {name} is longer than pattern length. This should not happen with default values.")
            replacement = replacement_hex # Use only the replacement without padding
        else:
            nop_padding = "1f 20 03 d5 " * (nops_needed_bytes // 4) # Each NOP is 4 bytes
            replacement = (replacement_hex + " " + nop_padding).strip()
            
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

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 analyze_lk.py <lk_file> <product_name>")
        sys.exit(1)
    analyze(sys.argv[1], sys.argv[2])
