import sys
import struct
import os

def find_string(data, s):
    # Search for the string followed by a null terminator
    return data.find(s.encode() + b'\x00')

def get_function_prologue(data, search_offset):
    # Search backwards from the string's location to find a common ARM64 function prologue.
    # We look for common prologue patterns within a reasonable distance (0x100 bytes).
    
    # Align search_offset to 4 bytes for instruction boundaries
    current_offset = search_offset & ~3
    
    # Search backwards for a function prologue signature
    for i in range(0, min(current_offset, 0x100), 4):
        pos = current_offset - i
        if pos < 0:
            continue
        
        instruction = data[pos:pos+4]
        if len(instruction) < 4:
            continue
        
        # STP X29, X30, [SP, #offset]!
        if instruction in [b'\xfd\x7b\xbe\xa9', b'\xfd\x7b\xbf\xa9', b'\xfd\x7b\xba\xa9']:
            return pos
        
        # CBZ W0, #offset
        if (struct.unpack('<I', instruction)[0] & 0xFF00001F) == 0x34000000:
            return pos
            
    # Fallback heuristic search window
    for i in range(0, min(current_offset, 0x20), 4):
        pos = current_offset - i
        if pos < 0:
            continue
        instruction = data[pos:pos+4]
        if len(instruction) == 4 and instruction != b'\x1f\x20\x03\xd5':
            return pos
            
    return None

def extract_pattern(data, offset, length=32):
    # Extract 32 bytes (8 instructions) for a unique pattern
    end_offset = min(offset + length, len(data))
    return data[offset:end_offset].hex(' ')

def analyze(file_path, product_name):
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return
        
    with open(file_path, 'rb') as f:
        data = f.read()
    
    results = {}
    
    # Patch replacements and descriptions matching the target repository specifications
    targets_info = {
        'sec_get_vfy_policy': {
            'description': 'Don\'t enforce secure boot policy',
            'replacement': 'e0 03 1f 2a c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5'
        },
        'get_sboot_state': {
            'description': 'Force secure boot state to enabled',
            'replacement': '20 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5'
        },
        'get_lock_state': {
            'description': 'Force bootloader lock state to unlocked',
            'replacement': '00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5'
        },
        'seccfg': {
            'description': 'Bypass seccfg write protection',
            'replacement': '1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5'
        },
        'boot_state': {
            'description': 'Force boot state to always be set to green',
            'replacement': '28 03 00 b0 1f 49 02 b9 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5'
        },
        'avb_slot_verify': {
            'description': 'Allow AVB verification errors',
            'replacement': '00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5'
        },
        'sec_otp_ver_get': {
            'description': 'Bypass OTP verification',
            'replacement': '00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5'
        }
    }
    
    for target, info in targets_info.items():
        str_off = find_string(data, target)
        if str_off == -1:
            continue
            
        func_start = get_function_prologue(data, str_off)
        if func_start is not None:
            pattern = extract_pattern(data, func_start)
            results[target] = {
                'pattern': pattern,
                'replacement': info['replacement'],
                'description': info['description']
            }
        else:
            print(f"Warning: Could not find function prologue for {target} near string offset {hex(str_off)}.")
            
    if not results:
        print("Warning: No patterns found via string XREFs.")
        
    codename = product_name.lower().replace(' ', '_').replace('-', '_')

    device_config = f"    Device(\n        name='{product_name}',\n        codename='{codename}',\n        patches={{\n"
    
    for name, patch_data in results.items():
        device_config += f"            '{name}': PatchStage(\n"
        device_config += f"                name='{name}',\n"
        device_config += f"                pattern='{patch_data['pattern']}',\n"
        device_config += f"                replacement='{patch_data['replacement']}',\n"
        device_config += f"                match_mode=MatchMode.ALL,\n"
        device_config += f"                description='{patch_data['description']}',\n"
        device_config += f"            ),\n"
    
    device_config += "        }\n    ),"
    
    print("--- GENERATED CONFIG ---")
    print(device_config)
    print("--- END CONFIG ---")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 analyze_lk.py <lk_file> <product_name>")
        sys.exit(1)
    analyze(sys.argv[1], sys.argv[2])
