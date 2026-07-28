import sys
import struct
import os
import re

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
    
    # =====================================================================
    # COMPLETE list of ALL patch targets matching upstream Plato device.
    # Each target maps to the string(s) to search for in the binary,
    # the known replacement pattern, and the description.
    # =====================================================================
    targets_info = [
        # 1. sec_get_vfy_policy — Don't enforce secure boot policy
        {
            'name': 'sec_get_vfy_policy',
            'strings': ['sec_get_vfy_policy'],
            'replacement': 'e0 03 1f 2a c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
            'description': "Don't enforce secure boot policy"
        },
        # 2. force_green_state — Force boot state to green
        {
            'name': 'force_green_state',
            'strings': ['green', 'boot state', 'green_state'],
            'replacement': '28 03 00 b0 1f 49 02 b9 c0 03 5f d6',
            'description': 'Force boot state to always be set to green'
        },
        # 3. bypass_security_control — Skip security error branch
        {
            'name': 'bypass_security_control',
            'strings': ['security_control', 'security error', 'Security'],
            'replacement': 'e8 0b 40 b9 1f 0d 00 71 1f 20 03 d5',
            'description': 'Skip security error branch - always execute commands'
        },
        # 4. bypass_cmd_erase_lock_control — Skip erase lock check
        {
            'name': 'bypass_cmd_erase_lock_control',
            'strings': ['erase', 'erase_lock', 'cmd_erase'],
            'replacement': 'a8 1f 40 b9 1f 05 00 71 1f 20 03 d5',
            'description': 'Skip lock error branch - always execute erase'
        },
        # 5. bypass_cmd_flash_control — Skip flash lock check
        {
            'name': 'bypass_cmd_flash_control',
            'strings': ['flash', 'flash_lock', 'cmd_flash'],
            'replacement': 'e8 07 40 b9 1f 05 00 71 09 00 10 d4',
            'description': 'Skip lock error branch - always execute flash'
        },
        # 6. spoof_get_sboot_state — Force sboot state
        {
            'name': 'spoof_get_sboot_state',
            'strings': ['sboot', 'secure boot state', 'get_sboot'],
            'replacement': '48 04 80 52 08 00 80 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5 c9',
            'description': 'Force sboot state to always be ATTR_SBOOT_ONLY_ENABLE_ON_SCHP'
        },
        # 7. spoof_lock_state — Force lock state to LKS_LOCK
        {
            'name': 'spoof_lock_state',
            'strings': ['lock_state', 'lock state', 'get_lock'],
            'replacement': '88 00 80 52 08 00 80 b9 00 00 80 52 c0 03 5f d6 1f 20 03 d5',
            'description': 'Force lock state to always be LKS_LOCK'
        },
        # 8. dont_relock_seccfg — Prevent LK from relocking seccfg
        {
            'name': 'dont_relock_seccfg',
            'strings': ['relock', 'relock_seccfg', 'dont_relock'],
            'replacement': '00 00 80 52 c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
            'description': 'Prevent LK from relocking seccfg'
        },
        # 9. sec_otp_ver_get — Force OTP verification to succeed
        {
            'name': 'sec_otp_ver_get',
            'strings': ['sec_otp_ver_get', 'otp_ver', 'otp_verification'],
            'replacement': 'e0 03 1f 2a c0 03 5f d6 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5',
            'description': 'Force otp verification to always return success'
        },
    ]
    
    print(f"Analyzing {file_path} ({len(data)} bytes)...")
    
    for target in targets_info:
        name = target['name']
        
        # Skip if we already found this patch
        if name in results:
            continue
        
        # Try each string variant for this target
        found = False
        for search_str in target['strings']:
            str_off = find_string(data, search_str)
            if str_off == -1:
                continue
            
            func_start = get_function_prologue(data, str_off)
            if func_start is not None:
                pattern = extract_pattern(data, func_start)
                results[name] = {
                    'pattern': pattern,
                    'replacement': target['replacement'],
                    'description': target['description']
                }
                print(f"  [+] Found: {name} (string '{search_str}' at offset {hex(str_off)})")
                found = True
                break
            else:
                print(f"  [!] Could not find function prologue for {name} near string '{search_str}' at offset {hex(str_off)}")
        
        if not found:
            print(f"  [-] Not found: {name} (none of the strings matched)")
    
    if not results:
        print("\nWarning: No patterns found via string XREFs.")
        print("The binary may not contain any of the expected string markers.")
        print("Possible reasons:")
        print("  - The binary is not an LK/bootloader image")
        print("  - The strings have been obfuscated or removed")
        print("  - The device uses a different boot chain architecture")
        return
    
    print(f"\nFound {len(results)} patch target(s):")
    for name in results:
        print(f"  - {name}")
    
    # Generate clean codename
    codename = product_name.lower().replace(' ', '_').replace('-', '_').replace("'", '').replace('.', '')
    # Remove duplicate underscores
    codename = re.sub(r'_+', '_', codename).strip('_')

    # Generate the Device entry using POSITIONAL arguments (matching upstream pattern)
    # FIX: Third positional arg is the stages dict (NOT 'patches')
    # FIX: Add cert_bypass=CertBypass.WRAP (matching upstream)
    device_config = f"    Device(\n"
    device_config += f"        '{codename}',\n"
    device_config += f"        '{product_name}',\n"
    device_config += f"        " + "{\n"
    
    for name, patch_data in results.items():
        device_config += f"            '{name}': PatchStage(\n"
        device_config += f"                '{name}',\n"
        device_config += f"                pattern='{patch_data['pattern']}',\n"
        device_config += f"                replacement='{patch_data['replacement']}',\n"
        device_config += f"                match_mode=MatchMode.ALL,\n"
        device_config += f"                description='{patch_data['description']}',\n"
        device_config += f"            ),\n"
    
    device_config += "        },\n"
    device_config += f"        cert_bypass=CertBypass.WRAP\n"
    device_config += f"    ),"
    
    print("\n--- GENERATED CONFIG ---")
    print(device_config)
    print("--- END CONFIG ---")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 analyze_lk.py <lk_file> <product_name>")
        print("Example: python3 analyze_lk.py bl2_ext.bin 'Xiaomi 12T'")
        sys.exit(1)
    analyze(sys.argv[1], sys.argv[2])
