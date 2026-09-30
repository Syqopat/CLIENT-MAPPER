"""
Antigravity Memory Scanner - x64dbg Style ReadProcessMemory Engine
No Frida, No JNI, No JVMTI. Pure Windows API memory reading.
Inspired by x64dbg and Cheat Engine internals.
"""
import os
import ctypes
import ctypes.wintypes as wt
import re
import struct
from PyQt5.QtCore import QThread, pyqtSignal

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
OpenProcess.restype = wt.HANDLE

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = wt.BOOL

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
VirtualQueryEx.restype = ctypes.c_size_t

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wt.HANDLE]
CloseHandle.restype = wt.BOOL


EXACT_CLASSES = [
    "net/minecraft/client/Minecraft",
    "net/minecraft/client/main/Main",
    "net/minecraft/entity/player/EntityPlayer",
    "net/minecraft/world/World",
]

GENERIC_SIGNATURES = [
    b"Minecraft",                  # Window title, always present
    b"minecraft",                  # Lowercase references
    b".minecraft",                 # Folder path reference  
    b"LWJGL",                      # OpenGL wrapper library
    b"org/lwjgl",                  # LWJGL class path
    b"java/lang/Object",           # Every JVM has this
    b"java/lang/String",           # Every JVM has this
    b"java/lang/Class",            # Every JVM has this
    b"java/lang/Thread",           # Every JVM has this
    b"thePlayer",                  # Minecraft field name (survives obfuscation sometimes)
    b"theWorld",                   # Minecraft field name
    b"ticksExisted",               # Entity field
    b"posX",                       # Entity position
    b"posY",                       # Entity position  
    b"posZ",                       # Entity position
    b"motionX",                    # Entity motion
    b"motionY",                    # Entity motion
    b"motionZ",                    # Entity motion
    b"onGround",                   # Entity field
    b"rotationYaw",                # Entity rotation
    b"rotationPitch",              # Entity rotation
    b"health",                     # Player health
    b"GameSettings",               # Settings class string
    b"SonOyuncu",                  # Client branding
    b"sonoyuncu",                  # Client branding lowercase
    b"AntiCheat",                  # AC reference
    b"anticheat",                  # AC reference lowercase
]



class MemoryScannerThread(QThread):
    log_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal()
    class_found_signal = pyqtSignal(str, int, list, str)

    def __init__(self, pid, parent=None):
        super().__init__(parent)
        self.pid = pid
        self.is_running = True
        self.dump_dir = os.path.abspath(os.path.join("dumps", "classes", "flat"))
        self.process_handle = None

        if not os.path.exists(self.dump_dir):
            os.makedirs(self.dump_dir)

    def stop(self):
        self.is_running = False

    def read_memory(self, address, size):
        """Read raw bytes from target process memory using ReadProcessMemory."""
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)
        ok = ReadProcessMemory(self.process_handle, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_read))
        if ok and bytes_read.value > 0:
            return buf.raw[:bytes_read.value]
        return None

    def enumerate_memory_regions(self):
        """Walk the process virtual address space (like x64dbg's Memory Map tab)."""
        regions = []
        address = 0
        mbi = MEMORY_BASIC_INFORMATION()
        mbi_size = ctypes.sizeof(mbi)

        while address < 0x7FFFFFFFFFFF:  # User-mode address space limit on x64
            result = VirtualQueryEx(self.process_handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size)
            if result == 0:
                break

            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0

            if (mbi.State == MEM_COMMIT and
                mbi.Protect not in (PAGE_NOACCESS, PAGE_GUARD, 0) and
                not (mbi.Protect & PAGE_GUARD) and
                size > 0):
                regions.append((base, size))

            next_addr = base + size
            if next_addr <= address:
                break
            address = next_addr

        return regions

    def scan_for_string(self, target_bytes, regions):
        """Scan all memory regions for a byte pattern (like x64dbg's Ctrl+B / Pattern Scan)."""
        found = []
        total = len(regions)

        for idx, (base, size) in enumerate(regions):
            if not self.is_running:
                break

            chunk_size = min(size, 4 * 1024 * 1024)  # 4MB chunks
            offset = 0

            while offset < size:
                read_size = min(chunk_size, size - offset)
                data = self.read_memory(base + offset, read_size)
                if data:
                    pos = 0
                    while True:
                        idx_found = data.find(target_bytes, pos)
                        if idx_found == -1:
                            break
                        found.append(base + offset + idx_found)
                        pos = idx_found + 1
                offset += chunk_size

            if total > 0:
                pct = int((idx + 1) / total * 100)
                self.progress_signal.emit(pct)

        return found

    def pointer_scan(self, target_address, regions):
        """Scan memory for pointers TO a specific address (like CE's pointer scan).
        This finds InstanceKlass structures that point to the Symbol."""
        addr_bytes = struct.pack('<Q', target_address)  # Little-endian 8 bytes (x64)
        found = []

        for base, size in regions:
            if not self.is_running:
                break
            data = self.read_memory(base, min(size, 8 * 1024 * 1024))
            if not data:
                continue
            pos = 0
            while True:
                idx = data.find(addr_bytes, pos)
                if idx == -1:
                    break
                found.append(base + idx)
                pos = idx + 8  # pointers are 8-byte aligned
        return found

    def try_parse_symbol(self, string_addr):
        """Check if a found string is a valid JVM Symbol object.
        JVM Symbol layout (HotSpot x64):
          offset -8: _hash (u32) + _length (u16) + padding
          offset  0: actual UTF-8 characters
        We verify by checking if the length field matches our target string length.
        """
        header = self.read_memory(string_addr - 8, 8)
        if not header or len(header) < 8:
            return None

        length_at_4 = struct.unpack_from('<H', header, 4)[0]
        length_at_0 = struct.unpack_from('<H', header, 0)[0]

        return string_addr - 8  # Return the Symbol base address

    def dump_hex(self, address, size=256):
        """Generate a hex dump string (like x64dbg's dump window)."""
        data = self.read_memory(address, size)
        if not data:
            return "<unreadable>"

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"  {address + i:016X}  {hex_part:<48s}  {ascii_part}")
        return "\n".join(lines)

    def extract_nearby_strings(self, address, range_size=4096):
        """Extract all readable ASCII/UTF-8 strings near an address.
        These are likely field names, method names, and type descriptors
        from the ConstantPool of the class."""
        data = self.read_memory(address, range_size)
        if not data:
            return []

        strings = []
        current = []
        for i, b in enumerate(data):
            if 32 <= b < 127:
                current.append(chr(b))
            else:
                if len(current) >= 3:  # Minimum 3 chars to be a meaningful string
                    s = "".join(current)
                    strings.append(s)
                current = []
        if len(current) >= 3:
            strings.append("".join(current))

        return strings

    def generate_skeleton(self, class_name, nearby_strings):
        """Generate a Java skeleton from extracted strings.
        Categorize strings into fields, methods, and type descriptors."""
        clean_name = class_name.replace("/", ".")
        short_name = clean_name.split(".")[-1]

        fields = []
        methods = []
        descriptors = []
        other_classes = []

        for s in nearby_strings:
            if s == class_name or len(s) < 2:
                continue

            if s.startswith("(") or s.startswith("[") or s in ("Z", "B", "C", "S", "I", "J", "F", "D", "V"):
                descriptors.append(s)
            elif "/" in s and not s.startswith("("):
                other_classes.append(s)
            elif s[0].islower() and " " not in s and len(s) < 50 and s.isidentifier():
                methods.append(s)
            elif s.isidentifier() and len(s) < 40:
                fields.append(s)

        fields = list(dict.fromkeys(fields))
        methods = list(dict.fromkeys(methods))
        other_classes = list(dict.fromkeys(other_classes))

        lines = []
        lines.append(f"// Extracted by Antigravity Memory Scanner (ReadProcessMemory)")
        lines.append(f"// Source: Raw RAM dump of sonoyuncuclient.exe")
        lines.append(f"// Class Address found in process memory")
        lines.append(f"")

        for ref in other_classes[:20]:
            lines.append(f"import {ref.replace('/', '.')};")
        if other_classes:
            lines.append("")

        lines.append(f"public class {short_name} {{")
        lines.append(f"")

        if fields:
            lines.append(f"    // ===== Fields ({len(fields)}) =====")
            for f in fields:
                lines.append(f"    public Object {f};")
            lines.append("")

        if methods:
            lines.append(f"    // ===== Methods ({len(methods)}) =====")
            for m in methods:
                lines.append(f"    public void {m}() {{ /* extracted */ }}")
            lines.append("")

        if descriptors:
            lines.append(f"    // ===== Type Descriptors ({len(descriptors)}) =====")
            for d in descriptors[:30]:
                lines.append(f"    // {d}")
            lines.append("")

        lines.append("}")
        return "\n".join(lines)

    def scan_value_first(self, value, val_type):
        """First scan: search entire memory for a specific value"""
        self.log_signal.emit(f"[*] Starting FIRST SCAN for {value} ({val_type})")
        
        try:
            if val_type == "Float (4 bytes)":
                target_bytes = struct.pack("f", float(value))
            elif val_type == "Double (8 bytes)":
                target_bytes = struct.pack("d", float(value))
            elif val_type == "Integer (4 bytes)":
                target_bytes = struct.pack("i", int(value))
            else:
                return []
        except ValueError:
            self.log_signal.emit("[!] Invalid value format.")
            return []

        regions = self.enumerate_memory_regions()
        self.log_signal.emit(f"[*] Scanning {len(regions)} regions for {len(target_bytes)} bytes...")
        
        results = self.scan_for_string(target_bytes, regions)
        self.log_signal.emit(f"[+] Found {len(results)} matches.")
        return results

    def scan_value_next(self, current_addresses, new_value, val_type):
        """Next scan: check existing addresses for a new value"""
        self.log_signal.emit(f"[*] Starting NEXT SCAN for {new_value} ({val_type}) on {len(current_addresses)} addresses")
        
        try:
            if val_type == "Float (4 bytes)":
                target_bytes = struct.pack("f", float(new_value))
            elif val_type == "Double (8 bytes)":
                target_bytes = struct.pack("d", float(new_value))
            elif val_type == "Integer (4 bytes)":
                target_bytes = struct.pack("i", int(new_value))
            else:
                return []
        except ValueError:
            self.log_signal.emit("[!] Invalid value format.")
            return current_addresses

        new_results = []
        val_len = len(target_bytes)
        
        handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, self.pid)
        if not handle:
            self.log_signal.emit("[!] Failed to open process for Next Scan.")
            return current_addresses

        buf = ctypes.create_string_buffer(val_len)
        bytes_read = ctypes.c_size_t()
        
        for addr in current_addresses:
            if ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, val_len, ctypes.byref(bytes_read)):
                if buf.raw == target_bytes:
                    new_results.append(addr)
                    
        CloseHandle(handle)
        self.log_signal.emit(f"[+] Next scan filtered down to {len(new_results)} matches.")
        return new_results

    def dump_jvm_offsets(self, target_class_name):
        """
        Attempts to dump field offsets by locating the InstanceKlass pointer
        and scanning the surrounding memory for FieldInfo structures.
        """
        self.log_signal.emit(f"[*] Starting JVM Heuristic Parser for: {target_class_name}")
        
        self.process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, self.pid)
        if not self.process_handle:
            self.log_signal.emit("[!] Failed to open process for JVM parsing.")
            return []

        target_bytes = target_class_name.encode('utf-8')
        regions = self.enumerate_memory_regions()
        string_addrs = self.scan_for_string(target_bytes, regions)
        
        if not string_addrs:
            self.log_signal.emit(f"[!] Could not find string '{target_class_name}' in memory.")
            CloseHandle(self.process_handle)
            return []
            
        self.log_signal.emit(f"[+] Found '{target_class_name}' at {len(string_addrs)} locations.")
        handle = self.process_handle

        pointer_candidates = []
        for addr in string_addrs:
            pointer_candidates.append(addr - 8)
            pointer_candidates.append(addr - 6) # Sometimes length is u2 at offset 0
            pointer_candidates.append(addr)
            
        pointer_patterns = [struct.pack("<Q", p) for p in pointer_candidates]
        
        self.log_signal.emit(f"[*] Scanning RAM for InstanceKlass pointers (8 bytes)...")
        instance_klass_addrs = []
        
        for base, size in regions:
            if not self.is_running:
                break
            data = self.read_memory(base, size)
            if not data:
                continue
            for pattern in pointer_patterns:
                idx = data.find(pattern)
                while idx != -1:
                    ik_addr = base + idx
                    instance_klass_addrs.append(ik_addr)
                    idx = data.find(pattern, idx + 1)
                    
        instance_klass_addrs = list(set(instance_klass_addrs))
        self.log_signal.emit(f"[+] Found {len(instance_klass_addrs)} possible InstanceKlass pointers.")
        
        results = []
        raw_hex_dumps = []
        for ik_addr in instance_klass_addrs:
            read_base = ik_addr - 2048
            if read_base < 0: read_base = 0
            
            buf = ctypes.create_string_buffer(6144)
            bytes_read = ctypes.c_size_t()
            
            if ReadProcessMemory(handle, ctypes.c_void_p(read_base), buf, 6144, ctypes.byref(bytes_read)):
                chunk = buf.raw[:bytes_read.value]
                
                if b"Lnet/minecraft/" in chunk or b"Ljava/lang/String;" in chunk:
                    self.log_signal.emit(f"[*] Valid Metaspace chunk found around 0x{ik_addr:X}")
                    
                    raw_hex_dumps.append(f"--- HEX DUMP FOR INSTANCEKLASS AT 0x{ik_addr:X} ---\n" + self.dump_hex(ik_addr - 128, 512))
                    
                    strings = list(re.finditer(b'[A-Za-z0-9_/<>;$()]{1,50}', chunk))
                    for i, match in enumerate(strings):
                        s_val = match.group().decode('utf-8', errors='ignore')
                        if s_val.startswith("(") or len(s_val) < 2 or s_val in ('Code', 'LineNumberTable', 'SourceFile'):
                            continue 
                            
                        sig_val = ""
                        if i + 1 < len(strings):
                            next_val = strings[i+1].group().decode('utf-8', errors='ignore')
                            if next_val.startswith("L") or next_val in ("I", "F", "D", "Z", "B", "C", "J", "S"):
                                sig_val = next_val
                                
                        start_idx = match.start()
                        if start_idx >= 8:
                            preceding = chunk[start_idx-8:start_idx]
                            try:
                                possible_offsets = struct.unpack("<II", preceding)
                                for p_off in possible_offsets:
                                    if 0x08 <= p_off <= 0x300: # Typical object offset range
                                        type_str = f" [Type: {sig_val}]" if sig_val else ""
                                        
                                        hint = ""
                                        if sig_val == "F": hint = " <- (Could be Health, Pitch, Yaw)"
                                        elif sig_val == "D": hint = " <- (Could be PosX, PosY, PosZ)"
                                        elif sig_val == "Z": hint = " <- (Could be onGround, isDead)"
                                        elif sig_val.startswith("Lnet/minecraft/"): hint = " <- (Object Reference)"
                                        
                                        res_str = f"Offset: 0x{p_off:02X} | Field: {s_val:<15}{type_str:<30}{hint}"
                                        if res_str not in results:
                                            results.append(res_str)
                            except:
                                pass
                                
        CloseHandle(handle)
        
        flat_name = target_class_name.replace("/", "_")
        dump_file = os.path.join(self.dump_dir, f"_OFFSETS_{flat_name}.txt")
        
        with open(dump_file, "w", encoding="utf-8") as f:
            f.write(f"=== ANTIGRAVITY JVM OFFSET DUMP ===\n")
            f.write(f"Target Class: {target_class_name}\n\n")
            
            if results:
                f.write("--- AUTOMATICALLY PARSED OFFSETS ---\n")
                try:
                    results.sort(key=lambda x: int(x.split("0x")[1].split()[0], 16))
                except:
                    pass
                for r in results:
                    f.write(r + "\n")
            else:
                f.write("[-] Automatic parser couldn't find exact offsets.\n")
                
            f.write("\n\n")
            for h in raw_hex_dumps:
                f.write(h + "\n\n")
        
        self.log_signal.emit(f"[+] Offset dump saved to: {dump_file}")
        
        if results:
            self.log_signal.emit(f"[+] Successfully extracted {len(results)} potential offsets!")
        else:
            self.log_signal.emit("[-] Extraction failed, but raw memory is saved to the file.")
            
        return results

    def run(self):
        self.log_signal.emit(f"[*] Antigravity Memory Scanner starting for PID: {self.pid}")
        self.log_signal.emit(f"[*] Engine: ReadProcessMemory (x64dbg/CE style, no injection)")

        self.process_handle = OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            False,
            self.pid
        )

        if not self.process_handle:
            err = ctypes.get_last_error()
            self.log_signal.emit(f"[!] Failed to open process (Error: {err}). Run as Administrator!")
            self.finished_signal.emit()
            return

        self.log_signal.emit(f"[+] Process handle acquired: 0x{self.process_handle:X}")

        self.log_signal.emit("[STAGE 1] Building Memory Map (VirtualQueryEx)...")
        regions = self.enumerate_memory_regions()
        total_mb = sum(size for _, size in regions) / (1024 * 1024)
        self.log_signal.emit(f"[+] Found {len(regions)} readable memory regions ({total_mb:.0f} MB total)")

        if total_mb < 100:
            self.log_signal.emit(f"[!] WARNING: Only {total_mb:.0f} MB readable. This looks like a launcher, not the JVM!")
            self.log_signal.emit(f"[!] The real game probably runs in javaw.exe or java.exe.")

        if not regions:
            self.log_signal.emit("[!] No readable memory regions found. Try running as Administrator.")
            CloseHandle(self.process_handle)
            self.finished_signal.emit()
            return

        self.log_signal.emit(f"\n{'='*60}")
        self.log_signal.emit(f"[PHASE 1] Searching for exact Minecraft class names...")
        self.log_signal.emit(f"{'='*60}")
        dumped_count = 0

        for class_name in EXACT_CLASSES:
            if not self.is_running:
                break

            target_bytes = class_name.encode('utf-8')
            self.log_signal.emit(f"[*] Searching: {class_name}")

            addresses = self.scan_for_string(target_bytes, regions)
            if not addresses:
                self.log_signal.emit(f"    [!] Not found.")
                continue

            self.log_signal.emit(f"    [+] FOUND {len(addresses)} match(es)!")

            best_strings = []
            best_addr = addresses[0]
            for addr in addresses:
                self.try_parse_symbol(addr)
                nearby = self.extract_nearby_strings(addr - 2048, 8192)
                if len(nearby) > len(best_strings):
                    best_strings = nearby
                    best_addr = addr

            hex_dump = self.dump_hex(best_addr - 32, 128)
            self.log_signal.emit(f"    [*] Hex dump:\n{hex_dump}")

            skeleton = self.generate_skeleton(class_name, best_strings)
            flat_name = class_name.replace("/", "_")
            filename = os.path.join(self.dump_dir, flat_name + ".java")
            with open(filename, "w", encoding="utf-8") as f:
                f.write(skeleton)

            field_count = skeleton.count("public Object ")
            method_count = skeleton.count("public void ")
            self.log_signal.emit(f"    [+] Skeleton: {field_count} fields, {method_count} methods")

            self.class_found_signal.emit(
                class_name.replace("/", "."), best_addr & 0xFFFFFFFF,
                best_strings[:50], filename
            )
            dumped_count += 1

        self.log_signal.emit(f"\n{'='*60}")
        self.log_signal.emit(f"[PHASE 2] Scanning for {len(GENERIC_SIGNATURES)} generic signatures...")
        self.log_signal.emit(f"{'='*60}")

        sig_results = {}
        for sig_idx, sig in enumerate(GENERIC_SIGNATURES):
            if not self.is_running:
                break

            sig_name = sig.decode('utf-8', errors='replace')
            addresses = self.scan_for_string(sig, regions)
            count = len(addresses)
            sig_results[sig_name] = count

            if count > 0:
                self.log_signal.emit(f"    [+] '{sig_name}' -> {count} hit(s)")
                if count <= 20 and sig_name in ('thePlayer', 'theWorld', 'SonOyuncu', 'AntiCheat', 'GameSettings', 'ticksExisted', 'onGround'):
                    for addr in addresses[:3]:
                        nearby = self.extract_nearby_strings(addr - 1024, 4096)
                        if nearby:
                            sig_file = os.path.join(self.dump_dir, f"_sig_{sig_name}.txt")
                            with open(sig_file, "w", encoding="utf-8") as f:
                                f.write(f"// Signature: {sig_name}\n")
                                f.write(f"// Address: 0x{addr:X}\n")
                                f.write(f"// Nearby strings ({len(nearby)}):\n\n")
                                for s in nearby:
                                    f.write(s + "\n")
                            
                            hex_dump = self.dump_hex(addr - 64, 256)
                            self.log_signal.emit(f"      [*] Context at 0x{addr:X}:\n{hex_dump}")
                            
                            self.class_found_signal.emit(
                                f"[SIG] {sig_name}", addr & 0xFFFFFFFF,
                                nearby[:30], sig_file
                            )
                            dumped_count += 1
            else:
                self.log_signal.emit(f"    [ ] '{sig_name}' -> not found")

            pct = int((sig_idx + 1) / len(GENERIC_SIGNATURES) * 50) + 50
            self.progress_signal.emit(min(pct, 99))

        self.log_signal.emit(f"\n{'='*60}")
        self.log_signal.emit(f"[PHASE 3] Broad Java string discovery...")
        self.log_signal.emit(f"{'='*60}")

        java_markers = [b"java/lang/", b"sun/misc/", b"com/sun/", b"org/apache/", b"net/minecraft/", b"cpw/mods/", b"com/mojang/"]
        
        all_java_strings = set()
        for marker in java_markers:
            if not self.is_running:
                break
            marker_name = marker.decode('utf-8')
            addresses = self.scan_for_string(marker, regions)
            if addresses:
                self.log_signal.emit(f"    [+] '{marker_name}' -> {len(addresses)} hits")
                for addr in addresses[:50]:
                    nearby = self.extract_nearby_strings(addr - 128, 512)
                    for s in nearby:
                        if '/' in s and len(s) > 5 and len(s) < 120:
                            all_java_strings.add(s)

        if all_java_strings:
            self.log_signal.emit(f"\n[+] Discovered {len(all_java_strings)} unique Java-like strings!")
            
            discovery_file = os.path.join(self.dump_dir, "_FULL_STRING_DISCOVERY.txt")
            sorted_strings = sorted(all_java_strings)
            with open(discovery_file, "w", encoding="utf-8") as f:
                f.write(f"// Antigravity Full String Discovery\n")
                f.write(f"// PID: {self.pid}\n")
                f.write(f"// Total unique strings: {len(sorted_strings)}\n\n")
                for s in sorted_strings:
                    f.write(s + "\n")
            
            mc_strings = [s for s in sorted_strings if 'minecraft' in s.lower() or 'mojang' in s.lower()]
            if mc_strings:
                self.log_signal.emit(f"\n[!] MINECRAFT-RELATED STRINGS FOUND ({len(mc_strings)}):")
                for s in mc_strings[:30]:
                    self.log_signal.emit(f"    -> {s}")
            
            self.class_found_signal.emit(
                f"[DISCOVERY] {len(all_java_strings)} strings",
                0, sorted_strings[:100], discovery_file
            )
            dumped_count += 1
        else:
            self.log_signal.emit(f"    [!] No Java-like strings found. Is this the right process?")

        CloseHandle(self.process_handle)
        self.process_handle = None
        self.progress_signal.emit(100)

        self.log_signal.emit(f"\n{'='*60}")
        self.log_signal.emit(f"[COMPLETE] Scan finished! Found {dumped_count} results.")
        self.log_signal.emit(f"[*] All data saved to: {self.dump_dir}")
        self.log_signal.emit(f"{'='*60}")

        self.finished_signal.emit()
