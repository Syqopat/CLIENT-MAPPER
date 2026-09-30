import sys
import os
import subprocess
import urllib.request
from PyQt5.QtWidgets import QApplication, QListWidgetItem, QMessageBox
from PyQt5.QtCore import Qt, QTimer
from ui import KernelMapperUI
from scanner import MemoryScannerThread
import psutil

class AppController(KernelMapperUI):
    def __init__(self):
        super().__init__()
        self.scanner_thread = None
        self.cfr_path = "cfr.jar"
        self.procyon_path = "procyon.jar"
        self.found_classes = set()
        self.class_count = 0
        
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_decompile.clicked.connect(self.decompile_selected_class)
        self.btn_dump_offsets.clicked.connect(self.dump_jvm_offsets_action)
        
        self.btn_live_dump.clicked.connect(self.toggle_live_dump)
        self.live_dump_timer = QTimer(self)
        self.live_dump_timer.timeout.connect(self.update_live_dump)
        self.live_offsets = []
        self.live_base_addr = 0
        
        self.log("[*] Scanner initialized. Waiting for sonoyuncuclient.exe...")
        self.search_timer = QTimer(self)
        self.search_timer.timeout.connect(self.auto_start_scan)
        self.search_timer.start(2000) # Check every 2 seconds
        
        self.ensure_decompiler()

    def ensure_decompiler(self):
        if not os.path.exists(self.cfr_path):
            self.log("[*] Downloading CFR Decompiler (cfr.jar)...")
            try:
                url = "https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
                urllib.request.urlretrieve(url, self.cfr_path)
                self.log("[+] CFR downloaded successfully.")
            except Exception as e:
                self.log(f"[!] Failed to download CFR: {e}")
                
        if not os.path.exists(self.procyon_path):
            self.log("[*] Downloading Procyon Decompiler (procyon.jar)...")
            try:
                url = "https://github.com/mstrobel/procyon/releases/download/v0.6.0/procyon-decompiler-0.6.0.jar"
                urllib.request.urlretrieve(url, self.procyon_path)
                self.log("[+] Procyon downloaded successfully.")
            except Exception as e:
                self.log(f"[!] Failed to download Procyon: {e}")

    def clear_dashboard(self):
        self.class_list.clear()
        self.class_preview.clear()
        self.class_count = 0
        self.lbl_counter.setText(f"Dumped Classes: 0")
        self.btn_decompile.setEnabled(False)
        self.found_classes.clear()

    def auto_start_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            return

        
        best_pid = None
        best_ram = 0
        
        for p in psutil.process_iter(['pid', 'name']):
            try:
                name = (p.info['name'] or '').lower()
                if name == 'sonoyuncuclient.exe':
                    ram = p.memory_info().rss
                    ram_mb = ram // (1024 * 1024)
                    self.log(f"[*] Found sonoyuncuclient.exe PID:{p.info['pid']} RAM:{ram_mb}MB")
                    if ram > best_ram:
                        best_ram = ram
                        best_pid = p.info['pid']
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
                
        if best_pid:
            best_ram_mb = best_ram // (1024 * 1024)
            self.search_timer.stop()
            self.lbl_selected.setText(f"Target: sonoyuncuclient.exe (PID: {best_pid}, {best_ram_mb}MB)")
            self.log(f"[+] Selected LARGEST process: PID {best_pid} ({best_ram_mb}MB)")
            self.start_scan(best_pid)

    def start_scan(self, pid):
        self.target_pid = pid # Save for CE scanner
        self.console.clear()
        self.progress_bar.setValue(0)
        self.btn_stop.setEnabled(True)
        
        self.scanner_thread = MemoryScannerThread(pid)
        self.scanner_thread.log_signal.connect(self.log)
        self.scanner_thread.progress_signal.connect(self.progress_bar.setValue)
        
        self.scanner_thread.class_found_signal.connect(self.on_class_found)
        
        self.scanner_thread.finished_signal.connect(self.on_scan_finished)
        
        self.scanner_thread.start()

    def stop_scan(self):
        if self.scanner_thread and self.scanner_thread.isRunning():
            self.scanner_thread.stop()
            self.log("[-] Stopping scan, please wait...")
            self.btn_stop.setEnabled(False)

    def on_class_found(self, class_name, address, strings, filename):
        item_text = f"[{address:08X}] {class_name}"
        
        item = QListWidgetItem(item_text)
        item.setData(Qt.UserRole, {
            "name": class_name,
            "address": address,
            "strings": strings,
            "filename": filename
        })
        self.class_list.addItem(item)
        
        self.class_count += 1
        self.lbl_counter.setText(f"Dumped Classes: {self.class_count}")
        
        if self.class_count % 10 == 0:
            self.class_list.scrollToBottom()

    def on_class_selected(self):
        selected = self.class_list.selectedItems()
        if selected:
            self.btn_decompile.setEnabled(True)
            self.btn_dump_offsets.setEnabled(True)
        else:
            self.btn_decompile.setEnabled(False)
            self.btn_dump_offsets.setEnabled(False)

    def decompile_selected_class(self):
        selected = self.class_list.selectedItems()
        if not selected:
            return
            
        item = selected[0]
        filename = item.data(Qt.UserRole).get("filename", "")
        
        if not filename or not os.path.exists(filename):
            self.class_preview.setText("[!] File not found on disk.")
            return
            
        
        if filename.endswith(".java") or filename.endswith(".txt"):
            self.class_preview.setText(f"[*] Reading Extracted File: {filename}...\n")
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    content = f.read()
                self.class_preview.setText(content)
            except Exception as e:
                self.class_preview.setText(f"[!] Failed to read file: {e}")
            return
            
        self.class_preview.setText(f"[*] Decompiling {filename}...\n[*] Please wait...")
        QApplication.processEvents() # Force UI update
        
        try:
            cmd_cfr = ['java', '-jar', self.cfr_path, filename]
            result_cfr = subprocess.run(cmd_cfr, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            
            output = result_cfr.stdout
            
            if result_cfr.returncode != 0 or "Decompilation failed" in output or len(output.strip()) < 50:
                self.class_preview.setText(f"[*] CFR failed or returned poor results. Trying Procyon...\n")
                QApplication.processEvents()
                
                cmd_proc = ['java', '-jar', self.procyon_path, filename]
                result_proc = subprocess.run(cmd_proc, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                
                if result_proc.returncode == 0 and len(result_proc.stdout.strip()) > 50:
                    self.class_preview.setText(f"/* Decompiled with Procyon */\n\n{result_proc.stdout}")
                else:
                    error_msg = f"[!] Both decompilers failed to produce meaningful output.\n\n"
                    error_msg += f"--- CFR ERROR ---\n{result_cfr.stderr}\n\n"
                    error_msg += f"--- PROCYON ERROR ---\n{result_proc.stderr}"
                    self.class_preview.setText(error_msg)
            else:
                self.class_preview.setText(output)
                
        except FileNotFoundError:
            self.class_preview.setText("[!] Java not found. Please install Java (JRE/JDK) and ensure it's in your system PATH.")
        except Exception as e:
            self.class_preview.setText(f"[!] An error occurred during decompilation:\n{e}")

    def dump_jvm_offsets_action(self):
        selected = self.class_list.selectedItems()
        if not selected:
            return
            
        item = selected[0]
        class_name = item.data(Qt.UserRole).get("name", "")
        
        if not class_name:
            return
            
        if not hasattr(self, 'target_pid') or not self.target_pid:
            self.log("[!] Target PID not found. Run Auto-Scan first.")
            return
            
        self.log(f"[*] Dispatching JVM Hack Offset Dumper for: {class_name}")
        self.btn_dump_offsets.setEnabled(False)
        
        self.scanner_thread = MemoryScannerThread(self.target_pid)
        self.scanner_thread.log_signal.connect(self.log)
        
        def run_dumper():
            self.scanner_thread.dump_jvm_offsets(class_name)
            self.btn_dump_offsets.setEnabled(True)
            
        self.scanner_thread.run = run_dumper
        self.scanner_thread.start()

    def on_scan_finished(self):
        self.btn_stop.setEnabled(False)
        self.scanner_thread = None
        self.log("[*] Scan finished or stopped. You can manually restart when needed.")
        self.lbl_selected.setText("Scan Finished.")

    def toggle_live_dump(self):
        if self.live_dump_timer.isActive():
            self.live_dump_timer.stop()
            self.btn_live_dump.setText("Start Live Object Dump")
            self.btn_live_dump.setStyleSheet("background-color: #8e44ad; color: white; font-weight: bold;")
            self.log("Live dump stopped.")
            return
            
        base_addr_str = self.txt_base_addr.text().strip()
        if not base_addr_str:
            self.log("Enter a base address first (e.g. 15A00000)!")
            return
            
        try:
            self.live_base_addr = int(base_addr_str, 16)
        except:
            self.log("Invalid hex address!")
            return
            
        selected = self.class_list.selectedItems()
        if not selected:
            self.log("Select a class from the list first to load its offsets!")
            return
            
        class_name = selected[0].data(Qt.UserRole).get("name", "")
        flat_name = class_name.replace("/", "_")
        dump_file = os.path.join("dumps", "classes", "flat", f"_OFFSETS_{flat_name}.txt")
        
        if not os.path.exists(dump_file):
            self.log(f"No _OFFSETS.txt found for {class_name}! Click 'Extract Field Offsets' first.")
            return
            
        self.live_offsets = []
        with open(dump_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("Offset: "):
                    parts = line.split("|")
                    off_str = parts[0].replace("Offset:", "").strip()
                    off_val = int(off_str, 16)
                    
                    field_part = parts[1].strip()
                    type_val = "Unknown"
                    if "[Type:" in field_part:
                        type_val = field_part.split("[Type:")[1].split("]")[0].strip()
                        
                    self.live_offsets.append({
                        'offset': off_val,
                        'type': type_val,
                        'field': field_part
                    })
                    
        if not self.live_offsets:
            self.log("No valid offsets parsed from the file!")
            return
            
        self.btn_live_dump.setText("Stop Live Dump")
        self.btn_live_dump.setStyleSheet("background-color: #e74c3c; color: white; font-weight: bold;")
        self.live_dump_timer.start(100) # 10 FPS
        
    def update_live_dump(self):
        import ctypes
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400
        handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, getattr(self, 'target_pid', 0))
        if not handle:
            self.live_dump_console.setText("Failed to open process. Have you started the scan?")
            self.toggle_live_dump()
            return
            
        result_lines = [f"--- LIVE DATA FOR 0x{self.live_base_addr:X} ---"]
        
        buf = ctypes.create_string_buffer(2048)
        bytes_read = ctypes.c_size_t()
        
        if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(self.live_base_addr), buf, 2048, ctypes.byref(bytes_read)):
            data = buf.raw[:bytes_read.value]
            import struct
            
            for off_info in self.live_offsets:
                offset = off_info['offset']
                t = off_info['type']
                val_str = "???"
                
                if offset + 4 <= len(data):
                    try:
                        if t == "F":
                            val = struct.unpack_from("<f", data, offset)[0]
                            val_str = f"{val:.4f}f"
                        elif t == "I":
                            val = struct.unpack_from("<i", data, offset)[0]
                            val_str = f"{val}"
                        elif t == "D" and offset + 8 <= len(data):
                            val = struct.unpack_from("<d", data, offset)[0]
                            val_str = f"{val:.4f}d"
                        elif t == "Z" or t == "B":
                            val = struct.unpack_from("<b", data, offset)[0]
                            val_str = "True" if val else "False"
                        elif t.startswith("L"):
                            val = struct.unpack_from("<I", data, offset)[0] # Compressed OOP
                            val_str = f"Ptr: 0x{val:X}"
                        else:
                            val = struct.unpack_from("<I", data, offset)[0]
                            val_str = f"0x{val:08X}"
                    except Exception as e:
                        val_str = "Err"
                        
                result_lines.append(f"0x{offset:02X} | {val_str:<15} | {off_info['field']}")
        else:
            result_lines.append("Failed to read memory at base address!")
            
        kernel32.CloseHandle(handle)
        self.live_dump_console.setText("\n".join(result_lines))

if __name__ == '__main__':
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    app = QApplication(sys.argv)
    
    window = AppController()
    window.show()
    sys.exit(app.exec_())
