from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QTextEdit, QLabel, QSplitter, 
                             QProgressBar, QTabWidget, QListWidget, QListWidgetItem,
                             QFrame, QComboBox, QLineEdit)
from PyQt5.QtCore import Qt

class KernelMapperUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Antigravity SonOyuncu Auto-Dumper")
        self.resize(1100, 750)
        self.setup_ui()

    def setup_ui(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #1e1e1e; color: #ffffff; }
            QTabWidget::pane { border: 1px solid #3e3e42; }
            QTabBar::tab { background: #2d2d30; color: #ffffff; padding: 10px 20px; border: 1px solid #3e3e42; }
            QTabBar::tab:selected { background: #0e639c; font-weight: bold; }
            QListWidget { background-color: #252526; color: #ffffff; gridline-color: #3e3e42; border: none; }
            QListWidget::item:selected { background-color: #094771; }
            QPushButton { background-color: #0e639c; color: white; border: none; padding: 8px 16px; font-weight: bold; }
            QPushButton:hover { background-color: #1177bb; }
            QPushButton:disabled { background-color: #4d4d4d; color: #808080; }
            QTextEdit { background-color: #1e1e1e; color: #d4d4d4; font-family: Consolas; border: 1px solid #3e3e42; }
            QProgressBar { border: 1px solid #3e3e42; text-align: center; color: white; }
            QProgressBar::chunk { background-color: #0e639c; }
            QLabel { color: #cccccc; font-weight: bold; }
        """)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self.tab_classes = QWidget()
        self.tab_classes_layout = QVBoxLayout(self.tab_classes)
        self.tabs.addTab(self.tab_classes, "Class Scanner")

        self.control_panel = QFrame()
        self.control_layout = QHBoxLayout(self.control_panel)
        
        self.btn_auto_scan = QPushButton("Auto-Find & Scan JVM")
        self.btn_auto_scan.setMinimumHeight(40)
        self.btn_auto_scan.setStyleSheet("background-color: #e74c3c; color: white; font-weight: bold; border-radius: 5px;")
        
        self.lbl_selected = QLabel("Target: None")
        self.lbl_selected.setStyleSheet("font-weight: bold; color: #f39c12;")
        
        self.btn_stop = QPushButton("Stop Scan")
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("background-color: #c53929; color: white; font-weight: bold;")
        
        self.control_layout.addWidget(self.btn_auto_scan)
        self.control_layout.addWidget(self.lbl_selected)
        self.control_layout.addStretch()
        self.control_layout.addWidget(self.btn_stop)
        
        self.tab_classes_layout.addWidget(self.control_panel)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.tab_classes_layout.addWidget(self.progress_bar)
        
        self.splitter = QSplitter(Qt.Horizontal)
        self.tab_classes_layout.addWidget(self.splitter)
        
        self.left_panel = QWidget()
        self.left_layout = QVBoxLayout(self.left_panel)
        
        self.lbl_counter = QLabel("Dumped Classes: 0")
        self.lbl_counter.setStyleSheet("font-weight: bold;")
        self.class_list = QListWidget()
        self.class_list.itemSelectionChanged.connect(self.on_class_selected)
        
        self.left_layout.addWidget(self.lbl_counter)
        self.left_layout.addWidget(self.class_list)
        
        self.right_panel = QWidget()
        self.right_layout = QVBoxLayout(self.right_panel)
        
        self.class_preview = QTextEdit()
        self.class_preview.setReadOnly(True)
        self.class_preview.setFontFamily("Consolas")
        
        self.btn_decompile = QPushButton("View Extracted Skeleton")
        self.btn_decompile.setEnabled(False)
        self.btn_decompile.setMinimumHeight(30)
        
        self.btn_dump_offsets = QPushButton("Extract Field Offsets (JVM Hack)")
        self.btn_dump_offsets.setEnabled(False)
        self.btn_dump_offsets.setMinimumHeight(30)
        self.btn_dump_offsets.setStyleSheet("background-color: #8e44ad; color: white; font-weight: bold;")
        
        self.right_layout.addWidget(self.class_preview)
        
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.btn_decompile)
        btn_layout.addWidget(self.btn_dump_offsets)
        self.right_layout.addLayout(btn_layout)
        
        self.splitter.addWidget(self.left_panel)
        self.splitter.addWidget(self.right_panel)
        self.splitter.setSizes([300, 500])

        self.tab_ce = QWidget()
        self.tab_ce_layout = QVBoxLayout(self.tab_ce)
        self.tabs.addTab(self.tab_ce, "Cheat Engine (Value Scan)")

        self.ce_control_panel = QHBoxLayout()
        
        self.combo_type = QComboBox()
        self.combo_type.addItems(["Float (4 bytes)", "Double (8 bytes)", "Integer (4 bytes)"])
        
        self.txt_value = QLineEdit()
        self.txt_value.setPlaceholderText("Enter value (e.g. 70.0 for Y coord)")
        
        self.btn_first_scan = QPushButton("First Scan")
        self.btn_first_scan.setStyleSheet("background-color: #27ae60; color: white; font-weight: bold;")
        
        self.btn_next_scan = QPushButton("Next Scan")
        self.btn_next_scan.setStyleSheet("background-color: #2980b9; color: white; font-weight: bold;")
        self.btn_next_scan.setEnabled(False)
        
        self.btn_reset_scan = QPushButton("Reset")
        
        self.ce_control_panel.addWidget(QLabel("Value Type:"))
        self.ce_control_panel.addWidget(self.combo_type)
        self.ce_control_panel.addWidget(self.txt_value)
        self.ce_control_panel.addWidget(self.btn_first_scan)
        self.ce_control_panel.addWidget(self.btn_next_scan)
        self.ce_control_panel.addWidget(self.btn_reset_scan)
        
        self.tab_ce_layout.addLayout(self.ce_control_panel)
        
        self.lbl_scan_results = QLabel("Results: 0")
        self.tab_ce_layout.addWidget(self.lbl_scan_results)
        
        self.scan_results_list = QListWidget()
        self.scan_results_list.setStyleSheet("font-family: Consolas;")
        self.tab_ce_layout.addWidget(self.scan_results_list)
        
        self.btn_analyze_ptr = QPushButton("Analyze Offset / Generate C++ Pointer")
        self.btn_analyze_ptr.setEnabled(False)
        self.tab_ce_layout.addWidget(self.btn_analyze_ptr)

        live_dump_frame = QFrame()
        live_dump_frame.setStyleSheet("background-color: #2d2d30; border: 1px solid #3e3e42; border-radius: 5px; margin-top: 10px;")
        live_dump_layout = QVBoxLayout(live_dump_frame)
        
        live_dump_controls = QHBoxLayout()
        self.txt_base_addr = QLineEdit()
        self.txt_base_addr.setPlaceholderText("Object Base Address (Hex, e.g. 15A00000)")
        
        self.btn_live_dump = QPushButton("Start Live Object Dump")
        self.btn_live_dump.setStyleSheet("background-color: #8e44ad; color: white; font-weight: bold;")
        
        live_dump_controls.addWidget(QLabel("Base Address:"))
        live_dump_controls.addWidget(self.txt_base_addr)
        live_dump_controls.addWidget(self.btn_live_dump)
        
        self.live_dump_console = QTextEdit()
        self.live_dump_console.setReadOnly(True)
        self.live_dump_console.setStyleSheet("background-color: #000000; color: #00FF00; font-family: Consolas;")
        self.live_dump_console.setMinimumHeight(200)
        
        live_dump_layout.addLayout(live_dump_controls)
        live_dump_layout.addWidget(QLabel("Live Object Data (Parsed from _OFFSETS.txt):"))
        live_dump_layout.addWidget(self.live_dump_console)
        
        self.tab_ce_layout.addWidget(live_dump_frame)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setLineWrapMode(QTextEdit.NoWrap)
        self.console.setMaximumHeight(150)
        main_layout.addWidget(QLabel("System Logs:"))
        main_layout.addWidget(self.console)

    def on_class_selected(self):
        selected = self.class_list.selectedItems()
        if not selected:
            self.class_preview.clear()
            self.btn_decompile.setEnabled(False)
            return
            
        item = selected[0]
        self.btn_decompile.setEnabled(True)
        strings_list = item.data(Qt.UserRole)
        
        if strings_list:
            formatted_preview = "\n".join(strings_list)
            self.class_preview.setText(formatted_preview)
        else:
            self.class_preview.setText("<No readable strings found in this class>")

    def log(self, msg):
        self.console.append(msg)
