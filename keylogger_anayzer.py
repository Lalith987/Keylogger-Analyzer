import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog, ttk
import threading
import time
import os
import sys
import json
import psutil
from pynput import keyboard

# --- Configuration ---
SUSPICIOUS_KEYWORDS = ["keylog", "logger", "keystroke", "pynput", "spy", "monitor"]
LOG_SAVE_FILE = "saved_keylog.txt"
WHITELIST_FILE = "whitelist.json"

# --- Advanced UI Color Palette ---
COLOR_BG = "#0D0D0D"
COLOR_WIDGET_BG = "#1A1A1A"
COLOR_TEXT = "#39FF14"
COLOR_ACCENT = "#00B300"
COLOR_DANGER = "#FF0000"
COLOR_INFO = "#00BFFF"

class KeyloggerAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("KΣYŁOGGΣR ΔNΔŁYZΣR")
        self.root.geometry("900x700")
        self.root.configure(bg=COLOR_BG)

        self.keylogger_listener = None
        self.keylogger_running = False
        self.whitelist = self.load_whitelist()

        # --- UI Styling ---
        self.setup_styles()
        
        # --- Main UI Elements ---
        title_label = tk.Label(root, text="KΣYŁOGGΣR :: ΔNΔŁYZΣR", font=("Consolas", 24, "bold"), fg=COLOR_TEXT, bg=COLOR_BG)
        title_label.pack(pady=(10, 20))

        # --- Tabbed Interface ---
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, padx=20, fill="both", expand=True)

        self.keylogger_tab = ttk.Frame(self.notebook, style="TFrame")
        self.scanner_tab = ttk.Frame(self.notebook, style="TFrame")
        self.network_tab = ttk.Frame(self.notebook, style="TFrame")

        self.notebook.add(self.keylogger_tab, text="> Keylogger_")
        self.notebook.add(self.scanner_tab, text="> Process_Scanner_")
        self.notebook.add(self.network_tab, text="> Network_Monitor_")

        self.create_keylogger_page()
        self.create_scanner_page()
        self.create_network_page()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background=COLOR_BG, borderwidth=1)
        style.configure("TNotebook.Tab", background=COLOR_WIDGET_BG, foreground=COLOR_TEXT, font=("Consolas", 11, "bold"), padding=[15, 5], borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", COLOR_ACCENT)], foreground=[("selected", "white")])
        style.configure("TFrame", background=COLOR_BG)
        
        # Style for Treeview
        style.configure("Treeview", background=COLOR_WIDGET_BG, foreground=COLOR_TEXT, fieldbackground=COLOR_WIDGET_BG, font=("Consolas", 10), borderwidth=2, relief="solid")
        style.configure("Treeview.Heading", background=COLOR_WIDGET_BG, foreground=COLOR_TEXT, font=("Consolas", 11, "bold"), borderwidth=1, relief="flat")
        style.map("Treeview.Heading", background=[('active', COLOR_ACCENT)])

    # --- Page Creation ---
    def create_keylogger_page(self):
        self.keylogger_log_text = scrolledtext.ScrolledText(self.keylogger_tab, wrap=tk.WORD, bg=COLOR_WIDGET_BG, fg=COLOR_TEXT, font=("Consolas", 11), insertbackground=COLOR_TEXT, borderwidth=2, relief="solid")
        self.keylogger_log_text.pack(pady=10, padx=10, fill="both", expand=True)
        self.log_message("// Press 'Initiate Capture' to begin logging keystrokes.", target='keylogger')
        button_frame = tk.Frame(self.keylogger_tab, bg=COLOR_BG)
        button_frame.pack(pady=15, fill="x", padx=10)
        button_frame.columnconfigure((0, 1), weight=1)
        self.create_styled_button(button_frame, "Initiate Capture", self.toggle_keylogger, COLOR_TEXT, 0, 0)
        self.create_styled_button(button_frame, "Save Log", self.save_log, COLOR_TEXT, 0, 1)

    def create_scanner_page(self):
        # Using Treeview for structured results and right-click menu
        self.process_tree = self.create_treeview(self.scanner_tab, ("PID", "Name", "Command"))
        self.process_tree.bind("<Button-3>", lambda event: self.show_context_menu(event, self.process_tree, 'process'))
        button_frame = tk.Frame(self.scanner_tab, bg=COLOR_BG)
        button_frame.pack(pady=15, fill="x", padx=10)
        button_frame.columnconfigure((0, 1), weight=1)
        self.create_styled_button(button_frame, "Execute Scan", self.start_scan_thread, COLOR_TEXT, 0, 0)
        self.create_styled_button(button_frame, "Terminate Process", self.kill_process_prompt, COLOR_DANGER, 0, 1)

    def create_network_page(self):
        # Using Treeview for network results and right-click menu
        self.network_tree = self.create_treeview(self.network_tab, ("PID", "Name", "Remote Address"))
        self.network_tree.bind("<Button-3>", lambda event: self.show_context_menu(event, self.network_tree, 'network'))
        button_frame = tk.Frame(self.network_tab, bg=COLOR_BG)
        button_frame.pack(pady=15, fill="x", padx=10)
        button_frame.columnconfigure((0, 1), weight=1)
        self.create_styled_button(button_frame, "Scan Connections", self.start_network_scan_thread, COLOR_INFO, 0, 0)
        self.create_styled_button(button_frame, "Terminate Process", self.kill_process_prompt, COLOR_DANGER, 0, 1)

    def create_treeview(self, parent, columns):
        frame = ttk.Frame(parent)
        frame.pack(pady=10, padx=10, fill="both", expand=True)
        tree = ttk.Treeview(frame, columns=columns, show="headings", style="Treeview")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150 if col != "PID" else 50, anchor="w")
        tree.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        return tree

    def create_styled_button(self, parent, text, command, border_color, row, col):
        frame = tk.Frame(parent, bg=border_color, pady=2, padx=2)
        frame.grid(row=row, column=col, sticky="ew", padx=10)
        button = tk.Button(frame, text=text, command=command, bg=COLOR_WIDGET_BG, fg=COLOR_TEXT, font=("Consolas", 11, "bold"), relief="flat", borderwidth=0, highlightthickness=0, activebackground=COLOR_ACCENT, activeforeground="white")
        button.pack(fill="both", expand=True)
        if text == "Initiate Capture": self.start_button, self.start_button_frame = button, frame
        elif text == "Execute Scan": self.scan_button = button
        elif text == "Scan Connections": self.network_scan_button = button

    # --- Whitelist Functionality ---
    def load_whitelist(self):
        try:
            with open(WHITELIST_FILE, 'r') as f:
                return set(json.load(f))
        except (FileNotFoundError, json.JSONDecodeError):
            return set()

    def save_whitelist(self):
        with open(WHITELIST_FILE, 'w') as f:
            json.dump(list(self.whitelist), f, indent=4)

    def add_to_whitelist(self, tree, item_id):
        values = tree.item(item_id, "values")
        if not values: return
        process_name = values[1] # Name is always the second column
        self.whitelist.add(process_name)
        self.save_whitelist()
        tree.delete(item_id) # Immediately remove from view
        messagebox.showinfo("Whitelisted", f"'{process_name}' has been added to the whitelist and will be ignored in future scans.")

    def show_context_menu(self, event, tree, scan_type):
        item_id = tree.identify_row(event.y)
        if not item_id: return
        tree.selection_set(item_id)
        menu = tk.Menu(self.root, tearoff=0, bg=COLOR_WIDGET_BG, fg=COLOR_TEXT, activebackground=COLOR_ACCENT, activeforeground="white")
        menu.add_command(label="Add to Whitelist", command=lambda: self.add_to_whitelist(tree, item_id))
        menu.tk_popup(event.x_root, event.y_root)

    def log_message(self, message, target='keylogger', clear=False):
        # This function now only logs to the keylogger tab for simplicity
        if target == 'keylogger': 
            if clear: self.keylogger_log_text.delete('1.0', tk.END)
            self.keylogger_log_text.insert(tk.END, message + "\n")
            self.keylogger_log_text.see(tk.END)
            
    # --- Keylogger Functionality ---
    def toggle_keylogger(self):
        if self.keylogger_running: self.stop_keylogger()
        else: self.start_keylogger()

    def start_keylogger(self):
        self.keylogger_running = True
        self.start_button.config(text="Stop Capture", bg=COLOR_WIDGET_BG, fg=COLOR_DANGER)
        self.start_button_frame.config(bg=COLOR_DANGER)
        self.log_message("\n[+] CAPTURE INITIATED...", target='keylogger', clear=True)
        self.keylogger_listener = keyboard.Listener(on_press=self.on_press)
        threading.Thread(target=self.keylogger_listener.start, daemon=True).start()

    def stop_keylogger(self):
        if self.keylogger_listener: self.keylogger_listener.stop()
        self.keylogger_running = False
        self.start_button.config(text="Initiate Capture", bg=COLOR_WIDGET_BG, fg=COLOR_TEXT)
        self.start_button_frame.config(bg=COLOR_TEXT)
        self.log_message("\n[-] CAPTURE TERMINATED.", target='keylogger')

    def on_press(self, key):
        if not self.keylogger_running: return False
        timestamp = time.strftime("[%H:%M:%S]")
        try: log_entry = f"{timestamp} :: Key: {key.char}"
        except AttributeError: log_entry = f"{timestamp} :: Special: {str(key)}"
        self.root.after(0, self.log_message, log_entry, 'keylogger')

    # --- Scanning Functionality ---
    def start_scan_thread(self):
        self.scan_button.config(state=tk.DISABLED, text="Scanning...")
        threading.Thread(target=self.scan_system_processes, daemon=True).start()

    def scan_system_processes(self):
        own_pid = os.getpid()
        suspicious_procs = []
        if self.keylogger_running:
            try:
                proc_info = psutil.Process(own_pid).as_dict(attrs=['pid', 'name', 'cmdline'])
                proc_info['name'] = f"(Internal) {proc_info.get('name', 'N/A')}"
                suspicious_procs.append(proc_info)
            except psutil.NoSuchProcess: pass
        for pid in psutil.pids():
            if pid == own_pid: continue
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                if proc_name in self.whitelist: continue
                proc_info = proc.as_dict(attrs=['pid', 'name', 'cmdline'])
                if any(keyword in proc_name.lower() for keyword in SUSPICIOUS_KEYWORDS):
                    suspicious_procs.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        self.root.after(0, self.display_scan_results, suspicious_procs, self.process_tree)

    def start_network_scan_thread(self):
        self.network_scan_button.config(state=tk.DISABLED, text="Scanning...")
        threading.Thread(target=self.scan_network_connections, daemon=True).start()

    def scan_network_connections(self):
        connected_procs_map = {}
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.pid and conn.pid not in connected_procs_map:
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                        if proc_name in self.whitelist: continue
                        proc_info = proc.as_dict(attrs=['pid', 'name'])
                        proc_info['remote_addr'] = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                        connected_procs_map[conn.pid] = proc_info
                    except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        except psutil.AccessDenied:
            messagebox.showerror("Access Denied", "Network scanning requires administrator privileges.")
        self.root.after(0, self.display_scan_results, list(connected_procs_map.values()), self.network_tree)

    def display_scan_results(self, procs_to_display, tree):
        for i in tree.get_children(): tree.delete(i) # Clear previous results
        
        # --- EDIT: Added logic to show a message box if no results are found ---
        if not procs_to_display:
            if tree == self.process_tree:
                messagebox.showinfo("Scan Complete", "No suspicious processes found. It seems no keylogger is plugged.")
            elif tree == self.network_tree:
                 messagebox.showinfo("Scan Complete", "No active network connections found.")
        else:
            for proc in procs_to_display:
                pid = proc.get('pid')
                name = proc.get('name', 'N/A')
                if tree == self.network_tree:
                    details = proc.get('remote_addr', 'N/A')
                else:
                    details = ' '.join(proc.get('cmdline', []))
                    if len(details) > 100: details = details[:97] + "..."
                tree.insert("", "end", values=(pid, name, details))

        if tree == self.process_tree: self.scan_button.config(state=tk.NORMAL, text="Execute Scan")
        else: self.network_scan_button.config(state=tk.NORMAL, text="Scan Connections")

    def kill_process_prompt(self):
        # Determine which tree is currently visible to get the selected item
        active_tree = None
        current_tab_text = self.notebook.tab(self.notebook.select(), "text")
        if "Process" in current_tab_text:
            active_tree = self.process_tree
        elif "Network" in current_tab_text:
            active_tree = self.network_tree

        pid_to_kill = ""
        if active_tree:
            selected_item = active_tree.selection()
            if selected_item:
                values = active_tree.item(selected_item[0], "values")
                pid_to_kill = values[0]

        # Ask the user, pre-filling with the selected PID if available
        pid_to_kill = simpledialog.askstring("Terminate Process", "Enter Target PID:", initialvalue=pid_to_kill, parent=self.root)

        if pid_to_kill and pid_to_kill.isdigit():
            pid = int(pid_to_kill)
            if pid == os.getpid():
                if self.keylogger_running:
                    self.stop_keylogger()
                    messagebox.showinfo("Success", "Internal keylogger terminated.")
                else:
                    messagebox.showwarning("Action Denied", "Cannot terminate the main analyzer.")
                return
            try:
                p = psutil.Process(pid)
                p.terminate()
                messagebox.showinfo("Success", f"Termination signal sent to PID: {pid}")
                self.start_scan_thread() # Refresh scans
                self.start_network_scan_thread()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to terminate process {pid}.\n{e}")
        elif pid_to_kill:
            messagebox.showerror("Invalid Input", "Please enter a valid numerical PID.")

    def save_log(self):
        log_content = self.keylogger_log_text.get('1.0', tk.END)
        try:
            with open(LOG_SAVE_FILE, "w", encoding="utf-8") as f:
                f.write(log_content)
            messagebox.showinfo("Log Saved", f"Log successfully saved to '{os.path.abspath(LOG_SAVE_FILE)}'")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log.\n{e}")

if __name__ == "__main__":
    main_root = tk.Tk()
    app = KeyloggerAnalyzerApp(main_root)
    main_root.mainloop()