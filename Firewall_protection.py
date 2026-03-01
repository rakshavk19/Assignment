import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import time
import socket
import struct
import ipaddress
from datetime import datetime
import json
import os
import queue
import random
from collections import defaultdict

class SimpleFirewallGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Firewall Protection Tool")
        self.root.geometry("1000x700")
        self.root.configure(bg='#2b2b2b')
        
        # Initialize firewall engine
        self.firewall = FirewallEngine()
        self.firewall.start()
        
        # Create GUI
        self.create_widgets()
        self.create_menu()
        
        # Start updates
        self.update_stats()
        
    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Logs", command=self.export_logs)
        file_menu.add_command(label="Import Rules", command=self.import_rules)
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        
    def create_widgets(self):
        """Create main GUI widgets"""
        
        # Top frame for stats
        top_frame = tk.Frame(self.root, bg='#2b2b2b')
        top_frame.pack(fill='x', padx=10, pady=5)
        
        # Stats display
        self.stats_vars = {}
        stats = [
            ("Total Packets:", "0", "total"),
            ("Blocked:", "0", "blocked"),
            ("Rules:", "0", "rules"),
            ("Status:", "Active", "status")
        ]
        
        for i, (label, value, key) in enumerate(stats):
            frame = tk.Frame(top_frame, bg='#3c3c3c', relief='raised', bd=2)
            frame.grid(row=0, column=i, padx=5, sticky='ew')
            
            tk.Label(frame, text=label, bg='#3c3c3c', fg='white', 
                    font=('Arial', 10)).pack(side='left', padx=5, pady=5)
            self.stats_vars[key] = tk.StringVar(value=value)
            tk.Label(frame, textvariable=self.stats_vars[key], 
                    bg='#3c3c3c', fg='#00ff00', font=('Arial', 12, 'bold')).pack(side='right', padx=5, pady=5)
        
        # Notebook for tabs
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#2b2b2b')
        style.configure('TNotebook.Tab', background='#3c3c3c', foreground='white')
        style.map('TNotebook.Tab', background=[('selected', '#4a4a4a')])
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create tabs
        self.create_monitor_tab()
        self.create_rules_tab()
        self.create_logs_tab()
        self.create_blocklist_tab()
        
        # Status bar
        status_frame = tk.Frame(self.root, bg='#3c3c3c', height=25)
        status_frame.pack(side='bottom', fill='x')
        
        self.status_label = tk.Label(status_frame, text="Firewall Running", 
                                     bg='#3c3c3c', fg='#00ff00', anchor='w')
        self.status_label.pack(side='left', padx=10)
        
    def create_monitor_tab(self):
        """Create real-time monitoring tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="Live Monitor")
        
        # Control panel
        control_frame = tk.Frame(monitor_frame, bg='#2b2b2b')
        control_frame.pack(fill='x', pady=5)
        
        self.monitor_active = False
        self.monitor_btn = tk.Button(control_frame, text="Start Monitoring",
                                     command=self.toggle_monitoring,
                                     bg='#4a4a4a', fg='white')
        self.monitor_btn.pack(side='left', padx=5)
        
        tk.Label(control_frame, text="Filter:", bg='#2b2b2b', fg='white').pack(side='left', padx=5)
        self.filter_entry = tk.Entry(control_frame, width=30, bg='#3c3c3c', fg='white')
        self.filter_entry.pack(side='left', padx=5)
        
        tk.Button(control_frame, text="Clear", command=self.clear_monitor,
                 bg='#4a4a4a', fg='white').pack(side='left', padx=5)
        
        # Monitor display
        self.monitor_text = scrolledtext.ScrolledText(monitor_frame, height=25,
                                                      bg='#1e1e1e', fg='#00ff00',
                                                      font=('Courier', 10))
        self.monitor_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Configure tags
        self.monitor_text.tag_config('blocked', foreground='#ff5555')
        self.monitor_text.tag_config('allowed', foreground='#55ff55')
        
    def create_rules_tab(self):
        """Create firewall rules tab"""
        rules_frame = ttk.Frame(self.notebook)
        self.notebook.add(rules_frame, text="Firewall Rules")
        
        # Left panel - Add rule
        left_panel = tk.Frame(rules_frame, bg='#2b2b2b')
        left_panel.pack(side='left', fill='y', padx=5, pady=5)
        
        tk.Label(left_panel, text="Add New Rule", bg='#2b2b2b', fg='white',
                font=('Arial', 12, 'bold')).pack(pady=5)
        
        # Rule form
        fields = [
            ("Name:", "name_entry"),
            ("Action (ALLOW/DENY):", "action_combo"),
            ("Protocol:", "protocol_combo"),
            ("Source IP:", "src_ip_entry"),
            ("Destination IP:", "dst_ip_entry"),
            ("Source Port:", "src_port_entry"),
            ("Destination Port:", "dst_port_entry")
        ]
        
        self.rule_entries = {}
        
        for label, key in fields:
            tk.Label(left_panel, text=label, bg='#2b2b2b', fg='white').pack(anchor='w', pady=2)
            
            if 'combo' in key:
                if key == 'action_combo':
                    values = ['ALLOW', 'DENY']
                else:
                    values = ['TCP', 'UDP', 'ICMP', 'ANY']
                    
                combo = ttk.Combobox(left_panel, values=values, width=27)
                combo.set(values[0])
                combo.pack(pady=2)
                self.rule_entries[key] = combo
            else:
                entry = tk.Entry(left_panel, width=30, bg='#3c3c3c', fg='white')
                entry.pack(pady=2)
                self.rule_entries[key] = entry
        
        tk.Button(left_panel, text="Add Rule", command=self.add_rule,
                 bg='#4a4a4a', fg='white', width=20).pack(pady=10)
        tk.Button(left_panel, text="Clear Form", command=self.clear_rule_form,
                 bg='#4a4a4a', fg='white', width=20).pack()
        
        # Right panel - Rules list
        right_panel = tk.Frame(rules_frame, bg='#2b2b2b')
        right_panel.pack(side='right', fill='both', expand=True, padx=5, pady=5)
        
        tk.Label(right_panel, text="Current Rules", bg='#2b2b2b', fg='white',
                font=('Arial', 12, 'bold')).pack(pady=5)
        
        # Rules treeview
        columns = ('Name', 'Action', 'Protocol', 'Source IP', 'Dest IP', 'Src Port', 'Dst Port')
        self.rules_tree = ttk.Treeview(right_panel, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.rules_tree.heading(col, text=col)
            self.rules_tree.column(col, width=90)
            
        self.rules_tree.pack(fill='both', expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(right_panel, orient='vertical', command=self.rules_tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.rules_tree.configure(yscrollcommand=scrollbar.set)
        
        # Buttons
        btn_frame = tk.Frame(right_panel, bg='#2b2b2b')
        btn_frame.pack(fill='x', pady=5)
        
        tk.Button(btn_frame, text="Delete Selected", command=self.delete_rule,
                 bg='#4a4a4a', fg='white').pack(side='left', padx=5)
        tk.Button(btn_frame, text="Toggle Rule", command=self.toggle_rule,
                 bg='#4a4a4a', fg='white').pack(side='left', padx=5)
        
    def create_logs_tab(self):
        """Create logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")
        
        # Control panel
        control_frame = tk.Frame(logs_frame, bg='#2b2b2b')
        control_frame.pack(fill='x', pady=5)
        
        tk.Button(control_frame, text="Refresh", command=self.refresh_logs,
                 bg='#4a4a4a', fg='white').pack(side='left', padx=5)
        tk.Button(control_frame, text="Clear Logs", command=self.clear_logs,
                 bg='#4a4a4a', fg='white').pack(side='left', padx=5)
        
        # Logs display
        self.logs_text = scrolledtext.ScrolledText(logs_frame, height=25,
                                                   bg='#1e1e1e', fg='white',
                                                   font=('Courier', 10))
        self.logs_text.pack(fill='both', expand=True, padx=5, pady=5)
        
    def create_blocklist_tab(self):
        """Create IP blocklist tab"""
        block_frame = ttk.Frame(self.notebook)
        self.notebook.add(block_frame, text="IP Blocklist")
        
        # Left panel - Add IP
        left_panel = tk.Frame(block_frame, bg='#2b2b2b')
        left_panel.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        tk.Label(left_panel, text="Add IP to Blocklist", bg='#2b2b2b', fg='white',
                font=('Arial', 12, 'bold')).pack(pady=5)
        
        tk.Label(left_panel, text="IP Address:", bg='#2b2b2b', fg='white').pack()
        self.block_ip_entry = tk.Entry(left_panel, width=30, bg='#3c3c3c', fg='white')
        self.block_ip_entry.pack(pady=5)
        
        tk.Button(left_panel, text="Block IP", command=self.block_ip,
                 bg='#4a4a4a', fg='white', width=20).pack(pady=5)
        
        tk.Label(left_panel, text="Or bulk add (one IP per line):", 
                bg='#2b2b2b', fg='white').pack(pady=5)
        self.bulk_text = scrolledtext.ScrolledText(left_panel, height=10,
                                                   bg='#3c3c3c', fg='white')
        self.bulk_text.pack(fill='both', expand=True, pady=5)
        
        tk.Button(left_panel, text="Bulk Block", command=self.bulk_block,
                 bg='#4a4a4a', fg='white', width=20).pack(pady=5)
        
        # Right panel - Blocked IPs list
        right_panel = tk.Frame(block_frame, bg='#2b2b2b')
        right_panel.pack(side='right', fill='both', expand=True, padx=5, pady=5)
        
        tk.Label(right_panel, text="Blocked IPs", bg='#2b2b2b', fg='white',
                font=('Arial', 12, 'bold')).pack(pady=5)
        
        self.blocked_listbox = tk.Listbox(right_panel, bg='#3c3c3c', fg='white',
                                          height=20)
        self.blocked_listbox.pack(fill='both', expand=True)
        
        tk.Button(right_panel, text="Unblock Selected", command=self.unblock_ip,
                 bg='#4a4a4a', fg='white').pack(pady=5)
        
    def toggle_monitoring(self):
        """Toggle real-time monitoring"""
        if not self.monitor_active:
            self.monitor_active = True
            self.monitor_btn.config(text="Stop Monitoring", bg='#ff5555')
            threading.Thread(target=self.monitor_traffic, daemon=True).start()
        else:
            self.monitor_active = False
            self.monitor_btn.config(text="Start Monitoring", bg='#4a4a4a')
            
    def monitor_traffic(self):
        """Monitor traffic in real-time"""
        while self.monitor_active:
            packet = self.firewall.get_next_packet()
            if packet:
                filter_text = self.filter_entry.get().lower()
                packet_str = str(packet)
                
                if not filter_text or filter_text in packet_str.lower():
                    self.root.after(0, self.display_packet, packet)
            time.sleep(0.1)
            
    def display_packet(self, packet):
        """Display packet in monitor"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        status = "BLOCKED" if packet.get('blocked') else "ALLOWED"
        tag = 'blocked' if packet.get('blocked') else 'allowed'
        
        line = f"[{timestamp}] {status}: {packet['src_ip']} -> {packet['dst_ip']} "
        line += f"({packet['protocol']}) Port: {packet.get('dst_port', 'N/A')}\n"
        
        self.monitor_text.insert(tk.END, line, tag)
        self.monitor_text.see(tk.END)
        
    def clear_monitor(self):
        """Clear monitor display"""
        self.monitor_text.delete(1.0, tk.END)
        
    def add_rule(self):
        """Add new firewall rule"""
        rule = {
            'name': self.rule_entries['name_entry'].get(),
            'action': self.rule_entries['action_combo'].get(),
            'protocol': self.rule_entries['protocol_combo'].get(),
            'src_ip': self.rule_entries['src_ip_entry'].get() or None,
            'dst_ip': self.rule_entries['dst_ip_entry'].get() or None,
            'src_port': self.rule_entries['src_port_entry'].get() or None,
            'dst_port': self.rule_entries['dst_port_entry'].get() or None
        }
        
        if rule['name']:
            self.firewall.add_rule(rule)
            self.update_rules_display()
            self.clear_rule_form()
            messagebox.showinfo("Success", "Rule added successfully")
        else:
            messagebox.showwarning("Warning", "Please enter a rule name")
            
    def delete_rule(self):
        """Delete selected rule"""
        selected = self.rules_tree.selection()
        if selected:
            rule_name = self.rules_tree.item(selected[0])['values'][0]
            self.firewall.remove_rule(rule_name)
            self.update_rules_display()
            
    def toggle_rule(self):
        """Toggle rule enabled/disabled"""
        selected = self.rules_tree.selection()
        if selected:
            rule_name = self.rules_tree.item(selected[0])['values'][0]
            self.firewall.toggle_rule(rule_name)
            self.update_rules_display()
            
    def clear_rule_form(self):
        """Clear rule input form"""
        self.rule_entries['name_entry'].delete(0, tk.END)
        self.rule_entries['action_combo'].set('ALLOW')
        self.rule_entries['protocol_combo'].set('ANY')
        self.rule_entries['src_ip_entry'].delete(0, tk.END)
        self.rule_entries['dst_ip_entry'].delete(0, tk.END)
        self.rule_entries['src_port_entry'].delete(0, tk.END)
        self.rule_entries['dst_port_entry'].delete(0, tk.END)

    # add to the imports at the top of the file   
    def block_ip(self):
        """Block single IP""" # raises valueerror if invalid
        ip = self.block_ip_entry.get().strip()
        if ip:
            self.firewall.block_ip(ip)
            self.update_blocklist()
            self.block_ip_entry.delete(0, tk.END)
            messagebox.showinfo("Success", f"IP {ip} blocked")
            
    def bulk_block(self):
        """Block multiple IPs"""
        ips = self.bulk_text.get(1.0, tk.END).strip().split('\n')
        count = 0
        for ip in ips:
            if ip.strip():
                self.firewall.block_ip(ip.strip())
                count += 1
                
        self.update_blocklist()
        self.bulk_text.delete(1.0, tk.END)
        messagebox.showinfo("Success", f"Blocked {count} IPs")
        
    def unblock_ip(self):
        """Unblock selected IP"""
        selected = self.blocked_listbox.curselection()
        if selected:
            ip = self.blocked_listbox.get(selected[0])
            self.firewall.unblock_ip(ip)
            self.update_blocklist()
            
    def update_blocklist(self):
        """Update blocked IPs list"""
        self.blocked_listbox.delete(0, tk.END)
        for ip in sorted(self.firewall.blocked_ips):
            self.blocked_listbox.insert(tk.END, ip)
            
    def update_stats(self):
        """Update statistics display"""
        stats = self.firewall.get_stats()
        
        self.stats_vars['total'].set(str(stats['total_packets']))
        self.stats_vars['blocked'].set(str(stats['blocked_packets']))
        self.stats_vars['rules'].set(str(len(self.firewall.rules)))
        
        # Schedule next update
        self.root.after(1000, self.update_stats)
        
    def update_rules_display(self):
        # Reject duplicate names - toggle/delete rely on uniqueness
        """Update rules treeview"""
        # Clear current items
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
            
        # Add rules
        for rule in self.firewall.rules:
            if rule.get('enabled', True):
                values = (
                    rule['name'],
                    rule['action'],
                    rule['protocol'],
                    rule.get('src_ip', 'ANY'),
                    rule.get('dst_ip', 'ANY'),
                    rule.get('src_port', 'ANY'),
                    rule.get('dst_port', 'ANY')
                )
                self.rules_tree.insert('', tk.END, values=values)
                
    def refresh_logs(self):
        """Refresh logs display"""
        self.logs_text.delete(1.0, tk.END)
        logs = self.firewall.get_logs()
        for log in logs[-100:]:
            self.logs_text.insert(tk.END, log + '\n')
     #  add clear logs        
    def clear_logs(self):
        """Clear all logs"""
        if messagebox.askyesno("Confirm", "Clear all logs?"):
            self.firewall.clear_logs()
            self.logs_text.delete(1.0, tk.END)
            
    def export_logs(self):
        """Export logs to file"""
        filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text files", "*.txt")])
        if filename:
            self.firewall.export_logs(filename)
            messagebox.showinfo("Success", f"Logs exported to {filename}")
            
    def import_rules(self):
        """Import rules from file"""
        filename = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if filename:
            self.firewall.import_rules(filename)
            self.update_rules_display()
            messagebox.showinfo("Success", "Rules imported successfully")
            
    def show_about(self):
        """Show about dialog"""
        about_text = """Simple Firewall Protection Tool
Version 1.0

A basic firewall management tool
with real-time monitoring.

Features:
- Live traffic monitoring
- Firewall rule management
- IP blocking
- Log management

Created with Python and tkinter
"""
        messagebox.showinfo("About", about_text)


class FirewallEngine:
    def __init__(self):
        self.rules = []
        self.blocked_ips = set()
        self.packet_count = 0
        self.blocked_count = 0
        self.start_time = time.time()
        self.logs = []
        self.packet_queue = queue.Queue()
        self.running = True
        
        # Load default rules
        self.load_default_rules()
        
    def load_default_rules(self):
        """Load default rules"""
        # Source IP check - support both exact match and CIDR notation
        default_rules = [
            {'name': 'Allow HTTP', 'action': 'ALLOW', 'protocol': 'TCP', 'dst_port': '80'},
            {'name': 'Allow HTTPS', 'action': 'ALLOW', 'protocol': 'TCP', 'dst_port': '443'},
            {'name': 'Block SSH', 'action': 'DENY', 'protocol': 'TCP', 'dst_port': '22'}
        ]
        
        for rule in default_rules:
            rule['enabled'] = True
            self.rules.append(rule)
   # start engine         
    def start(self):
        """Start firewall engine"""
        threading.Thread(target=self._process_packets, daemon=True).start()
        
    def _process_packets(self):
        """Process simulated packets"""
        while self.running:
            self._simulate_packet()
            time.sleep(0.2)
            
    def _simulate_packet(self):
        """Simulate network packet"""
        protocols = ['TCP', 'UDP', 'ICMP']
        ips = ['192.168.1.' + str(random.randint(2, 254)) for _ in range(5)]
        ports = [80, 443, 22, 3389, 8080, 53]
        # In __init__:
        packet = {
            'src_ip': random.choice(ips),
            'dst_ip': random.choice(ips),
            'protocol': random.choice(protocols),
            'src_port': random.choice(ports) if random.random() > 0.3 else None,
            'dst_port': random.choice(ports) if random.random() > 0.3 else None,
            'timestamp': time.time()
        }
        
        # Check packet
        packet['blocked'] = not self.check_packet(packet) # In _simulate_packet -unsynchromised increments:
        
        if packet['blocked']:
            self.blocked_count += 1
            # add one block object
            self.add_log(f"Blocked: {packet['src_ip']} -> {packet['dst_ip']} ({packet['protocol']})")
        else:
            self.add_log(f"Allowed: {packet['src_ip']} -> {packet['dst_ip']} ({packet['protocol']})")
            
        self.packet_count += 1
        # In _simulate_packet - drop packet if GUI is too slow:
        self.packet_queue.put(packet)
        
    def check_packet(self, packet):
        """Check if packet should be allowed"""
        # Check blocked IPs
        if packet['src_ip'] in self.blocked_ips:
            return False
            
        # Check rules
        for rule in self.rules:
            if not rule.get('enabled', True):
                continue
                
            if self.match_rule(rule, packet):
                return rule['action'] == 'ALLOW'
                
        return True  # Default allow
        
    def match_rule(self, rule, packet):
        """Check if packet matches rule"""
        # Protocol check
        if rule.get('protocol') and rule['protocol'] != 'ANY':
            if rule['protocol'] != packet['protocol']:
                return False
                
        # Port check
        if rule.get('dst_port'):
            if str(rule['dst_port']) != str(packet.get('dst_port')):
                return False
                
        # IP check
        if rule.get('src_ip') and rule['src_ip'] != packet['src_ip']:
            return False
        # result true    
        return True
        
    def add_rule(self, rule):
        """Add firewall rule"""
        rule['enabled'] = True
        self.rules.append(rule)
        self.add_log(f"Added rule: {rule['name']}")
    # add remove rule    
    def remove_rule(self, rule_name):
        """Remove rule"""
        self.rules = [r for r in self.rules if r['name'] != rule_name]
        self.add_log(f"Removed rule: {rule_name}")
        
    def toggle_rule(self, rule_name):
        """Toggle rule state"""
        for rule in self.rules:
            if rule['name'] == rule_name:
                rule['enabled'] = not rule.get('enabled', True)
                state = "enabled" if rule['enabled'] else "disabled"
                self.add_log(f"Rule {rule_name} {state}")
                break
                
    def block_ip(self, ip):
        """Block IP address"""
        self.blocked_ips.add(ip)
        self.add_log(f"Blocked IP: {ip}")
        
    def unblock_ip(self, ip):
        """Unblock IP address"""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self.add_log(f"Unblocked IP: {ip}")
            
    def get_next_packet(self):
        """Get next packet from queue"""
        try:
            return self.packet_queue.get_nowait()
        except queue.Empty:
            return None
            
    def get_stats(self):
        """Get statistics"""
        return {
            'total_packets': self.packet_count,# integer total since engine started
            'blocked_packets': self.blocked_count
        }
        
    def add_log(self, message):
        """Add log entry"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
       # In __init__ - replace the empty List:
       #add logs
        self.logs.append(f"[{timestamp}] {message}")
        
        if len(self.logs) > 1000:
            self.logs = self.logs[-1000:]
            
    def get_logs(self):
        """Get all logs"""
        return self.logs
        
    def clear_logs(self):
        """Clear logs"""
        self.logs = []
        
    def export_logs(self, filename):
        """Export logs to file"""
        with open(filename, 'w') as f:
            for log in self.logs:
                f.write(log + '\n')
                
    def import_rules(self, filename):# add to GUI import if not already present
        """Import rules from JSON"""
        try:
            with open(filename, 'r') as f:
                rules = json.load(f)
                for rule in rules:
                    rule['enabled'] = True
                    self.rules.append(rule)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import rules: {e}")


def main():
    root = tk.Tk()
    app = SimpleFirewallGUI(root)
    
    def on_closing():
        app.firewall.running = False
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()