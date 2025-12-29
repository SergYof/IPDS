import tkinter as tk
from tkinter import ttk
from datetime import datetime
import threading
import time
import random

# ──────────────────────────────────────────────
# Dark theme palette & Constants
# ──────────────────────────────────────────────
BG_MAIN = "#0f111a"
BG_PANEL = "#161925"
FG_TEXT = "#e6e6e6"
FG_HEADER = "#ffffff"

SEVERITY_COLORS = {
    "INFO": "#9aa5ce",
    "LOW": "#7dcfff",
    "MEDIUM": "#ff9e64",
    "HIGH": "#f7768e",
    "CRITICAL": "#ff007c",
}


class IDPSGui:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("IDPS Dashboard")
        self.root.geometry("1000x650")
        self.root.configure(bg=BG_MAIN)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.panels = {}
        self._build_layout()

    # ──────────────────────────────────────────────
    # Layout Builder
    # ──────────────────────────────────────────────
    def _build_layout(self):
        # Header
        header = tk.Label(
            self.root,
            text="Intrusion Detection & Prevention System",
            bg=BG_MAIN,
            fg=FG_HEADER,
            font=("Segoe UI", 18, "bold")
        )
        header.pack(pady=15)

        # Container for panels
        container = tk.Frame(self.root, bg=BG_MAIN)
        container.pack(fill="both", expand=True, padx=12, pady=12)

        # Grid weights
        container.columnconfigure((0, 1), weight=1)
        container.rowconfigure((0, 1), weight=1)

        # Create 4 panels
        self.panels = {
            "ARP": self._create_panel(container, "ARP Spoofing", 0, 0),
            "DNS": self._create_panel(container, "DNS Spoofing", 0, 1),
            "MITM": self._create_panel(container, "MITM Attacks", 1, 0),
            "PORT": self._create_panel(container, "Port Scanning", 1, 1),
        }

    def _create_panel(self, parent, title, row, col):
        frame = tk.LabelFrame(
            parent,
            text=title,
            bg=BG_PANEL,
            fg=FG_TEXT,
            font=("Segoe UI", 11, "bold"),
            bd=2,
            relief="groove"
        )
        frame.grid(row=row, column=col, sticky="nsew", padx=8, pady=8)

        text = tk.Text(
            frame,
            bg=BG_PANEL,
            fg=FG_TEXT,
            insertbackground=FG_TEXT,
            wrap="word",
            state="disabled",
            font=("Consolas", 10),
            relief="flat"
        )

        scrollbar = tk.Scrollbar(
            frame,
            command=text.yview,
            bg=BG_PANEL,
            troughcolor=BG_MAIN,
            activebackground=BG_MAIN
        )

        text.configure(yscrollcommand=scrollbar.set)

        text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Configure color tags for severities
        for sev, color in SEVERITY_COLORS.items():
            text.tag_config(sev, foreground=color)

        return text

    # ──────────────────────────────────────────────
    # Public API (Thread-Safe)
    # ──────────────────────────────────────────────
    def add_alert(self, category: str, message: str, severity="INFO"):
        """
        Adds a log message to the specified category panel.
        This method is thread-safe; it uses .after() to schedule the UI update.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        severity = severity.upper()

        def _update():
            if category not in self.panels:
                return

            panel = self.panels[category]
            panel.configure(state="normal")  # Unlock to write

            # Insert text with the severity tag for color
            panel.insert(
                "end",
                f"[{timestamp}] [{severity}] {message}\n",
                severity
            )

            panel.configure(state="disabled")  # Lock again
            panel.see("end")  # Auto-scroll to bottom

        # Schedule the update on the main GUI thread
        self.root.after(0, _update)

    # ──────────────────────────────────────────────
    # Lifecycle
    # ──────────────────────────────────────────────
    def on_close(self):
        self.root.destroy()
        # In a real app, you might signal threads to stop here

    def run(self):
        self.root.mainloop()


# ──────────────────────────────────────────────
# Main Execution (With Threading Fix)
# ──────────────────────────────────────────────
if __name__ == "__main__":
    gui = IDPSGui()


    # Define a function to simulate network traffic in the background
    def simulate_traffic():
        time.sleep(1)  # Wait for GUI to open

        alerts = [
            ("ARP", "Gateway MAC address changed unexpectedly", "HIGH"),
            ("DNS", "Response ID mismatch for google.com", "MEDIUM"),
            ("PORT", "SYN scan detected from 192.168.1.15", "LOW"),
            ("MITM", "SSL Certificate mismatch detected", "CRITICAL"),
            ("ARP", "Duplicate IP detected on network", "INFO"),
            ("MITM", "Packet sequence analysis suggests tampering", "HIGH"),
            ("DNS", "DNS cache poisoning attempt", "CRITICAL"),
        ]

        print("Network Simulation: Started")

        # Keep running to prove the window updates live
        for i in range(20):
            # Check if window is still open before trying to update
            try:
                if not gui.root.winfo_exists():
                    break
            except tk.TclError:
                break

            category, msg, sev = random.choice(alerts)
            gui.add_alert(category, msg, sev)
            time.sleep(random.uniform(0.5, 1.5))  # Random delay

        print("Network Simulation: Finished")


    # Start the simulation in a separate daemon thread
    # Daemon means this thread dies automatically when the main program closes
    t = threading.Thread(target=simulate_traffic, daemon=True)
    t.start()

    # Start the GUI (This blocks until window is closed)
    gui.run()