import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime

from bus.alert_bus import ALERT_BUS
from bus.packet_bus import PACKET_BUS

# ---------------- CONFIG ----------------
BG = "#0d1117"
FG = "#c9d1d9"
ACCENT = "#58a6ff"
GREEN = "#3fb950"
RED = "#f85149"
ORANGE = "#d29922"
YELLOW = "#f0883e"
HEADER_BG = "#161b22"
CARD_BG = "#0d1117"
BORDER = "#30363d"
SHADOW = "#010409"

MAX_PACKETS = 5000
UPDATE_INTERVAL = 250  # ms


# ---------------------------------------


class IDSApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Live IDS Monitor")
        self.geometry("1600x900")
        self.configure(bg=BG)

        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Enhanced ttk styles with better contrast and modern look
        self.style.configure(
            "Treeview",
            background=CARD_BG,
            foreground=FG,
            fieldbackground=CARD_BG,
            rowheight=28,
            borderwidth=0
        )
        self.style.map(
            "Treeview",
            background=[("selected", ACCENT)],
            foreground=[("selected", "#ffffff")]
        )
        self.style.configure(
            "Treeview.Heading",
            background=HEADER_BG,
            foreground=ACCENT,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            borderwidth=0
        )
        self.style.map(
            "Treeview.Heading",
            background=[("active", BORDER)]
        )

        # PanedWindow styling
        self.style.configure("TPanedwindow", background=BG)
        self.style.configure("Sash", sashthickness=4, background=BORDER)

        self._build_ui()
        self.after(UPDATE_INTERVAL, self.update_ui)

    def _build_ui(self):
        main = tk.Frame(self, bg=BG)
        main.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)

        # Enhanced header with gradient-like effect
        header_frame = tk.Frame(main, bg=HEADER_BG, height=60)
        header_frame.pack(fill=tk.X, pady=(0, 16))
        header_frame.pack_propagate(False)

        header = tk.Label(
            header_frame,
            text="🛡️ Live Intrusion Detection System Monitor",
            bg=HEADER_BG,
            fg=ACCENT,
            font=("Segoe UI", 18, "bold")
        )
        header.pack(pady=12)

        def section_header(parent, text, emoji=""):
            frame = tk.Frame(parent, bg=HEADER_BG, height=40)
            frame.pack(fill=tk.X)
            frame.pack_propagate(False)

            lbl = tk.Label(
                frame,
                text=f"{emoji} {text}",
                bg=HEADER_BG,
                fg=ACCENT,
                font=("Segoe UI", 12, "bold"),
                anchor="w",
                padx=16
            )
            lbl.pack(fill=tk.BOTH, expand=True)

            # Bottom border
            border = tk.Frame(parent, bg=BORDER, height=2)
            border.pack(fill=tk.X)

        paned = ttk.PanedWindow(main, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        # Left: Alerts with card-like appearance
        left_container = tk.Frame(paned, bg=BG)
        paned.add(left_container, weight=1)

        left_frame = tk.Frame(
            left_container,
            bg=CARD_BG,
            relief=tk.FLAT,
            highlightbackground=BORDER,
            highlightthickness=2
        )
        left_frame.pack(fill=tk.BOTH, expand=True, padx=(0, 8))

        section_header(left_frame, "Security Alerts", "🚨")

        # Alerts text area with custom scrollbar
        self.alerts_text = scrolledtext.ScrolledText(
            left_frame,
            bg=CARD_BG,
            fg=FG,
            insertbackground=ACCENT,
            font=("Consolas", 10),
            wrap=tk.NONE,
            relief=tk.FLAT,
            bd=0,
            padx=12,
            pady=12
        )
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 2))
        self.alerts_text.configure(state=tk.DISABLED)

        # Enhanced text tags with better styling
        self.alerts_text.tag_config("time", foreground=ACCENT, font=("Consolas", 9))
        self.alerts_text.tag_config("attack", foreground=RED, font=("Consolas", 11, "bold"))
        self.alerts_text.tag_config("attacker", foreground=ORANGE, font=("Consolas", 10, "bold"))
        self.alerts_text.tag_config("details", foreground=FG)
        self.alerts_text.tag_config("sep", foreground=BORDER)

        # Right: Live Traffic with card-like appearance
        right_container = tk.Frame(paned, bg=BG)
        paned.add(right_container, weight=3)

        right_frame = tk.Frame(
            right_container,
            bg=CARD_BG,
            relief=tk.FLAT,
            highlightbackground=BORDER,
            highlightthickness=2
        )
        right_frame.pack(fill=tk.BOTH, expand=True, padx=(8, 0))

        section_header(right_frame, "Live Network Traffic", "📡")

        # Treeview container with custom styling
        tree_container = tk.Frame(right_frame, bg=CARD_BG)
        tree_container.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 2))

        columns = ("Time", "Src IP", "Src MAC", "Dst IP", "Dst MAC", "Protocol", "Location", "Info", "Status")
        self.packet_tree = ttk.Treeview(
            tree_container,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        # Scrollbars
        vsb = ttk.Scrollbar(tree_container, orient="vertical", command=self.packet_tree.yview)
        hsb = ttk.Scrollbar(tree_container, orient="horizontal", command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)

        widths = [100, 140, 140, 140, 140, 90, 150, 400, 90]
        for col, width in zip(columns, widths):
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, anchor="w", width=width)

        self.packet_tree.column("Time", anchor="center")
        self.packet_tree.column("Status", anchor="center")
        self.packet_tree.column("Location", anchor="w")

        # Enhanced color tags - Green for normal, Red for suspicious
        self.packet_tree.tag_configure(
            "suspicious",
            foreground=RED,
            background="#1a0f0f",
            font=("Consolas", 9, "bold")
        )
        self.packet_tree.tag_configure(
            "normal",
            foreground=GREEN,
            background="#0d1117"
        )

        paned.sashpos(0, 550)

    def update_ui(self):
        self._update_alerts()
        self._update_packets()
        self.after(UPDATE_INTERVAL, self.update_ui)

    def _update_alerts(self):
        alerts = ALERT_BUS.get_all()
        if not alerts:
            return

        self.alerts_text.config(state=tk.NORMAL)
        for a in alerts:
            self.alerts_text.insert(tk.END, "\n" + "━" * 90 + "\n", "sep")
            # Convert timestamp to local timezone
            alert_time = datetime.fromtimestamp(a['time']).strftime("%Y-%m-%d %H:%M:%S")
            self.alerts_text.insert(tk.END, f"⏰ {alert_time}\n", "time")
            self.alerts_text.insert(tk.END, f"🎯 ATTACK: {a['attack']}\n", "attack")
            self.alerts_text.insert(tk.END, f"👤 ATTACKER: {a['attacker']} ({a['geo']})\n", "attacker")
            self.alerts_text.insert(tk.END, f"📝 DETAILS: {a['details']}\n", "details")
        self.alerts_text.see(tk.END)
        self.alerts_text.config(state=tk.DISABLED)

    def _update_packets(self):
        packets = PACKET_BUS.get_all()
        if not packets:
            return

        for pkt, suspicious in packets:
            try:
                # Convert timestamp to local timezone in HH:MM:SS format
                if hasattr(pkt, 'time'):
                    timestamp = datetime.fromtimestamp(pkt.time).strftime("%H:%M:%S")
                else:
                    timestamp = ""

                # Get MAC addresses from Ethernet layer
                src_mac = pkt.getlayer('Ether').src if pkt.haslayer('Ether') else ''
                dst_mac = pkt.getlayer('Ether').dst if pkt.haslayer('Ether') else ''

                # Get IP addresses from IP layer
                src_ip = ''
                dst_ip = ''
                if pkt.haslayer('IP'):
                    src_ip = pkt.getlayer('IP').src
                    dst_ip = pkt.getlayer('IP').dst
                elif pkt.haslayer('IPv6'):
                    src_ip = pkt.getlayer('IPv6').src
                    dst_ip = pkt.getlayer('IPv6').dst

                proto = getattr(pkt, 'proto', getattr(pkt, 'highest_layer', ''))

                # Get geographical location
                location = getattr(pkt, 'geo', '')

                info = pkt.summary() if callable(getattr(pkt, 'summary', None)) else str(pkt)
            except Exception:
                timestamp = src_ip = src_mac = dst_ip = dst_mac = proto = location = info = ""

            # Status with emoji indicators
            status = "🚨 THREAT" if suspicious else "✓ SAFE"

            self.packet_tree.insert(
                "",
                "end",
                values=(timestamp, src_ip, src_mac, dst_ip, dst_mac, proto, location, info, status),
                tags=("suspicious" if suspicious else "normal",)
            )

        children = self.packet_tree.get_children()
        if len(children) > MAX_PACKETS:
            excess = len(children) - MAX_PACKETS
            for child in children[:excess]:
                self.packet_tree.delete(child)

        if children:
            self.packet_tree.see(children[-1])


def start_gui():
    app = IDSApp()
    app.mainloop()