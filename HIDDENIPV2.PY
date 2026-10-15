"""
HiddenIP v2 — Scanner de sub-rede com detecção de MAC, fabricante, hostname,
portas abertas, serviços e banners.

Dependência obrigatória:  pip install ping3
Opcionais (melhoram o reconhecimento do fabricante do MAC):
    pip install mac-vendor-lookup
    ou coloque um arquivo "oui.txt" (lista oficial da IEEE) na mesma pasta.

Use apenas em redes suas ou com autorização de quem administra a rede.
"""

import csv
import errno
import ipaddress
import os
import queue
import re
import socket
import ssl
import subprocess
import threading
import time
import tkinter as tk
import webbrowser
from bisect import bisect_left
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import filedialog, messagebox, ttk

from ping3 import ping

# ----------------------------------------------------------------------------
# Dados de referência
# ----------------------------------------------------------------------------

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCbind", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 515: "LPD",
    548: "AFP", 554: "RTSP", 587: "SMTP-Sub", 631: "IPP", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 1883: "MQTT",
    2049: "NFS", 3000: "HTTP-Dev", 3306: "MySQL", 3389: "RDP", 5000: "HTTP-Alt",
    5060: "SIP", 5432: "PostgreSQL", 5555: "ADB", 5900: "VNC", 5985: "WinRM",
    6379: "Redis", 7547: "TR-069", 8000: "HTTP-Alt", 8008: "HTTP-Alt",
    8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "HTTP-Alt", 9100: "JetDirect", 9200: "Elasticsearch",
    27017: "MongoDB", 32400: "Plex", 62078: "iPhone-Sync",
}

QUICK_PORTS = [21, 22, 23, 25, 53, 80, 135, 139, 143, 443, 445, 554, 3306,
               3389, 5900, 8000, 8080, 8443, 9100, 62078]

# Portas que merecem atenção quando expostas na rede
RISKY = {
    21: "FTP trafega senha sem criptografia",
    23: "Telnet trafega tudo sem criptografia",
    445: "SMB exposto (alvo comum de ataques)",
    1883: "MQTT geralmente sem TLS/autenticação",
    2049: "NFS exposto",
    3389: "RDP exposto (alvo comum de força bruta)",
    5555: "Android Debug Bridge aberto",
    5900: "VNC exposto",
    6379: "Redis geralmente sem senha",
    7547: "TR-069 (gerenciamento remoto de roteador)",
    9200: "Elasticsearch geralmente sem autenticação",
    27017: "MongoDB geralmente sem autenticação",
}

HTTP_PORTS = {80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000}
TLS_PORTS = {443, 465, 993, 995, 8443}
SILENT_PORTS = {135, 139, 445, 3389, 5985, 62078}   # não "falam" primeiro
PROBE_PORTS = (445, 80, 443, 22, 3389, 62078)       # detecção quando ICMP é bloqueado
ALIVE_CODES = {0, errno.ECONNREFUSED, 10061}        # conectou ou foi recusado = host vivo

VENDOR_HINTS = {
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading", "D8:3A:DD": "Raspberry Pi Trading",
    "00:50:56": "VMware", "00:0C:29": "VMware", "00:05:69": "VMware",
    "08:00:27": "VirtualBox (Oracle)", "52:54:00": "QEMU/KVM",
    "00:15:5D": "Microsoft Hyper-V", "00:1C:42": "Parallels",
    "3C:5A:B4": "Google", "F4:F5:D8": "Google", "00:17:88": "Philips Hue",
}


# ----------------------------------------------------------------------------
# Funções utilitárias (sem interface gráfica)
# ----------------------------------------------------------------------------

def ip_key(ip):
    return int(ipaddress.IPv4Address(ip))


def normalize_mac(raw):
    """Converte aa-bb-c:d... para AA:BB:0C:0D... e descarta broadcast/multicast."""
    parts = re.split(r"[:-]", raw.strip())
    if len(parts) != 6:
        return None
    try:
        octets = [int(p, 16) for p in parts]
    except ValueError:
        return None
    if all(o == 0 for o in octets) or all(o == 255 for o in octets) or octets[0] & 1:
        return None
    return ":".join(f"{o:02X}" for o in octets)


def read_arp_table():
    """Lê a tabela ARP do sistema (Linux, Windows e macOS). Retorna {ip: mac}."""
    table = {}
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", encoding="utf-8") as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] != "0x0":
                        mac = normalize_mac(parts[3])
                        if mac:
                            table[parts[0]] = mac
            return table
        except OSError:
            pass
    try:
        out = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return table
    pattern = re.compile(
        r"(\d{1,3}(?:\.\d{1,3}){3}).*?((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})"
    )
    for line in out.splitlines():
        m = pattern.search(line)
        if m:
            mac = normalize_mac(m.group(2))
            if mac:
                table[m.group(1)] = mac
    return table


class VendorDB:
    """Descobre o fabricante pelo prefixo (OUI) do MAC."""

    def __init__(self):
        self.local = {}
        self.lib = None
        self._load_oui_file()
        try:
            from mac_vendor_lookup import MacLookup
            self.lib = MacLookup()
        except Exception:
            self.lib = None

    def _load_oui_file(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui.txt")
        if not os.path.exists(path):
            return
        rx = re.compile(r"^\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$")
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    m = rx.match(line)
                    if m:
                        self.local[":".join(m.group(i).upper() for i in (1, 2, 3))] = m.group(4)
        except OSError:
            pass

    def lookup(self, mac):
        if not mac:
            return ""
        prefix = mac[:8]
        if prefix in self.local:
            return self.local[prefix]
        if self.lib:
            try:
                return self.lib.lookup(mac)
            except Exception:
                pass
        if prefix in VENDOR_HINTS:
            return VENDOR_HINTS[prefix]
        if int(mac[:2], 16) & 2:
            return "MAC aleatório/privado"
        return "Desconhecido"


def service_name(port):
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "desconhecido"


def parse_ports(text):
    ports = set()
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    if not ports:
        raise ValueError("nenhuma porta informada")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("portas devem estar entre 1 e 65535")
    if len(ports) > 5000:
        raise ValueError("máximo de 5000 portas por host")
    return sorted(ports)


def tcp_connect(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port))
    except OSError:
        return -1
    finally:
        s.close()


def clean_text(s, limit=140):
    s = "".join(c if c.isprintable() and c != "\ufffd" else " " for c in s)
    return " ".join(s.split())[:limit]


def format_banner(data):
    if not data:
        return ""
    text = data.decode("utf-8", errors="replace")
    if text.startswith("HTTP/"):
        head, _, body = text.partition("\r\n\r\n")
        lines = head.split("\r\n")
        status = lines[0].split(" ", 1)[1] if " " in lines[0] else lines[0]
        server = next(
            (ln.split(":", 1)[1].strip() for ln in lines[1:] if ln.lower().startswith("server:")), ""
        )
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        parts = [status]
        if server:
            parts.append(f"Server: {server}")
        if title:
            parts.append(f"Título: {' '.join(title.group(1).split())}")
        return clean_text(" | ".join(parts))
    first = next((ln for ln in text.splitlines() if ln.strip()), "")
    return clean_text(first)


def read_banner(sock, ip, port):
    wrapped = None
    try:
        sock.settimeout(1.5)
        conn = sock
        if port in TLS_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("DEFAULT:@SECLEVEL=0")  # aceita dispositivos antigos
            except ssl.SSLError:
                pass
            conn = wrapped = ctx.wrap_socket(sock)
        if port in HTTP_PORTS:
            conn.sendall(
                f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: HiddenIP\r\nConnection: close\r\n\r\n".encode()
            )
        return format_banner(conn.recv(4096))
    except OSError:
        return ""
    finally:
        for s in (wrapped, sock):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def probe_port(ip, port, timeout, want_banner):
    """Retorna dict se a porta estiver aberta, senão None."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    info = {"port": port, "service": service_name(port), "banner": ""}
    if want_banner and port not in SILENT_PORTS:
        info["banner"] = read_banner(sock, ip, port)
    else:
        sock.close()
    return info


# ----------------------------------------------------------------------------
# Aplicação
# ----------------------------------------------------------------------------

class HiddenIPScannerApp:

    def __init__(self, root):
        self.root = root
        self.root.title("HiddenIP — Subnet Scanner v2")
        self.root.geometry("1180x760")
        self.root.minsize(980, 600)

        # Paleta (preto e azul)
        self.COLOR_BG = "#0b0c10"
        self.COLOR_PANEL = "#1f2833"
        self.COLOR_TEXT_MAIN = "#c5c6c7"
        self.COLOR_ACCENT = "#1f4068"
        self.COLOR_ACCENT_HOVER = "#00f5ff"
        self.COLOR_ONLINE = "#2ecc71"
        self.COLOR_OFFLINE = "#e74c3c"
        self.COLOR_WARN = "#f1c40f"
        self.COLOR_CYAN = "#66fcf1"
        self.root.configure(bg=self.COLOR_BG)

        # Estado
        self.scanning = False
        self.stop_event = threading.Event()
        self.events = queue.Queue()
        self.results = {}          # ip -> dict
        self.shown = []            # chaves (int) das linhas visíveis, em ordem
        self.dirty = False
        self.arp_cache = {}
        self.arp_time = 0.0
        self.arp_lock = threading.Lock()
        self.icmp_blocked = False
        self.vendors = VendorDB()

        self._build_styles()
        self._build_ui()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(80, self.poll_events)

    # ------------------------------------------------------------------ UI --

    def _build_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("default")
        self.style.configure(
            "Treeview", background=self.COLOR_PANEL, foreground=self.COLOR_TEXT_MAIN,
            rowheight=28, fieldbackground=self.COLOR_PANEL, borderwidth=0,
            font=("Segoe UI", 10),
        )
        self.style.map("Treeview", background=[("selected", self.COLOR_ACCENT)],
                       foreground=[("selected", "white")])
        self.style.configure(
            "Treeview.Heading", background="#11141a", foreground=self.COLOR_CYAN,
            font=("Segoe UI", 10, "bold"), borderwidth=0,
        )
        self.style.map("Treeview.Heading", background=[("active", self.COLOR_PANEL)])
        self.style.configure(
            "Neon.Horizontal.TProgressbar", troughcolor=self.COLOR_BG,
            background=self.COLOR_CYAN, thickness=8, borderwidth=0,
        )
        self.style.configure(
            "TCombobox", fieldbackground=self.COLOR_BG, background=self.COLOR_PANEL,
            foreground="white", arrowcolor=self.COLOR_CYAN, borderwidth=0,
        )
        self.style.map(
            "TCombobox", fieldbackground=[("readonly", self.COLOR_BG)],
            foreground=[("readonly", "white")],
            selectbackground=[("readonly", self.COLOR_BG)],
            selectforeground=[("readonly", "white")],
        )
        self.root.option_add("*TCombobox*Listbox.background", self.COLOR_BG)
        self.root.option_add("*TCombobox*Listbox.foreground", "white")
        self.root.option_add("*TCombobox*Listbox.selectBackground", self.COLOR_ACCENT)

    def _label(self, parent, text, **kw):
        opts = dict(font=("Segoe UI", 9, "bold"), bg=self.COLOR_PANEL, fg=self.COLOR_TEXT_MAIN)
        opts.update(kw)
        return tk.Label(parent, text=text, **opts)

    def _check(self, parent, text, var, command=None):
        return tk.Checkbutton(
            parent, text=text, variable=var, command=command, bg=self.COLOR_PANEL,
            fg=self.COLOR_TEXT_MAIN, selectcolor=self.COLOR_BG,
            activebackground=self.COLOR_PANEL, activeforeground="white",
            bd=0, highlightthickness=0, font=("Segoe UI", 9),
        )

    def _build_ui(self):
        tk.Label(self.root, text="HiddenIP", font=("Segoe UI", 24, "bold"),
                 fg=self.COLOR_CYAN, bg=self.COLOR_BG).pack(pady=(12, 0))
        tk.Label(self.root, text="ADVANCED NETWORK STATUS SCANNER", font=("Segoe UI", 9, "bold"),
                 fg="#45f3ff", bg=self.COLOR_BG).pack(pady=(0, 10))

        # --- Configurações ---
        cfg = tk.Frame(self.root, bg=self.COLOR_PANEL)
        cfg.pack(fill="x", padx=25, pady=6)

        self._label(cfg, "ALVO (IP ou CIDR):").grid(row=0, column=0, sticky="w", padx=(15, 5), pady=(12, 4))
        self.entry_ip = tk.Entry(cfg, font=("Segoe UI", 11), width=18, bg=self.COLOR_BG, fg="white",
                                 insertbackground="white", bd=1, relief="flat")
        self.entry_ip.insert(0, "192.168.1.0")
        self.entry_ip.grid(row=0, column=1, padx=5, pady=(12, 4), sticky="w")

        self._label(cfg, "MÁSCARA:").grid(row=0, column=2, sticky="w", padx=(15, 5), pady=(12, 4))
        self.combo_mask = ttk.Combobox(
            cfg, font=("Segoe UI", 10), width=16, state="readonly",
            values=["/24 (254 IPs)", "/25 (126 IPs)", "/26 (62 IPs)", "/27 (30 IPs)",
                    "/28 (14 IPs)", "/29 (6 IPs)", "/30 (2 IPs)", "/23 (510 IPs)",
                    "/22 (1022 IPs)", "/21 (2046 IPs)", "/20 (4094 IPs)"],
        )
        self.combo_mask.set("/24 (254 IPs)")
        self.combo_mask.grid(row=0, column=3, padx=5, pady=(12, 4), sticky="w")

        self._label(cfg, "PORTAS:").grid(row=1, column=0, sticky="w", padx=(15, 5), pady=4)
        self.combo_ports = ttk.Combobox(
            cfg, font=("Segoe UI", 10), width=18, state="readonly",
            values=["Rápido (~20 portas)", "Comum (~50 portas)", "Personalizado"],
        )
        self.combo_ports.set("Rápido (~20 portas)")
        self.combo_ports.grid(row=1, column=1, padx=5, pady=4, sticky="w")

        self._label(cfg, "PERSONALIZADAS:").grid(row=1, column=2, sticky="w", padx=(15, 5), pady=4)
        self.entry_ports = tk.Entry(cfg, font=("Segoe UI", 10), width=22, bg=self.COLOR_BG, fg="white",
                                    insertbackground="white", bd=1, relief="flat")
        self.entry_ports.insert(0, "22,80,443,8000-8100")
        self.entry_ports.grid(row=1, column=3, padx=5, pady=4, sticky="w")

        self.btn_scan = tk.Button(
            cfg, text="START SCAN", font=("Segoe UI", 10, "bold"), bg=self.COLOR_ACCENT, fg="white",
            activebackground=self.COLOR_ACCENT_HOVER, activeforeground="black",
            command=self.start_scan, width=14, relief="flat", bd=0, cursor="hand2",
        )
        self.btn_scan.grid(row=0, column=4, rowspan=2, padx=25, pady=10, sticky="ns")

        opts = tk.Frame(cfg, bg=self.COLOR_PANEL)
        opts.grid(row=2, column=0, columnspan=5, sticky="w", padx=10, pady=(0, 10))
        self.var_ports = tk.BooleanVar(value=True)
        self.var_banner = tk.BooleanVar(value=True)
        self.var_deep = tk.BooleanVar(value=True)
        self._check(opts, "Escanear portas/serviços", self.var_ports).pack(side="left", padx=5)
        self._check(opts, "Capturar banners", self.var_banner).pack(side="left", padx=5)
        self._check(opts, "Detecção profunda (hosts que bloqueiam ping)", self.var_deep).pack(side="left", padx=5)
        self._label(opts, "THREADS:").pack(side="left", padx=(20, 5))
        self.spin_threads = tk.Spinbox(opts, from_=8, to=300, width=5, bg=self.COLOR_BG, fg="white",
                                       buttonbackground=self.COLOR_PANEL, relief="flat",
                                       insertbackground="white", font=("Segoe UI", 10))
        self.spin_threads.delete(0, "end")
        self.spin_threads.insert(0, "64")
        self.spin_threads.pack(side="left")

        # --- Progresso e status ---
        info = tk.Frame(self.root, bg=self.COLOR_BG)
        info.pack(fill="x", padx=25, pady=(6, 0))
        self.progress = ttk.Progressbar(info, orient="horizontal", mode="determinate",
                                        style="Neon.Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(0, 8))
        self.lbl_network_info = tk.Label(info, text="Insira os parâmetros para inicializar a varredura.",
                                         font=("Segoe UI", 9), bg=self.COLOR_BG, fg=self.COLOR_TEXT_MAIN)
        self.lbl_network_info.pack(anchor="w")
        self.lbl_status = tk.Label(info, text="Sistema pronto.", font=("Segoe UI", 9, "italic"),
                                   bg=self.COLOR_BG, fg=self.COLOR_CYAN)
        self.lbl_status.pack(anchor="w", pady=(2, 4))

        # --- Barra de ferramentas ---
        bar = tk.Frame(self.root, bg=self.COLOR_BG)
        bar.pack(fill="x", padx=25, pady=(0, 6))
        self.lbl_counters = tk.Label(bar, text="Online: 0 | Portas abertas: 0 | Alertas: 0",
                                     font=("Segoe UI", 9, "bold"), bg=self.COLOR_BG, fg=self.COLOR_WARN)
        self.lbl_counters.pack(side="left")
        tk.Button(bar, text="EXPORTAR CSV", font=("Segoe UI", 9, "bold"), bg=self.COLOR_ACCENT, fg="white",
                  activebackground=self.COLOR_ACCENT_HOVER, relief="flat", bd=0, cursor="hand2",
                  command=self.export_csv, padx=10).pack(side="right")
        self.var_show_offline = tk.BooleanVar(value=False)
        cb = self._check(bar, "Mostrar offline", self.var_show_offline, command=self.rebuild_table)
        cb.config(bg=self.COLOR_BG, activebackground=self.COLOR_BG)
        cb.pack(side="right", padx=15)

        # --- Tabela ---
        frame = tk.Frame(self.root, bg=self.COLOR_BG)
        frame.pack(fill="both", expand=True, padx=25, pady=(0, 20))
        columns = ("ip", "status", "latencia", "hostname", "mac", "fabricante", "portas")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        heads = [("ip", "ENDEREÇO IP", 120), ("status", "STATUS", 100), ("latencia", "LATÊNCIA", 90),
                 ("hostname", "HOSTNAME", 160), ("mac", "MAC", 130), ("fabricante", "FABRICANTE", 160),
                 ("portas", "PORTAS / SERVIÇOS", 320)]
        for col, title, width in heads:
            self.tree.heading(col, text=title)
            self.tree.column(col, anchor="center" if col != "portas" else "w", width=width,
                             stretch=(col == "portas"))
        self.tree.tag_configure("online", background="#112211", foreground=self.COLOR_ONLINE)
        self.tree.tag_configure("offline", background="#221111", foreground=self.COLOR_OFFLINE)
        self.tree.tag_configure("risk", background="#2a2410", foreground=self.COLOR_WARN)

        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", self.on_double_click)
        for seq in ("<Button-3>", "<Button-2>"):
            self.tree.bind(seq, self.show_context_menu)

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="Ver detalhes", command=self.menu_details)
        self.menu.add_command(label="Copiar IP", command=lambda: self.copy_field("ip"))
        self.menu.add_command(label="Copiar MAC", command=lambda: self.copy_field("mac"))
        self.menu.add_command(label="Abrir no navegador", command=self.menu_open_browser)

    # ------------------------------------------------------- Linhas/tabela --

    @staticmethod
    def ports_text(d):
        if not d["online"]:
            return "—"
        state = d["ports_state"]
        if state == "pending":
            return "⏳ analisando…"
        if state == "stopped":
            return "interrompido"
        if state == "skipped":
            return "—"
        if not d["ports"]:
            return "nenhuma aberta"
        return ", ".join(f"{p['port']}/{p['service']}" for p in d["ports"])

    def row_values(self, d):
        return (
            d["ip"],
            "ONLINE 🟢" if d["online"] else "OFFLINE 🔴",
            d["latency"],
            d["hostname"] or "—",
            d["mac"] or "—",
            d["vendor"] or "—",
            self.ports_text(d),
        )

    @staticmethod
    def row_tag(d):
        if not d["online"]:
            return "offline"
        if any(p["port"] in RISKY for p in d["ports"]):
            return "risk"
        return "online"

    def render_row(self, d):
        ip = d["ip"]
        key = ip_key(ip)
        visible = d["online"] or self.var_show_offline.get()
        exists = self.tree.exists(ip)
        if not visible:
            if exists:
                self.tree.delete(ip)
                self.shown.remove(key)
            return
        values, tag = self.row_values(d), (self.row_tag(d),)
        if exists:
            self.tree.item(ip, values=values, tags=tag)
        else:
            idx = bisect_left(self.shown, key)
            self.shown.insert(idx, key)
            self.tree.insert("", idx, iid=ip, values=values, tags=tag)

    def rebuild_table(self):
        self.tree.delete(*self.tree.get_children())
        self.shown = []
        for d in sorted(self.results.values(), key=lambda x: ip_key(x["ip"])):
            self.render_row(d)

    def update_counters(self):
        online = sum(1 for d in self.results.values() if d["online"])
        open_ports = sum(len(d["ports"]) for d in self.results.values())
        alerts = sum(1 for d in self.results.values() if any(p["port"] in RISKY for p in d["ports"]))
        self.lbl_counters.config(
            text=f"Online: {online}/{len(self.results)} | Portas abertas: {open_ports} | Hosts com alerta: {alerts}"
        )

    # --------------------------------------------------- Menu / detalhes -----

    def selected_ip(self):
        sel = self.tree.selection()
        return sel[0] if sel else None

    def show_context_menu(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.menu.tk_popup(event.x_root, event.y_root)

    def on_double_click(self, _event):
        ip = self.selected_ip()
        if ip:
            self.show_details(ip)

    def menu_details(self):
        ip = self.selected_ip()
        if ip:
            self.show_details(ip)

    def copy_field(self, field):
        ip = self.selected_ip()
        if not ip:
            return
        value = ip if field == "ip" else self.results[ip]["mac"]
        if value:
            self.root.clipboard_clear()
            self.root.clipboard_append(value)

    def menu_open_browser(self):
        ip = self.selected_ip()
        if not ip:
            return
        open_ports = {p["port"] for p in self.results[ip]["ports"]}
        for port in (443, 8443, 80, 8080, 8000, 8008, 8081, 8888, 3000, 5000, 9000):
            if port in open_ports:
                scheme = "https" if port in (443, 8443) else "http"
                suffix = "" if port in (80, 443) else f":{port}"
                webbrowser.open(f"{scheme}://{ip}{suffix}")
                return
        messagebox.showinfo("HiddenIP", "Nenhuma porta web aberta neste host.")

    def show_details(self, ip):
        d = self.results.get(ip)
        if not d:
            return
        win = tk.Toplevel(self.root)
        win.title(f"Detalhes — {ip}")
        win.geometry("760x460")
        win.configure(bg=self.COLOR_BG)
        txt = tk.Text(win, bg=self.COLOR_PANEL, fg=self.COLOR_TEXT_MAIN, font=("Consolas", 10),
                      wrap="word", relief="flat", padx=14, pady=12)
        txt.pack(fill="both", expand=True, padx=10, pady=10)

        lines = [
            f"IP:           {d['ip']}",
            f"Status:       {'ONLINE' if d['online'] else 'OFFLINE'}"
            + (f"  (detectado via {d['method']})" if d["method"] else ""),
            f"Latência:     {d['latency']}",
            f"Hostname:     {d['hostname'] or '—'}",
            f"MAC:          {d['mac'] or '— (só aparece para hosts na mesma rede local)'}",
            f"Fabricante:   {d['vendor'] or '—'}",
            "",
        ]
        if d["online"]:
            lines.append(f"Portas abertas ({len(d['ports'])}):  [{self.ports_state_label(d)}]")
            for p in d["ports"]:
                lines.append(f"  {p['port']:>5}/tcp  {p['service']:<14} {p['banner']}")
            alerts = [f"  {p['port']}/tcp — {RISKY[p['port']]}" for p in d["ports"] if p["port"] in RISKY]
            if alerts:
                lines += ["", "⚠ Atenção:"] + alerts
        txt.insert("1.0", "\n".join(lines))
        txt.config(state="disabled")

    @staticmethod
    def ports_state_label(d):
        return {"done": "concluído", "pending": "em andamento", "stopped": "interrompido",
                "skipped": "não escaneado"}.get(d["ports_state"], "")

    def export_csv(self):
        rows = [self.results[k] for k in sorted(self.results, key=ip_key)
                if self.results[k]["online"] or self.var_show_offline.get()]
        if not rows:
            messagebox.showinfo("HiddenIP", "Não há resultados para exportar.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile=f"hiddenip_{time.strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if not path:
            return
        try:
            # ";" e utf-8-sig para abrir direto no Excel em português
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow(["IP", "Status", "Método", "Latência", "Hostname", "MAC", "Fabricante",
                            "Portas abertas", "Banners", "Alertas"])
                for d in rows:
                    w.writerow([
                        d["ip"], "ONLINE" if d["online"] else "OFFLINE", d["method"], d["latency"],
                        d["hostname"], d["mac"], d["vendor"],
                        ", ".join(f"{p['port']}/{p['service']}" for p in d["ports"]),
                        " || ".join(f"{p['port']}: {p['banner']}" for p in d["ports"] if p["banner"]),
                        " || ".join(f"{p['port']}: {RISKY[p['port']]}" for p in d["ports"] if p["port"] in RISKY),
                    ])
            messagebox.showinfo("HiddenIP", f"Exportado para:\n{path}")
        except OSError as e:
            messagebox.showerror("HiddenIP - Erro", f"Não foi possível salvar:\n{e}")

    # ------------------------------------------------------------- Scan ------

    def start_scan(self):
        if self.scanning:
            self.stop_event.set()
            self.btn_scan.config(text="PARANDO...", state="disabled")
            return

        target = self.entry_ip.get().strip()
        if "/" not in target:
            target += self.combo_mask.get().split()[0]
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            messagebox.showerror("HiddenIP - Erro",
                                 "Formato de IP ou máscara inválido.\nUse padrões como 192.168.1.0 e /24 "
                                 "(ou digite 192.168.1.0/24 direto no campo).")
            return
        if network.version != 4:
            messagebox.showerror("HiddenIP - Erro", "Somente IPv4 é suportado.")
            return
        if network.num_addresses > 4096:
            messagebox.showerror("HiddenIP - Erro", "Rede muito grande. O máximo suportado é /20 (4094 hosts).")
            return

        ports = []
        if self.var_ports.get():
            profile = self.combo_ports.get()
            try:
                if profile.startswith("Rápido"):
                    ports = list(QUICK_PORTS)
                elif profile.startswith("Comum"):
                    ports = sorted(SERVICES)
                else:
                    ports = parse_ports(self.entry_ports.get())
            except ValueError as e:
                messagebox.showerror("HiddenIP - Erro", f"Portas inválidas: {e}\nExemplo: 22,80,443,8000-8100")
                return

        try:
            threads = max(1, min(300, int(self.spin_threads.get())))
        except ValueError:
            threads = 64

        cfg = {
            "threads": threads, "ping_timeout": 0.8, "port_timeout": 0.6,
            "ports": ports, "scan_ports": bool(ports),
            "banner": self.var_banner.get(), "deep": self.var_deep.get(),
        }
        hosts = [str(h) for h in network.hosts()]

        # Limpa estado anterior
        self.results.clear()
        self.shown.clear()
        self.tree.delete(*self.tree.get_children())
        self.progress["value"] = 0
        self.progress["maximum"] = max(1, len(hosts))
        self.stop_event.clear()
        self.scanning = True
        self.btn_scan.config(text="STOP SCAN", bg=self.COLOR_OFFLINE, state="normal")
        self.lbl_network_info.config(
            text=f"Rede alvo: {network.network_address} | Máscara: {network.netmask} | "
                 f"Hosts: {len(hosts)} | Portas por host: {len(ports)}"
        )
        self.lbl_status.config(text="Iniciando varredura...")

        threading.Thread(target=self.run_scan, args=(hosts, cfg), daemon=True).start()

    # --- Trabalho em segundo plano (nunca mexe direto na interface) ---

    def icmp_ping(self, ip, timeout):
        for _ in range(2):  # 2 tentativas: aparelhos em Wi-Fi às vezes perdem o 1º ping
            if self.stop_event.is_set():
                return None
            try:
                r = ping(ip, timeout=timeout)
            except (PermissionError, OSError):
                self.icmp_blocked = True
                return None
            if r is not None and r is not False:
                return r * 1000
        return None

    def lookup_mac(self, ip):
        with self.arp_lock:
            mac = self.arp_cache.get(ip)
            if not mac and time.time() - self.arp_time > 1.5:
                self.arp_cache.update(read_arp_table())
                self.arp_time = time.time()
                mac = self.arp_cache.get(ip)
        return mac or ""

    @staticmethod
    def new_result(ip):
        return {"ip": ip, "online": False, "method": "", "latency": "—", "hostname": "",
                "mac": "", "vendor": "", "ports": [], "ports_state": "skipped"}

    def enrich(self, d, cfg):
        d["mac"] = self.lookup_mac(d["ip"])
        d["vendor"] = self.vendors.lookup(d["mac"])
        try:
            d["hostname"] = socket.gethostbyaddr(d["ip"])[0]
        except (OSError, UnicodeError):
            d["hostname"] = ""
        d["ports_state"] = "pending" if cfg["scan_ports"] else "skipped"

    def discover_host(self, ip, cfg):
        if self.stop_event.is_set():
            return None
        d = self.new_result(ip)
        latency = self.icmp_ping(ip, cfg["ping_timeout"])
        if latency is not None:
            d.update(online=True, method="ICMP", latency=f"{latency:.1f} ms")
        elif cfg["deep"]:
            for port in PROBE_PORTS:
                if self.stop_event.is_set():
                    return None
                if tcp_connect(ip, port, 0.4) in ALIVE_CODES:
                    d.update(online=True, method=f"TCP/{port}", latency="sem ICMP")
                    break
        if d["online"]:
            self.enrich(d, cfg)
        return d

    def scan_services(self, d, cfg):
        open_ports = []

        def task(port):
            if self.stop_event.is_set():
                return None
            return probe_port(d["ip"], port, cfg["port_timeout"], cfg["banner"])

        with ThreadPoolExecutor(max_workers=64) as pool:
            for r in pool.map(task, cfg["ports"]):
                if r:
                    open_ports.append(r)
        open_ports.sort(key=lambda p: p["port"])
        state = "stopped" if self.stop_event.is_set() else "done"
        self.events.put(("host", dict(d, ports=open_ports, ports_state=state)))

    def run_scan(self, hosts, cfg):
        start = time.time()
        total = len(hosts)
        self.arp_cache = {}
        self.arp_time = 0.0
        self.icmp_blocked = False
        online = set()
        pool = ThreadPoolExecutor(max_workers=cfg["threads"])
        svc_pool = ThreadPoolExecutor(max_workers=4)
        try:
            self.events.put(("status", "Descobrindo hosts ativos..."))
            futures = [pool.submit(self.discover_host, ip, cfg) for ip in hosts]
            done = 0
            for fut in as_completed(futures):
                done += 1
                try:
                    d = fut.result()
                except Exception:
                    d = None
                if d is not None:
                    self.events.put(("host", d))
                    if d["online"]:
                        online.add(d["ip"])
                        if cfg["scan_ports"]:
                            svc_pool.submit(self.scan_services, d, cfg)
                    self.events.put(("progress", done, total))
                    if done % 8 == 0:
                        self.events.put(("status", f"Descoberta: {done}/{total} IPs verificados"))
                if self.stop_event.is_set():
                    break

            # Hosts que bloquearam ping/TCP mas responderam ao ARP (mesma rede local)
            if not self.stop_event.is_set():
                table = read_arp_table()
                for ip in hosts:
                    if ip in table and ip not in online:
                        d = self.new_result(ip)
                        d.update(online=True, method="ARP", latency="sem ICMP")
                        self.arp_cache[ip] = table[ip]
                        self.enrich(d, cfg)
                        online.add(ip)
                        self.events.put(("host", d))
                        if cfg["scan_ports"]:
                            svc_pool.submit(self.scan_services, d, cfg)
                self.events.put(("progress", total, total))
                if cfg["scan_ports"] and online:
                    self.events.put(("status", f"Analisando portas e serviços em {len(online)} host(s)..."))
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
            svc_pool.shutdown(wait=True, cancel_futures=self.stop_event.is_set())
            self.events.put(("done", {
                "elapsed": time.time() - start, "online": len(online), "total": total,
                "stopped": self.stop_event.is_set(), "icmp_blocked": self.icmp_blocked,
            }))

    # --- Eventos vindos das threads (rodam na thread da interface) ---

    def poll_events(self):
        try:
            for _ in range(400):
                ev = self.events.get_nowait()
                kind = ev[0]
                if kind == "host":
                    self.results[ev[1]["ip"]] = ev[1]
                    self.render_row(ev[1])
                    self.dirty = True
                elif kind == "progress":
                    self.progress["maximum"] = max(1, ev[2])
                    self.progress["value"] = ev[1]
                elif kind == "status":
                    self.lbl_status.config(text=ev[1])
                elif kind == "done":
                    self.on_done(ev[1])
        except queue.Empty:
            pass
        if self.dirty:
            self.update_counters()
            self.dirty = False
        self.root.after(80, self.poll_events)

    def on_done(self, s):
        for d in list(self.results.values()):
            if d["ports_state"] == "pending":
                d = dict(d, ports_state="stopped")
                self.results[d["ip"]] = d
                self.render_row(d)
        self.scanning = False
        self.btn_scan.config(text="START SCAN", bg=self.COLOR_ACCENT, state="normal")
        if s["stopped"]:
            msg = "Operação abortada pelo operador."
        else:
            msg = f"Varredura finalizada em {s['elapsed']:.1f}s — {s['online']} host(s) online de {s['total']}."
        if s["icmp_blocked"]:
            msg += " Aviso: ICMP indisponível (execute como administrador/root); usei TCP/ARP."
        self.lbl_status.config(text=msg)
        self.update_counters()

    def on_close(self):
        self.stop_event.set()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = HiddenIPScannerApp(root)
    root.mainloop()