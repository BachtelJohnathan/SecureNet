# =============================================
# app.py
# =============================================
from __future__ import annotations

"""Flask app factory wiring blueprints for tools.
Run:
    export FLASK_APP=app.py
    flask run --host=0.0.0.0 --port=5000

Or:
    python app.py
"""

from flask import Flask

# IMPORTANT: these imports are one-way; blueprints must NOT import from app
from blueprints.home import home_bp
from blueprints.packet_sniffer import packet_sniffer_bp
from blueprints.vulnerability_scanner import vulnerability_scanner_bp
from blueprints.penetration_tester import penetration_tester_bp


def create_app() -> Flask:
    app = Flask(__name__)

    # Register blueprints (no side effects)
    app.register_blueprint(home_bp)
    app.register_blueprint(packet_sniffer_bp)
    app.register_blueprint(vulnerability_scanner_bp)
    app.register_blueprint(penetration_tester_bp)

    return app


if __name__ == "__main__":
    flask_app = create_app()
    flask_app.run(host="0.0.0.0", port=5000, debug=False)


# =============================================
# blueprints/__init__.py
# (ensures this is a proper package and helps avoid import ambiguity)
# =============================================
# Intentionally empty

# =============================================
# tools/__init__.py
# =============================================
# Intentionally empty

# =============================================
# blueprints/home.py
# =============================================
from __future__ import annotations

from flask import Blueprint, jsonify, Response

home_bp = Blueprint("home", __name__, url_prefix="/")


@home_bp.get("")
def index():
    return jsonify({
        "service": "netsec-toolkit",
        "endpoints": {
            "sniffer_status": "/sniffer/status",
            "sniffer_start": "/sniffer/start",
            "sniffer_stop": "/sniffer/stop",
            "sniffer_recent": "/sniffer/recent",
            "sniffer_pcap": "/sniffer/pcap",
            "ui": "/ui",
        },
    })


@home_bp.get("/ui")
def ui_page():
    """Simple HTML UI with color-coded status and fetch polling."""
    html = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>NetSec Toolkit – Packet Sniffer</title>
  <style>
    :root { --bg:#0b1020; --card:#131a2b; --muted:#94a3b8; --txt:#e5e7eb; --ok:#22c55e; --warn:#f59e0b; --err:#ef4444; }
    * { box-sizing: border-box; }
    body { margin: 0; font: 14px/1.4 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background: var(--bg); color: var(--txt); }
    header { padding: 16px 20px; background: #0e1426; border-bottom: 1px solid #1f2a44; display:flex; align-items:center; justify-content:space-between; }
    h1 { margin: 0; font-size: 18px; }
    .container { padding: 20px; max-width: 1100px; margin: 0 auto; display:grid; grid-template-columns: 360px 1fr; gap: 16px; }
    .card { background: var(--card); border: 1px solid #1f2a44; border-radius: 12px; padding: 14px; }
    .row { display: grid; grid-template-columns: 120px 1fr; align-items: center; gap: 8px; margin-bottom: 10px; }
    input[type=text], input[type=number] { width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #2b395e; background:#0d1427; color: var(--txt); }
    input[type=checkbox] { transform: scale(1.1); }
    .actions { display:flex; gap: 10px; margin-top: 10px; }
    button { padding: 8px 12px; border-radius: 10px; border: 1px solid #2b395e; background:#0f1a31; color: var(--txt); cursor: pointer; }
    button.primary { border-color:#2e5aff; background:#13224a; }
    button.danger { border-color:#ff4d4d; background:#2a1220; }
    button:disabled { opacity:.6; cursor:not-allowed; }
    .status { display:flex; align-items:center; gap:10px; font-weight:600; }
    .dot { width:12px; height:12px; border-radius:50%; background:#64748b; box-shadow:0 0 0 2px #1f2a44 inset; }
    .running { background: var(--ok); }
    .stopped { background: var(--err); }
    .warn { background: var(--warn); }
    .kvs { display:grid; grid-template-columns: auto 1fr; gap: 6px 10px; }
    code, pre { background:#0a1224; border:1px solid #1f2a44; color:#d1e3ff; border-radius:8px; }
    pre { padding:10px; height: 420px; overflow:auto; }
    .muted { color: var(--muted); }
    a.btn { text-decoration:none; padding:6px 10px; border-radius:10px; border:1px solid #2b395e; }
    footer { text-align:center; padding: 14px; color:#8ba3c7; font-size:12px; }
    .grid2 { display:grid; grid-template-columns: 1fr 1fr; gap: 10px; }
  </style>
</head>
<body>
  <header>
    <h1>NetSec Toolkit – Packet Sniffer</h1>
    <div class="status"><span id="statusDot" class="dot"></span><span id="statusText">Loading…</span></div>
  </header>
  <div class="container">
    <section class="card">
      <h2 style="margin-top:4px">Controls</h2>
      <div class="row"><label>Interface</label><input id="iface" type="text" placeholder="default (auto)" /></div>
      <div class="row"><label>Filter</label><input id="bpf" type="text" value="ip or arp or ipv6" /></div>
      <div class="row"><label>Count</label><input id="count" type="number" value="0" min="0" /></div>
      <div class="row"><label>PCAP Path</label><input id="pcap" type="text" placeholder="out.pcap" /></div>
      <div class="row"><label>Header-only</label><div><input id="headerOnly" type="checkbox" checked /> <span class="muted">redacts payloads</span></div></div>
      <div class="row"><label>Ring size</label><input id="ring" type="number" value="2000" min="50" max="10000" /></div>
      <div class="actions">
        <button class="primary" id="startBtn">Start</button>
        <button class="danger" id="stopBtn">Stop</button>
        <a id="dlLink" class="btn" href="#" download>Download PCAP</a>
      </div>
      <p class="muted" style="margin-top:10px">Run as admin/root. Capture only on authorized networks.</p>
    </section>

    <section class="card">
      <div class="grid2">
        <div>
          <h2 style="margin-top:4px">Status</h2>
          <div class="kvs">
            <span class="muted">Interface</span><span id="kvIface">–</span>
            <span class="muted">Filter</span><span id="kvBpf">–</span>
            <span class="muted">Started</span><span id="kvStarted">–</span>
            <span class="muted">Captured</span><span id="kvCaptured">0</span>
          </div>
        </div>
        <div>
          <h2 style="margin-top:4px">Protocol Counters</h2>
          <div id="counters" class="kvs"></div>
        </div>
      </div>
      <h2>Recent</h2>
      <div class="row" style="grid-template-columns: 80px 1fr;">
        <label>Show last</label>
        <div>
          <select id="tailN" style="padding:6px 8px; border-radius:8px; border:1px solid #2b395e; background:#0d1427; color:var(--txt)">
            <option>50</option>
            <option selected>100</option>
            <option>200</option>
            <option>500</option>
          </select>
        </div>
      </div>
      <pre id="recent"></pre>
    </section>
  </div>
  <footer>© NetSec Toolkit · Minimal demo UI</footer>

<script>
const $ = (id) => document.getElementById(id);

async function api(path, options={}) {
  const res = await fetch(path, {headers:{'content-type':'application/json'}, ...options});
  if (!res.ok) throw new Error(await res.text());
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  return res.text();
}

function setStatus(running) {
  const dot = $("statusDot");
  const text = $("statusText");
  dot.classList.remove('running','stopped','warn');
  if (running === true) { dot.classList.add('running'); text.textContent = 'Running'; }
  else if (running === false) { dot.classList.add('stopped'); text.textContent = 'Stopped'; }
  else { dot.classList.add('warn'); text.textContent = 'Unknown'; }
}

function renderCounters(obj){
  const root = $("counters");
  root.innerHTML = '';
  const entries = Object.entries(obj || {});
  if (entries.length === 0) { root.innerHTML = '<span class="muted">–</span>'; return; }
  for (const [k,v] of entries) {
    const kEl = document.createElement('span'); kEl.className='muted'; kEl.textContent = k;
    const vEl = document.createElement('span'); vEl.textContent = String(v);
    root.appendChild(kEl); root.appendChild(vEl);
  }
}

function renderRecent(lines){
  $("recent").textContent = (lines||[]).join('
');
}

function setKV(id, val){ $(id).textContent = val ?? '–'; }

async function refresh(){
  try {
    const meta = await api('/sniffer/status');
    setStatus(!!meta.running);
    setKV('kvIface', meta.iface);
    setKV('kvBpf', meta.bpf);
    setKV('kvStarted', meta.started_at ? new Date(meta.started_at).toLocaleString() : '–');
    setKV('kvCaptured', meta.captured || 0);
    renderCounters(meta.counters);
    const tail = Number($("tailN").value || 100);
    const rec = await api('/sniffer/recent?n=' + tail);
    renderRecent(rec.lines || []);
    const dl = $("dlLink");
    if (meta.pcap_path) { dl.href = '/sniffer/pcap'; dl.removeAttribute('aria-disabled'); }
    else { dl.href = '#'; dl.setAttribute('aria-disabled','true'); }
  } catch (e) {
    setStatus(null);
  }
}

async function startCapture(){
  const payload = {
    interface: $("iface").value || null,
    filter: $("bpf").value || 'ip or arp or ipv6',
    count: Number($("count").value||0),
    pcap: $("pcap").value || null,
    header_only: $("headerOnly").checked,
    ring_size: Number($("ring").value||2000),
  };
  try {
    $("startBtn").disabled = true;
    await api('/sniffer/start', { method:'POST', body: JSON.stringify(payload) });
    setTimeout(refresh, 300);
  } catch(err){
    alert('Start failed: ' + err.message);
  } finally { $("startBtn").disabled = false; }
}

async function stopCapture(){
  try {
    $("stopBtn").disabled = true;
    await api('/sniffer/stop', { method:'POST' });
    setTimeout(refresh, 300);
  } catch(err){
    alert('Stop failed: ' + err.message);
  } finally { $("stopBtn").disabled = false; }
}

$('startBtn').addEventListener('click', startCapture);
$('stopBtn').addEventListener('click', stopCapture);
$('tailN').addEventListener('change', refresh);

refresh();
setInterval(refresh, 1500);
</script>
</body>
</html>
"""
    return Response(html, mimetype="text/html")

# =============================================
# blueprints/packet_sniffer.py
# =============================================
from __future__ import annotations

import os
from dataclasses import asdict
from typing import Any, Dict

from flask import Blueprint, jsonify, request, send_file

from tools.basic_packet_sniffer import SnifferConfig, SnifferManager, SnifferError

packet_sniffer_bp = Blueprint("packet_sniffer", __name__, url_prefix="/sniffer")
manager = SnifferManager.shared()


@packet_sniffer_bp.get("/status")
def status():
    return jsonify(manager.status())


@packet_sniffer_bp.post("/start")
def start_capture():
    payload: Dict[str, Any] = request.get_json(silent=True) or {}

    cfg = SnifferConfig(
        iface=payload.get("interface"),
        bpf=payload.get("filter", "ip or arp or ipv6"),
        count=int(payload.get("count", 0) or 0),
        pcap_path=payload.get("pcap"),
        header_only=bool(payload.get("header_only", True)),
        quiet=bool(payload.get("quiet", False)),
        ring_size=int(payload.get("ring_size", 2000)),
    )

    try:
        manager.start(cfg)
    except SnifferError as e:
        return jsonify({"ok": False, "error": str(e), "config": asdict(cfg)}), 400

    return jsonify({"ok": True, "status": manager.status()})


@packet_sniffer_bp.post("/stop")
def stop_capture():
    manager.stop()
    return jsonify({"ok": True, "status": manager.status()})


@packet_sniffer_bp.get("/recent")
def recent_lines():
    n = int(request.args.get("n", 100))
    return jsonify({"lines": manager.recent(n)})


@packet_sniffer_bp.get("/pcap")
def fetch_pcap():
    meta = manager.status()
    pcap_path = meta.get("pcap_path")
    if not pcap_path or not os.path.exists(pcap_path):
        return jsonify({"ok": False, "error": "No pcap available"}), 404
    return send_file(pcap_path, as_attachment=True)


# =============================================
# blueprints/vulnerability_scanner.py (stub)
# =============================================
from __future__ import annotations

from flask import Blueprint, jsonify

vulnerability_scanner_bp = Blueprint(
    "vulnerability_scanner", __name__, url_prefix="/vuln"
)


@vulnerability_scanner_bp.get("/")
def vuln_root():
    return jsonify({"message": "Vulnerability scanner placeholder"})


# =============================================
# blueprints/penetration_tester.py (stub)
# =============================================
from __future__ import annotations

from flask import Blueprint, jsonify

penetration_tester_bp = Blueprint(
    "penetration_tester", __name__, url_prefix="/pentest"
)


@penetration_tester_bp.get("/")
def pentest_root():
    return jsonify({"message": "Penetration tester placeholder"})


# =============================================
# tools/basic_packet_sniffer.py
# (refactored for Flask integration; AsyncSniffer + ring buffer)
# =============================================
from __future__ import annotations

import datetime as dt
import os
import threading
from collections import Counter, deque
from dataclasses import dataclass, field, asdict
from typing import Deque, Dict, Optional, Tuple

try:
    from scapy.all import (
        AsyncSniffer,
        conf,
        get_if_list,
        Ether,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        ARP,
        DNS,
        Raw,
        PcapWriter,
    )
except Exception as exc:  # pragma: no cover
    raise RuntimeError(
        "Scapy is required. Install with: pip install scapy"
    ) from exc


# ---------------------- Data model ----------------------
@dataclass
class SnifferConfig:
    iface: Optional[str] = None
    bpf: str = "ip or arp or ipv6"
    count: int = 0  # 0=infinite
    pcap_path: Optional[str] = None
    header_only: bool = True  # redact payloads by default
    quiet: bool = False
    ring_size: int = 2000


class SnifferError(RuntimeError):
    pass


# ---------------------- Engine ----------------------
class SnifferManager:
    _shared: Optional["SnifferManager"] = None

    @classmethod
    def shared(cls) -> "SnifferManager":
        if cls._shared is None:
            cls._shared = cls()
        return cls._shared

    def __init__(self) -> None:
        self._sniffer: Optional[AsyncSniffer] = None
        self._writer: Optional[PcapWriter] = None
        self._cfg: Optional[SnifferConfig] = None
        self._lock = threading.RLock()
        self._counters: Counter[str] = Counter()
        self._ring: Deque[str] = deque(maxlen=2000)
        self._started_at: Optional[dt.datetime] = None
        self._captured: int = 0

    # ---------- helpers ----------
    def _is_admin(self) -> bool:
        if os.name != "nt":
            try:
                return os.geteuid() == 0  # type: ignore[attr-defined]
            except AttributeError:
                return False
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _validate_iface(self, iface: Optional[str]) -> str:
        available = get_if_list()
        if iface is None:
            return str(conf.iface)
        if iface in available:
            return iface
        raise SnifferError(
            f"Interface '{iface}' not found. Available: {', '.join(available)}"
        )

    def _redact(self, pkt):
        try:
            cp = pkt.copy()
            if Raw in cp:
                while Raw in cp:
                    del cp[Raw]
            return cp
        except Exception:
            return pkt

    def _build_writer(self, path: str) -> PcapWriter:
        outdir = os.path.dirname(os.path.abspath(path)) or "."
        if not os.path.isdir(outdir):
            raise SnifferError(f"Output directory does not exist: {outdir}")
        return PcapWriter(path, append=True, sync=True)

    def _classify_and_format(self, pkt) -> Tuple[str, str]:
        ts = dt.datetime.now().strftime("%H:%M:%S")
        length = len(pkt)
        ether_info = ""
        if Ether in pkt:
            e = pkt[Ether]
            ether_info = f"ETH {e.src} → {e.dst}"
        if IP in pkt:
            ip = pkt[IP]
            if TCP in pkt:
                tcp = pkt[TCP]
                flags = tcp.sprintf("%TCP.flags%")
                info = f"TCP {ip.src}:{tcp.sport} → {ip.dst}:{tcp.dport} flags={flags}"
                proto = "TCP"
            elif UDP in pkt:
                udp = pkt[UDP]
                info = f"UDP {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}"
                if DNS in pkt:
                    info += " (DNS)"
                proto = "UDP"
            elif ICMP in pkt:  # type: ignore[truthy-bool]
                icmp = pkt[ICMP]
                info = f"ICMP type={icmp.type} code={icmp.code} id={getattr(icmp, 'id', '-') }"
                proto = "ICMP"
            else:
                info = f"IPv4 {ip.src} → {ip.dst} ttl={ip.ttl}"
                proto = "IP"
            line = f"[{ts}] {ether_info} | {info} len={length}"
            return proto, line
        if IPv6 in pkt:
            ip6 = pkt[IPv6]
            if TCP in pkt:
                tcp = pkt[TCP]
                flags = tcp.sprintf("%TCP.flags%")
                info = f"TCP6 {ip6.src}:{tcp.sport} → {ip6.dst}:{tcp.dport} flags={flags}"
                proto = "TCP6"
            elif UDP in pkt:
                udp = pkt[UDP]
                info = f"UDP6 {ip6.src}:{udp.sport} → {ip6.dst}:{udp.dport}"
                if DNS in pkt:
                    info += " (DNS)"
                proto = "UDP6"
            else:
                info = f"IPv6 {ip6.src} → {ip6.dst} hlim={ip6.hlim}"
                proto = "IPv6"
            line = f"[{ts}] {ether_info} | {info} len={length}"
            return proto, line
        if ARP in pkt:
            arp = pkt[ARP]
            op = "REQ" if int(arp.op) == 1 else "REPLY"
            info = f"ARP {op} who-has {arp.pdst} tell {arp.psrc}"
            line = f"[{ts}] {ether_info} | {info} len={length}"
            return "ARP", line
        line = f"[{ts}] {ether_info} | L2 len={length}"
        return "L2", line

    def _on_packet(self, pkt) -> None:
        proto, line = self._classify_and_format(pkt)
        with self._lock:
            self._counters[proto] += 1
            self._captured += 1
            self._ring.append(line)
            if self._writer is not None:
                to_write = self._redact(pkt) if (self._cfg and self._cfg.header_only) else pkt
                try:
                    self._writer.write(to_write)
                except Exception:
                    # Why: keep capture loop resilient to transient I/O errors
                    pass

    # ---------- public API ----------
    def start(self, cfg: SnifferConfig) -> None:
        with self._lock:
            if self._sniffer and self._sniffer.running:
                raise SnifferError("Sniffer already running")
            if not self._is_admin():
                raise SnifferError("Admin/root privileges required for capture")

            iface = self._validate_iface(cfg.iface)
            self._cfg = SnifferConfig(**{**asdict(cfg), "iface": iface})

            self._ring = deque(maxlen=cfg.ring_size)
            self._counters.clear()
            self._captured = 0
            self._started_at = dt.datetime.now()

            self._writer = None
            if cfg.pcap_path:
                self._writer = self._build_writer(cfg.pcap_path)

            self._sniffer = AsyncSniffer(
                iface=iface,
                filter=cfg.bpf,
                prn=self._on_packet,
                store=False,
                count=cfg.count if cfg.count > 0 else 0,
            )
            try:
                self._sniffer.start()
            except Exception as e:  # noqa: BLE001
                # Clean up on failure
                self._sniffer = None
                if self._writer:
                    try:
                        self._writer.close()
                    except Exception:
                        pass
                    self._writer = None
                raise SnifferError(f"Failed to start sniffer: {e}") from e

    def stop(self) -> None:
        with self._lock:
            if self._sniffer:
                try:
                    self._sniffer.stop()
                except Exception:
                    pass
                self._sniffer = None
            if self._writer:
                try:
                    self._writer.flush()
                    self._writer.close()
                except Exception:
                    pass
                self._writer = None

    def status(self) -> Dict[str, object]:
        with self._lock:
            running = bool(self._sniffer and self._sniffer.running)
            return {
                "running": running,
                "iface": getattr(self._cfg, "iface", None),
                "bpf": getattr(self._cfg, "bpf", None),
                "count": getattr(self._cfg, "count", None),
                "captured": self._captured,
                "counters": dict(self._counters),
                "started_at": self._started_at.isoformat() if self._started_at else None,
                "pcap_path": getattr(self._cfg, "pcap_path", None),
                "header_only": getattr(self._cfg, "header_only", None),
            }

    def recent(self, n: int = 100) -> list[str]:
        with self._lock:
            n = max(1, min(n, len(self._ring)))
            return list(list(self._ring)[-n:])


# =============================================
# requirements.txt (recommended)
# =============================================
# Flask>=2.3
# scapy>=2.5
