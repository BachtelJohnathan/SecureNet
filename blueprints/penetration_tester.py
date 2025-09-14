"""Penetration Tester blueprint.
- Scans ONLY localhost/private IPs (safety).
- Fast/Full profiles + optional custom ports (?ports=22,80,443 or 20-25,80).
- Saves history (SQLite), view past scans, CSV+JSON export.
- Adds service labels and plain-English recommendations.
"""
from __future__ import annotations

from flask import Blueprint, render_template, request, Response, url_for, redirect
import socket, ipaddress, sqlite3, json
from datetime import datetime
from typing import List, Dict

penetration_tester_bp = Blueprint("penetration_tester", __name__)

# ====== Port sets ======
FAST_PORTS: List[int] = [21,22,23,25,53,80,110,135,139,143,443,445,587,993,995,3306,3389,5900,8080]
FULL_PORTS: List[int] = FAST_PORTS + [17,19,69,123,161,389,636,2049,5060,5353,6379,8000,8443,9000,9200,11211]

# ====== Service Labels ======
SERVICE_NAMES = {
    17:"Quote of Day", 19:"Chargen", 21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP",
    53:"DNS", 69:"TFTP", 80:"HTTP", 110:"POP3", 123:"NTP", 135:"MS RPC",
    139:"NetBIOS", 143:"IMAP", 161:"SNMP", 389:"LDAP", 443:"HTTPS", 445:"SMB",
    5060:"SIP", 5353:"mDNS", 5900:"VNC", 6379:"Redis", 8000:"HTTP-Alt",
    8080:"HTTP-Alt", 8443:"HTTPS-Alt", 9000:"Servlet/Alt", 9200:"Elasticsearch",
    993:"IMAPS", 995:"POP3S", 11211:"Memcached", 2049:"NFS", 3306:"MySQL", 3389:"RDP"
}

DB_PATH = "securenet_scans.db"

# ====== Helpers ======
def _db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            ip TEXT NOT NULL,
            profile TEXT NOT NULL,
            rows_json TEXT NOT NULL
        )
    """)
    return con

def _is_allowed_target(target_str: str) -> tuple[bool, str|None, str|None]:
    target_str = (target_str or "").strip()
    if not target_str:
        return False, None, "Target required"
    if target_str.lower() == "localhost":
        return True, "127.0.0.1", None
    try:
        ip = socket.gethostbyname(target_str)
    except Exception:
        return False, None, "Could not resolve hostname/IP"
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False, None, "Invalid IP address"
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return True, ip, None
    return False, None, "Target must be localhost or a private IP (10/172.16–31/192.168)."

def _parse_ports(raw: str) -> List[int]:
    """Accepts '22,80,443' and ranges '20-25' (comma/semicolon separated)."""
    ports: List[int] = []
    if not raw:
        return ports
    for tok in raw.replace(";", ",").split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            a, b = tok.split("-", 1)
            try:
                a, b = int(a), int(b)
            except ValueError:
                continue
            lo, hi = min(a, b), max(a, b)
            ports.extend([p for p in range(lo, hi + 1) if 1 <= p <= 65535])
        else:
            try:
                p = int(tok)
                if 1 <= p <= 65535:
                    ports.append(p)
            except ValueError:
                continue
    # dedupe & sort
    return sorted(set(ports))

def _scan_ports(ip: str, ports: List[int], timeout_s: float = 0.3) -> List[Dict]:
    rows: List[Dict] = []
    for p in ports:
        status, banner = "closed", ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout_s)
                if s.connect_ex((ip, p)) == 0:
                    status = "open"
                    # light banner grab for HTTP-ish ports
                    try:
                        s.settimeout(0.2)
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        data = s.recv(128)
                        banner = data.decode(errors="ignore").strip()
                    except Exception:
                        banner = ""
        except Exception:
            status = "error"
        rows.append({
            "port": p,
            "service": SERVICE_NAMES.get(p, ""),
            "status": status,
            "banner": banner
        })
    return rows

def _risk_level(port: int) -> str:
    risky = {21,23,25,110,139,143,445,3389,5900,3306}
    warn  = {80,8080,11211,6379,9200}
    if port in risky: return "red"
    if port in warn:  return "yellow"
    return "green"

def _recommendation(port: int) -> str:
    if port in {21,23}:             return "Legacy plaintext service; disable or tunnel."
    if port in {445,3389}:          return "Restrict to LAN/VPN; require auth and MFA if exposed."
    if port in {3306}:              return "Bind to localhost; avoid direct external exposure."
    if port in {110,143,25}:        return "Use TLS variants; restrict exposure."
    if port in {80,8080}:           return "Harden HTTP; prefer HTTPS and limit access."
    if port in {11211,6379,9200}:   return "Never expose to internet; firewall to trusted hosts."
    return "No immediate action if unused/closed."

# ====== Routes ======
@penetration_tester_bp.route("/penetration_tester", methods=["GET", "POST"])
def penetration_tester():
    ctx = {"results": None, "error": None, "target": "", "profile": "fast", "last_id": None}

    if request.method == "POST" or request.args:
        target  = (request.form.get("target") or request.args.get("target") or "").strip()
        profile = (request.form.get("profile") or request.args.get("profile") or "fast").strip()
        raw_ports = (request.form.get("ports") or request.args.get("ports") or "").strip()

        ctx["target"], ctx["profile"] = target, profile
        ok, ip, err = _is_allowed_target(target or "127.0.0.1")
        if not ok:
            ctx["error"] = err
            return render_template("penetration_tester.html", **ctx)

        custom_ports = _parse_ports(raw_ports)
        ports = custom_ports if custom_ports else (FAST_PORTS if profile == "fast" else FULL_PORTS)

        rows = _scan_ports(ip, ports)
        for r in rows:
            r["risk"] = _risk_level(r["port"])
            r["rec"]  = _recommendation(r["port"])
        ctx["results"] = {"ip": ip, "rows": rows}

        con = _db()
        cur = con.cursor()
        cur.execute(
            "INSERT INTO scans(created_at, ip, profile, rows_json) VALUES(?,?,?,?)",
            (datetime.utcnow().isoformat(timespec="seconds") + "Z", ip, profile if not custom_ports else f"custom:{raw_ports}", json.dumps(rows))
        )
        con.commit()
        ctx["last_id"] = cur.lastrowid
        con.close()

    return render_template("penetration_tester.html", **ctx)

@penetration_tester_bp.route("/penetration_tester/recent")
def recent_scans():
    con = _db()
    cur = con.cursor()
    cur.execute("SELECT id, created_at, ip, profile FROM scans ORDER BY id DESC LIMIT 50")
    items = [{"id": rid, "created_at": ts, "ip": ip, "profile": profile} for (rid, ts, ip, profile) in cur.fetchall()]
    con.close()
    return render_template("recent_scans.html", items=items)

@penetration_tester_bp.route("/penetration_tester/view/<int:scan_id>")
def view_scan(scan_id: int):
    con = _db()
    cur = con.cursor()
    cur.execute("SELECT id, created_at, ip, profile, rows_json FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        return redirect(url_for("penetration_tester.recent_scans"))
    rid, ts, ip, profile, rows_json = row
    rows = json.loads(rows_json)
    # backfill in case of old scans
    for r in rows:
        p = r.get("port", 0)
        r.setdefault("service", SERVICE_NAMES.get(p, ""))
        r.setdefault("risk", _risk_level(p))
        r.setdefault("rec", _recommendation(p))
    return render_template("penetration_tester.html",
                           results={"ip": ip, "rows": rows},
                           target=ip, profile=profile, error=None, last_id=rid)

@penetration_tester_bp.route("/penetration_tester/export/<int:scan_id>.csv")
def export_csv(scan_id: int):
    con = _db()
    cur = con.cursor()
    cur.execute("SELECT created_at, ip, profile, rows_json FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        return Response("not found", status=404)
    ts, ip, profile, rows_json = row
    rows = json.loads(rows_json)
    lines = ["scan_id,created_at,ip,profile,port,service,status,risk,recommendation,banner"]
    for r in rows:
        port = r.get("port","")
        svc  = r.get("service","")
        st   = r.get("status","")
        risk = r.get("risk","")
        rec  = r.get("rec","")
        ban  = (r.get("banner","") or "").replace(",", " ")
        lines.append(f"{scan_id},{ts},{ip},{profile},{port},{svc},{st},{risk},{rec},{ban}")
    csv_body = "\n".join(lines)
    return Response(csv_body, mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"})

@penetration_tester_bp.route("/penetration_tester/export/<int:scan_id>.json")
def export_json(scan_id: int):
    con = _db()
    cur = con.cursor()
    cur.execute("SELECT id, created_at, ip, profile, rows_json FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        return Response("not found", status=404)
    rid, ts, ip, profile, rows_json = row
    return Response(json.dumps({
        "scan_id": rid,
        "created_at": ts,
        "ip": ip,
        "profile": profile,
        "rows": json.loads(rows_json)
    }, indent=2), mimetype="application/json")
