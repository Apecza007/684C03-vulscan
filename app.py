from __future__ import annotations

import html
import json
import os
import sqlite3
import secrets
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from functools import wraps

from scanner import ScanConfig, run_scan
from storage import get_scan, init_db, save_scan

# การตั้งค่าการยืนยันตัวตน
AUTH_USER = os.getenv("NEXORA_USER", "admin")
AUTH_PASS = os.getenv("NEXORA_PASS", "changeme")
COOKIE_NAME = "session_token"

# เก็บ session
sessions = {}

MODE_DETAILS = {
    "quick": "สแกนเร็ว: Host discovery + Top ports",
    "balanced": "สแกนสมดุล: เพิ่ม service/version detection และ NSE vulners",
    "deep": "สแกนเชิงลึก: ใช้เครื่องมือที่เลือกทั้งหมดและเก็บรายละเอียดมากขึ้น",
}

CSS_PATH = Path("static/style.css")
DB_PATH = Path("scan_results.db")

def create_session() -> str:
    """สร้าง session token ใหม่"""
    token = secrets.token_urlsafe(32)
    sessions[token] = datetime.now().timestamp() + 86400  # 24 ชั่วโมง
    return token

def validate_session(token: str) -> bool:
    """ตรวจสอบ session token"""
    if token not in sessions:
        return False
    if sessions[token] < datetime.now().timestamp():
        del sessions[token]
        return False
    return True

def _escape_pdf_text(value: str) -> str:
    """จัดการ escape characters สำหรับ PDF"""
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

def _extract_port_lines(scan: dict) -> list[str]:
    """ดึงข้อมูล port จากผลการสแกน"""
    findings = scan.get("result", {}).get("findings", {})
    nmap = findings.get("nmap", {})
    ports: list[str] = []
    for phase in nmap.get("phases", []):
        stdout = phase.get("stdout", "")
        for line in stdout.splitlines():
            stripped = line.strip()
            if "/tcp" in stripped and "open" in stripped:
                ports.append(stripped)
    return ports[:8]

def _estimate_risk(scan: dict) -> tuple[str, list[str]]:
    """ประเมินระดับความเสี่ยงจากผลการสแกน"""
    ports = _extract_port_lines(scan)
    findings = scan.get("result", {}).get("findings", {})
    issue_count = len(ports)
    if findings.get("zap", {}).get("status") == "available":
        issue_count += 2
    if findings.get("arachni", {}).get("status") == "available":
        issue_count += 2

    if issue_count >= 6:
        level = "HIGH"
    elif issue_count >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    vulns: list[str] = []
    for idx, port_line in enumerate(ports[:4], start=1):
        severity = "LOW" if idx % 2 else "MEDIUM"
        vulns.append(f"[{severity}] {port_line}")
    if not vulns:
        vulns.append("No obvious high-risk service found from available scan output")
    return level, vulns

def build_pdf_report(scan: dict) -> bytes:
    """สร้าง PDF report จากข้อมูลการสแกน"""
    target = scan["target"]
    scan_id = scan["id"]
    created = scan["created_at"]
    status = "COMPLETED"
    mode = scan["scan_mode"].upper()
    risk_level, vuln_lines = _estimate_risk(scan)
    port_lines = _extract_port_lines(scan)

    content: list[str] = []
    y_position = 795

    def add_text(y: int, text: str, size: int = 11, x: int = 45, indent: int = 0) -> int:
        nonlocal y_position
        safe = _escape_pdf_text(text[:120])
        x_pos = x + indent
        content.append(f"BT /F1 {size} Tf {x_pos} {y} Td ({safe}) Tj ET")
        return y - (size + 4)

    # ส่วนหัว
    content.append("0.05 0.10 0.22 rg")
    content.append("30 770 535 45 re f")
    content.append("0 0 0 rg")
    y_position = add_text(795, "684C03 VULNERABILITY ASSESSMENT REPORT", 18, 45)
    y_position = add_text(778, "CONFIDENTIAL SECURITY DOCUMENT", 10, 45)

    # สารบัญ
    y_position -= 25
    y_position = add_text(y_position, "TABLE OF CONTENTS", 14, 45)
    y_position = add_text(y_position, "1. Scan Information", 11, 45, 10)
    y_position = add_text(y_position, "2. Host Discovery Results", 11, 45, 10)
    y_position = add_text(y_position, "3. Port & Service Detection", 11, 45, 10)
    y_position = add_text(y_position, "4. Vulnerability Findings", 11, 45, 10)
    y_position = add_text(y_position, "5. Risk Summary", 11, 45, 10)
    y_position = add_text(y_position, "6. Recommendations", 11, 45, 10)

    # ส่วนที่ 1
    y_position -= 25
    y_position = add_text(y_position, "1. SCAN INFORMATION", 15, 45)
    y_position = add_text(y_position, f"Target: {target}", 11, 45, 10)
    y_position = add_text(y_position, f"Scan ID: {scan_id}", 11, 300, 10)
    y_position = add_text(y_position, f"Date: {created}", 11, 300, 10)
    y_position = add_text(y_position, f"Status: {status}", 11, 300, 10)
    y_position = add_text(y_position, f"Mode: {mode}", 11, 300, 10)

    # ส่วนที่ 2
    y_position -= 25
    y_position = add_text(y_position, "2. HOST DISCOVERY", 15, 45)
    host_info = f"Target {target} - Reachability depends on network policy"
    y_position = add_text(y_position, host_info, 11, 45, 10)

    # ส่วนที่ 3
    y_position -= 25
    y_position = add_text(y_position, "3. PORT & SERVICE DETECTION", 15, 45)
    if port_lines:
        y_position = add_text(y_position, "Open ports found:", 11, 45, 10)
        for line in port_lines[:6]:
            y_position = add_text(y_position, f"• {line}", 10, 45, 20)
            if y_position < 100:
                content.append("0.05 0.10 0.22 rg")
                content.append("30 770 535 45 re f")
                y_position = 750
    else:
        y_position = add_text(y_position, "No open ports detected", 11, 45, 10)

    # ส่วนที่ 4
    if y_position < 200:
        content.append("0.05 0.10 0.22 rg")
        content.append("30 770 535 45 re f")
        y_position = 750
    
    y_position -= 25
    y_position = add_text(y_position, "4. VULNERABILITY FINDINGS", 15, 45)
    for line in vuln_lines[:6]:
        y_position = add_text(y_position, f"• {line}", 10, 45, 10)
        if y_position < 150:
            break

    # ส่วนที่ 5
    if y_position < 200:
        content.append("0.05 0.10 0.22 rg")
        content.append("30 770 535 45 re f")
        y_position = 750
    
    y_position -= 25
    y_position = add_text(y_position, "5. RISK SUMMARY", 15, 45)
    y_position = add_text(y_position, f"Overall Risk Level: {risk_level}", 12, 45, 10)
    y_position = add_text(y_position, f"Findings Count: {len(vuln_lines)}", 11, 45, 10)

    # ส่วนที่ 6
    y_position -= 25
    y_position = add_text(y_position, "6. RECOMMENDATIONS", 15, 45)
    recommendations = [
        "• Patch exposed services immediately",
        "• Run balanced/deep scans regularly",
        "• Review firewall rules",
        "• Update all software versions"
    ]
    for rec in recommendations:
        y_position = add_text(y_position, rec, 11, 45, 10)

    # สร้าง PDF
    stream_data = "\n".join(content).encode("latin-1", errors="replace")
    
    objects: list[bytes] = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
    objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
    objects.append(
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n"
    )
    objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
    objects.append(
        f"5 0 obj << /Length {len(stream_data)} >> stream\n".encode("ascii")
        + stream_data
        + b"\nendstream endobj\n"
    )

    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    pdf = bytearray(header)
    offsets = [0]
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)

    xref_offset = len(pdf)
    xref = [f"xref\n0 {len(objects) + 1}\n", "0000000000 65535 f \n"]
    for offset in offsets[1:]:
        xref.append(f"{offset:010d} 00000 n \n")
    pdf.extend("".join(xref).encode("ascii"))
    trailer = (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    )
    pdf.extend(trailer.encode("ascii"))
    return bytes(pdf)

def render_index(error: str = "") -> str:
    """แสดงหน้าแรก"""
    mode_options = "".join(
        f'<option value="{m}">{m.capitalize()} - {html.escape(desc)}</option>'
        for m, desc in MODE_DETAILS.items()
    )
    error_html = f'<div class="alert error">{html.escape(error)}</div>' if error else ""
    return f"""<!doctype html>
<html lang="th">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>684C03 Vulnerability Scanner</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <main class="container">
    <h1>684C03 Vulnerability Scanner</h1>
    <p class="subtitle">สแกนช่องโหว่สำหรับ IP, Domain และ URL พร้อมเลือกโหมดการสแกน</p>
    <div class="nav-links">
      <a href="/" class="btn">หน้าหลัก</a>
      <a href="/history" class="btn">ประวัติการสแกน</a>
      <a href="/logout" class="btn">ออกจากระบบ</a>
    </div>
    {error_html}
    <form action="/scan" method="post" class="card">
      <label>เป้าหมาย</label>
      <input type="text" name="target" placeholder="เช่น 192.168.1.1, example.com, https://example.com" required>

      <label>ประเภทเป้าหมาย</label>
      <div class="grid3">
        <label><input type="radio" name="target_type" value="ip" required> IP Address</label>
        <label><input type="radio" name="target_type" value="domain"> Domain</label>
        <label><input type="radio" name="target_type" value="url"> URL</label>
      </div>

      <label>โหมดการสแกน</label>
      <select name="scan_mode" required>{mode_options}</select>

      <label>เครื่องมือที่ใช้</label>
      <div class="grid3">
        <label><input type="checkbox" name="tools" value="nmap" checked> Nmap</label>
        <label><input type="checkbox" name="tools" value="zap" checked> OWASP ZAP</label>
        <label><input type="checkbox" name="tools" value="arachni" checked> Arachni</label>
      </div>

      <button type="submit">เริ่มสแกน</button>
    </form>
  </main>
</body>
</html>"""

def render_login(error: str = "") -> str:
    """แสดงหน้าเข้าสู่ระบบ"""
    error_html = f'<div class="alert error">{html.escape(error)}</div>' if error else ""
    return f"""<!doctype html>
<html lang="th">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>เข้าสู่ระบบ - 684C03 Scanner</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <main class="container">
    <h1>684C03 Vulnerability Scanner</h1>
    <div class="card login-form">
        <h2>เข้าสู่ระบบ</h2>
        {error_html}
        <form action="/login" method="post">
            <label>Username</label>
            <input type="text" name="username" required>
            
            <label>Password</label>
            <input type="password" name="password" required>
            
            <button type="submit">เข้าสู่ระบบ</button>
        </form>
    </div>
  </main>
</body>
</html>"""

def render_history(page: int = 1, per_page: int = 10) -> str:
    """แสดงประวัติการสแกน"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    total = conn.execute("SELECT COUNT(*) as count FROM scan_runs").fetchone()["count"]
    offset = (page - 1) * per_page
    rows = conn.execute(
        "SELECT id, target, target_type, scan_mode, created_at FROM scan_runs ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (per_page, offset)
    ).fetchall()
    conn.close()

    total_pages = (total + per_page - 1) // per_page

    history_rows = ""
    for row in rows:
        history_rows += f"""
        <tr>
            <td>#{row['id']}</td>
            <td>{html.escape(row['target'])}</td>
            <td>{row['target_type']}</td>
            <td>{row['scan_mode']}</td>
            <td>{row['created_at']}</td>
            <td>
                <a href="/results/{row['id']}" class="btn-small">ดูผล</a>
                <a href="/results/{row['id']}/json" class="btn-small">JSON</a>
                <a href="/results/{row['id']}/pdf" class="btn-small">PDF</a>
            </td>
        </tr>
        """

    pagination = ""
    if total_pages > 1:
        pagination = '<div class="pagination">'
        if page > 1:
            pagination += f'<a href="/history?page={page-1}">‹ ก่อนหน้า</a>'
        pagination += f'<span>หน้า {page} จาก {total_pages}</span>'
        if page < total_pages:
            pagination += f'<a href="/history?page={page+1}">ถัดไป ›</a>'
        pagination += '</div>'

    return f"""<!doctype html>
<html lang="th">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ประวัติการสแกน - 684C03 Scanner</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <main class="container">
    <h1>ประวัติการสแกน</h1>
    <div class="nav-links">
      <a href="/" class="btn">← กลับหน้าหลัก</a>
    </div>

    <div class="card">
        <table class="history-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Target</th>
                    <th>Type</th>
                    <th>Mode</th>
                    <th>Date</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {history_rows if history_rows else '<tr><td colspan="6" class="text-center">ไม่พบประวัติการสแกน</td></tr>'}
            </tbody>
        </table>
        {pagination}
    </div>
  </main>
</body>
</html>"""

def render_result(scan: dict) -> str:
    """แสดงผลการสแกน"""
    findings = html.escape(json.dumps(scan["result"]["findings"], ensure_ascii=False, indent=2))
    raw = html.escape(json.dumps(scan["result"], ensure_ascii=False, indent=2))
    return f"""<!doctype html>
<html lang="th">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>ผลการสแกน #{scan['id']}</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <main class="container">
    <h1>ผลการสแกน #{scan['id']}</h1>
    <p class="subtitle">Target: {html.escape(scan['target'])} | Type: {scan['target_type']} | Mode: {scan['scan_mode']}</p>
    <p><a href="/results/{scan['id']}/json">ดาวน์โหลด JSON report</a> | <a href="/results/{scan['id']}/pdf">ดาวน์โหลด PDF report</a></p>
    <p><a href="/">← กลับหน้าหลัก</a> | <a href="/history">ดูประวัติทั้งหมด</a></p>

    <section class="card">
      <h2>Findings</h2>
      <pre>{findings}</pre>
    </section>

    <section class="card">
      <h2>Raw Result JSON</h2>
      <pre>{raw}</pre>
    </section>
  </main>
</body>
</html>"""

class AppHandler(BaseHTTPRequestHandler):
    """จัดการ HTTP requests"""
    
    def do_GET(self) -> None:
        init_db()
        parsed = urlparse(self.path)
        
        if parsed.path == "/login":
            self._send_html(render_login())
            return
        
        if parsed.path == "/static/style.css":
            self._serve_css()
            return
        
        if parsed.path == "/logout":
            self._handle_logout()
            return
        
        if not self._check_auth():
            return
        
        if parsed.path == "/":
            self._send_html(render_index())
            return
        
        if parsed.path == "/history":
            query = parse_qs(parsed.query)
            page = int(query.get('page', ['1'])[0])
            self._send_html(render_history(page))
            return
        
        if parsed.path.startswith("/results/"):
            self._handle_results(parsed.path)
            return
        
        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
    
    def do_POST(self) -> None:
        init_db()
        parsed = urlparse(self.path)
        
        if parsed.path == "/login":
            self._handle_login()
            return
        
        if not self._check_auth():
            return
        
        if parsed.path == "/scan":
            self._handle_scan()
            return
        
        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
    
    def _check_auth(self) -> bool:
        cookie = SimpleCookie(self.headers.get('Cookie', ''))
        session = cookie.get(COOKIE_NAME)
        
        if session and validate_session(session.value):
            return True
        
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header('Location', '/login')
        self.end_headers()
        return False
    
    def _handle_logout(self):
        cookie = SimpleCookie(self.headers.get('Cookie', ''))
        session = cookie.get(COOKIE_NAME)
        if session and session.value in sessions:
            del sessions[session.value]
        
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header('Location', '/login')
        self.send_header('Set-Cookie', f'{COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0')
        self.end_headers()
    
    def _handle_login(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8")
        params = parse_qs(body)
        
        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]
        
        if username == AUTH_USER and password == AUTH_PASS:
            token = create_session()
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie', f'{COOKIE_NAME}={token}; HttpOnly; Path=/; Max-Age=86400')
            self.end_headers()
            return
        
        self._send_html(render_login("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"), HTTPStatus.UNAUTHORIZED)
    
    def _serve_css(self):
        if CSS_PATH.exists():
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.end_headers()
            self.wfile.write(CSS_PATH.read_bytes())
            return
        self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
    
    def _handle_results(self, path: str):
        if path.endswith("/json"):
            run_id = self._extract_run_id(path, suffix="/json")
            if run_id is None:
                return
            scan = get_scan(run_id)
            if not scan:
                self.send_error(HTTPStatus.NOT_FOUND, "Scan not found")
                return
            payload = json.dumps(scan["result"], ensure_ascii=False, indent=2)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", f"attachment; filename=scan-{run_id}.json")
            self.end_headers()
            self.wfile.write(payload.encode("utf-8"))
            return
        
        if path.endswith("/pdf"):
            run_id = self._extract_run_id(path, suffix="/pdf")
            if run_id is None:
                return
            scan = get_scan(run_id)
            if not scan:
                self.send_error(HTTPStatus.NOT_FOUND, "Scan not found")
                return
            payload = build_pdf_report(scan)
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f"attachment; filename=scan-{run_id}.pdf")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        
        run_id = self._extract_run_id(path)
        if run_id is None:
            return
        scan = get_scan(run_id)
        if not scan:
            self.send_error(HTTPStatus.NOT_FOUND, "Scan not found")
            return
        self._send_html(render_result(scan))
    
    def _handle_scan(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length).decode("utf-8")
        params = parse_qs(body)

        target = params.get("target", [""])[0]
        target_type = params.get("target_type", [""])[0]
        scan_mode = params.get("scan_mode", ["quick"])[0]
        tools = params.get("tools", [])

        if scan_mode not in MODE_DETAILS:
            self._send_html(render_index("โหมดสแกนไม่ถูกต้อง"), status=HTTPStatus.BAD_REQUEST)
            return

        if not tools:
            self._send_html(render_index("กรุณาเลือกเครื่องมืออย่างน้อย 1 ตัว"), status=HTTPStatus.BAD_REQUEST)
            return

        try:
            result = run_scan(
                ScanConfig(target=target, target_type=target_type, scan_mode=scan_mode, tools=tools)
            )
        except ValueError as exc:
            self._send_html(render_index(str(exc)), status=HTTPStatus.BAD_REQUEST)
            return

        run_id = save_scan(
            target=result["target"],
            target_type=result["target_type"],
            scan_mode=result["scan_mode"],
            tools=result["tools"],
            created_at=datetime.now().isoformat(timespec="seconds"),
            result=result,
        )

        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", f"/results/{run_id}")
        self.end_headers()
    
    def _send_html(self, content: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def _extract_run_id(self, path: str, suffix: str = "") -> int | None:
        token = path.removeprefix("/results/")
        if suffix and token.endswith(suffix):
            token = token[: -len(suffix)]
        token = token.strip("/")
        if not token.isdigit():
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid run id")
            return None
        return int(token)

if __name__ == "__main__":
    init_db()
    host = os.getenv("NEXORA_HOST", "0.0.0.0")
    port = int(os.getenv("NEXORA_PORT", "5000"))
    server = ThreadingHTTPServer((host, port), AppHandler)
    print(f"684C03 Scanner ทำงานที่ http://{host}:{port}")
    print(f"ล็อกอินด้วย username: {AUTH_USER} / password: {AUTH_PASS}")
    server.serve_forever()