
from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import datetime as dt
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple

# Try to import requests for nicer HTTP handling; fall back to urllib if missing
try:
    import requests  # type: ignore
    HAVE_REQUESTS = True
except Exception:
    import urllib.request
    import urllib.error
    HAVE_REQUESTS = False


# -----------------------------
# Utility data structures
# -----------------------------
@dataclass
class PortFinding:
    port: int
    open: bool
    banner: Optional[str] = None

@dataclass
class TLSFinding:
    enabled: bool
    protocol: Optional[str] = None
    cipher: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_issuer: Optional[str] = None
    cert_not_before: Optional[str] = None
    cert_not_after: Optional[str] = None
    cert_days_to_expiry: Optional[int] = None
    san: Optional[List[str]] = None
    issues: List[str] = None

@dataclass
class HTTPFinding:
    url: str
    status: Optional[int] = None
    headers: Dict[str, str] = None
    security_headers_missing: List[str] = None
    cookie_issues: List[str] = None
    directory_index_exposed: bool = False
    allowed_methods: Optional[List[str]] = None
    server_banner: Optional[str] = None

@dataclass
class ScanReport:
    target: str
    resolved_ip: Optional[str]
    timestamp_utc: str
    ports: List[PortFinding]
    tls: Optional[TLSFinding]
    http: Optional[HTTPFinding]
    notes: List[str]


# -----------------------------
# Common ports to probe
# -----------------------------
DEFAULT_PORTS = [
    # Web
    80, 443, 8080, 8443,
    # SSH, RDP, DBs
    22, 3389, 5432, 3306, 6379, 27017, 9200,
    # Mail
    25, 110, 143, 465, 587, 993, 995,
    # File/remote mgmt
    21, 23, 389, 445, 1521
]


# -----------------------------
# Networking helpers
# -----------------------------

def resolve_host(target: str) -> Optional[str]:
    """Best-effort DNS/host resolution to an IP address."""
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None


def tcp_connect(host: str, port: int, timeout: float) -> Tuple[bool, Optional[str]]:
    """
    Try to establish a TCP connection to host:port.
    If successful, attempt a super-lightweight banner grab by reading
    whatever the server sends first (many services send a greeting).
    """
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            # Non-blocking read peek for a banner (don’t hang if nothing comes)
            s.settimeout(0.5)
            try:
                data = s.recv(256)
                banner = data.decode(errors="ignore").strip() if data else None
            except Exception:
                banner = None
            return True, banner
        except Exception:
            return False, None


def scan_ports(host: str, ports: List[int], timeout: float, max_workers: int = 100) -> List[PortFinding]:
    """Concurrent port scan across selected ports using thread pool."""
    findings: List[PortFinding] = []

    def worker(p: int) -> PortFinding:
        is_open, banner = tcp_connect(host, p, timeout)
        return PortFinding(port=p, open=is_open, banner=banner)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        for f in concurrent.futures.as_completed([ex.submit(worker, p) for p in ports]):
            findings.append(f.result())

    # Sort for nice output
    findings.sort(key=lambda x: x.port)
    return findings


# -----------------------------
# TLS inspection
# -----------------------------

def inspect_tls(host: str, port: int = 443, timeout: float = 3.0) -> TLSFinding:
    """
    Connects with TLS and extracts details:
    - Minimum negotiated protocol (e.g., TLSv1.2)
    - Cipher suite
    - Certificate subject/issuer, expiry, SANs
    - Issues (weak protocol, imminent expiry)

    Note: We rely on `ssl` defaults, which already avoid SSLv3/TLSv1 in modern Python.
    """
    issues: List[str] = []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # we’re auditing, not validating here
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = None
                try:
                    c = ssock.cipher()
                    # c is a tuple: (cipher_name, protocol, secret_bits)
                    cipher = f"{c[0]} ({c[1]}, {c[2]} bits)" if c else None
                except Exception:
                    pass

                # Protocol version string (e.g., 'TLSv1.3')
                try:
                    protocol = ssock.version()
                except Exception:
                    protocol = None

                # Certificate details
                try:
                    cert = ssock.getpeercert()
                except Exception:
                    cert = None

                subject = None
                issuer = None
                not_before = None
                not_after = None
                days_to_expiry = None
                san_list: Optional[List[str]] = None

                if cert:
                    # Subject CN
                    if "subject" in cert:
                        cn_parts = [x[0][1] for x in cert["subject"] if x and x[0][0] == 'commonName']
                        subject = cn_parts[0] if cn_parts else None
                    # Issuer CN
                    if "issuer" in cert:
                        issuer_parts = [x[0][1] for x in cert["issuer"] if x and x[0][0] == 'commonName']
                        issuer = issuer_parts[0] if issuer_parts else None
                    # Validity
                    nb = cert.get("notBefore")
                    na = cert.get("notAfter")
                    if nb:
                        not_before = nb
                    if na:
                        not_after = na
                        # Compute days to expiry for quick risk signal
                        try:
                            exp = dt.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                            delta = exp - dt.datetime.utcnow()
                            days_to_expiry = max(0, delta.days)
                            if days_to_expiry < 14:
                                issues.append("Certificate expires in < 14 days")
                        except Exception:
                            pass
                    # SANs
                    if "subjectAltName" in cert:
                        san_list = [v for (t, v) in cert["subjectAltName"] if t in ("DNS", "IP Address")]

                # Protocol hardening hint
                if protocol and protocol.startswith("TLSv1."):
                    try:
                        minor = int(protocol.split(".")[-1])
                        if minor < 2:
                            issues.append(f"Weak TLS protocol negotiated: {protocol}")
                    except Exception:
                        pass

                return TLSFinding(
                    enabled=True,
                    protocol=protocol,
                    cipher=cipher,
                    cert_subject=subject,
                    cert_issuer=issuer,
                    cert_not_before=not_before,
                    cert_not_after=not_after,
                    cert_days_to_expiry=days_to_expiry,
                    san=san_list,
                    issues=issues,
                )
    except Exception as e:
        return TLSFinding(enabled=False, issues=[f"TLS handshake failed: {e}"])


# -----------------------------
# HTTP checks (headers, cookies, methods, dir index)
# -----------------------------
SECURITY_HEADERS = [
    # Helmet of modern web security; absence is a red flag
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _http_request(url: str, timeout: float = 5.0, method: str = "GET") -> Tuple[int, Dict[str, str], str]:
    """Perform an HTTP request returning (status_code, headers, body)."""
    if HAVE_REQUESTS:
        try:
            resp = requests.request(method, url, timeout=timeout, allow_redirects=True)
            # Normalize header keys casing for consistent access
            headers = {k.strip(): v.strip() for k, v in resp.headers.items()}
            return resp.status_code, headers, resp.text
        except Exception as e:
            raise RuntimeError(str(e))
    else:
        try:
            req = urllib.request.Request(url, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as r:  # type: ignore
                status = getattr(r, 'status', 200)
                headers_list = r.getheaders()
                headers = {k.strip(): v.strip() for k, v in headers_list}
                body_bytes = r.read()
                # Heuristic decode; production code should use chardet/encoding
                body = body_bytes.decode("utf-8", errors="ignore")
                return status, headers, body
        except Exception as e:
            raise RuntimeError(str(e))


def analyze_cookies(headers: Dict[str, str]) -> List[str]:
    """Inspect Set-Cookie headers for missing Secure/HttpOnly/SameSite flags."""
    issues: List[str] = []
    # Servers may emit multiple Set-Cookie headers; requests merges to a list-like
    cookie_headers: List[str] = []

    for k, v in headers.items():
        if k.lower() == "set-cookie":
            cookie_headers.append(v)

    # If multiple cookies are merged into one string (some libs);
    # split naively on comma only when it looks like cookie separators.
    # For teaching simplicity, we'll split on ", " occurrences of key=value
    split_candidates: List[str] = []
    for ch in cookie_headers:
        # Attempt to split while keeping things simple
        parts = re.split(r", (?=[^,=\s]+=[^,=\s])", ch)
        split_candidates.extend(parts)

    for raw in (split_candidates or cookie_headers):
        low = raw.lower()
        # HttpOnly prevents JS access; Secure limits to HTTPS; SameSite thwarts CSRF
        if "httponly" not in low:
            issues.append(f"Cookie missing HttpOnly: {raw[:60]}...")
        if "secure" not in low:
            issues.append(f"Cookie missing Secure: {raw[:60]}...")
        if "samesite" not in low:
            issues.append(f"Cookie missing SameSite: {raw[:60]}...")
    return issues


def http_audit(base_url: str, timeout: float = 5.0) -> HTTPFinding:
    """
    Fetches the page and evaluates common web hardening controls.
    Also performs an OPTIONS call to see what methods are allowed.
    """
    missing: List[str] = []
    cookie_issues: List[str] = []

    # Normalize: if user passed a bare host, assume https first, then http
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        candidates = [f"https://{base_url}", f"http://{base_url}"]
    else:
        candidates = [base_url]

    last_error: Optional[str] = None
    for url in candidates:
        try:
            status, headers, body = _http_request(url, timeout=timeout, method="GET")
            # Identify missing security headers by name (case-insensitive)
            hdr_lc = {k.lower(): v for k, v in headers.items()}
            for h in SECURITY_HEADERS:
                if h.lower() not in hdr_lc:
                    missing.append(h)

            # Cookie flags
            cookie_issues = analyze_cookies(headers)

            # Directory listing check: common signature in default autoindex
            dir_index = bool(re.search(r"<title>Index of /</title>|<h1>Index of /</h1>", body, re.IGNORECASE))

            # OPTIONS to see if dangerous methods are allowed (e.g., PUT, DELETE)
            allowed_methods = None
            try:
                status_opt, headers_opt, _ = _http_request(url, timeout=timeout, method="OPTIONS")
                allow_val = headers_opt.get("Allow") or headers_opt.get("allow")
                if allow_val:
                    allowed_methods = [m.strip() for m in allow_val.split(',')]
            except Exception:
                pass

            # Server header often leaks stack details (Apache/2.4.52, etc.)
            server_banner = headers.get("Server") or headers.get("server")

            return HTTPFinding(
                url=url,
                status=status,
                headers=headers,
                security_headers_missing=sorted(set(missing)),
                cookie_issues=cookie_issues,
                directory_index_exposed=dir_index,
                allowed_methods=allowed_methods,
                server_banner=server_banner,
            )
        except Exception as e:
            last_error = str(e)
            continue

    # If all candidates failed
    return HTTPFinding(url=candidates[0], status=None, headers={}, security_headers_missing=["(request failed)"])


# -----------------------------
# Orchestration
# -----------------------------

def parse_ports_arg(arg: str) -> List[int]:
    """
    Parse a string like "80,443,8000-8005" into a list of ints.
    """
    ports: List[int] = []
    for chunk in arg.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        if '-' in chunk:
            start, end = chunk.split('-', 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(chunk))
    # De-dup and sort
    return sorted(set(ports))


def run_scan(target: str, ports: List[int], timeout: float) -> ScanReport:
    # Resolve target to IP (helpful for reports and to ensure host is valid)
    resolved_ip = resolve_host(target)

    notes: List[str] = []
    if resolved_ip is None:
        notes.append("DNS resolution failed; proceeding with HTTP checks if possible.")

    # 1) Port scan
    port_results = scan_ports(resolved_ip or target, ports, timeout)

    # 2) TLS inspection only if 443 is open or if target appears to be HTTPS-only service
    tls_result = None
    if any(p.port == 443 and p.open for p in port_results) or target.startswith("https://"):
        try:
            host_for_tls = target
            # If schema provided, extract host
            if target.startswith("http://") or target.startswith("https://"):
                host_for_tls = re.sub(r"^https?://", "", target).split('/')[0]
            tls_result = inspect_tls(host_for_tls, 443, timeout)
        except Exception as e:
            notes.append(f"TLS inspection error: {e}")

    # 3) HTTP audit (headers/cookies)
    http_result = None
    try:
        http_result = http_audit(target, timeout=timeout)
    except Exception as e:
        notes.append(f"HTTP audit error: {e}")

    return ScanReport(
        target=target,
        resolved_ip=resolved_ip,
        timestamp_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        ports=port_results,
        tls=tls_result,
        http=http_result,
        notes=notes,
    )


# -----------------------------
# CLI
# -----------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Educational vulnerability scanner for common web risks",
        epilog=(
            "Examples:\n"
            "  python scanner.py example.com\n"
            "  python scanner.py https://example.com --ports 80,443,8000-8010 --timeout 2.5 --json report.json\n"
        ),
    )
    p.add_argument("target", help="Hostname or URL to scan (e.g., example.com or https://example.com)")
    p.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)), help="Comma/range list of ports to scan (default: common set)")
    p.add_argument("--timeout", type=float, default=2.0, help="Per-connection timeout in seconds (default: 2.0)")
    p.add_argument("--json", dest="json_out", default=None, help="Write full JSON report to this file path")
    return p


def as_json(report: ScanReport) -> str:
    """Convert dataclass report into a pretty-printed JSON string."""
    def default(o):
        if hasattr(o, "__dict__"):
            return o.__dict__
        if isinstance(o, (set,)):
            return list(o)
        return str(o)
    return json.dumps(asdict(report), indent=2, default=default)


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    # Convert ports string to numeric list
    try:
        ports = parse_ports_arg(args.ports)
    except Exception:
        print("Invalid --ports format. Use examples like: 80,443,8000-8010", file=sys.stderr)
        return 2

    # Execute the scan
    report = run_scan(args.target, ports, timeout=args.timeout)

    # Print a concise human summary for quick resume/demo output
    print("==== Vulnerability Scan Summary ====")
    print(f"Target:        {report.target}")
    print(f"Resolved IP:   {report.resolved_ip}")
    print(f"Timestamp UTC: {report.timestamp_utc}")

    # Ports
    open_ports = [p.port for p in report.ports if p.open]
    print(f"Open ports:    {open_ports or 'None detected on selected set'}")

    # TLS
    if report.tls and report.tls.enabled:
        print(f"TLS:           {report.tls.protocol} | {report.tls.cipher}")
        if report.tls.issues:
            print(f"TLS issues:    {', '.join(report.tls.issues)}")
    elif report.tls:
        print(f"TLS:           disabled/failed ({'; '.join(report.tls.issues or [])})")

    # HTTP
    if report.http and report.http.status:
        missing = ", ".join(report.http.security_headers_missing or []) or "None"
        print(f"HTTP {report.http.status} at {report.http.url}")
        print(f"Missing headers: {missing}")
        if report.http.cookie_issues:
            print(f"Cookie issues:   {len(report.http.cookie_issues)} (see JSON)")
        if report.http.directory_index_exposed:
            print("Directory index: EXPOSED")
        if report.http.allowed_methods:
            print(f"Allowed methods: {', '.join(report.http.allowed_methods)}")
        if report.http.server_banner:
            print(f"Server banner:   {report.http.server_banner}")

    if report.notes:
        print("Notes:")
        for n in report.notes:
            print(f" - {n}")

    # Optionally write full JSON report (useful for attaching to resumes/portfolios)
    if args.json_out:
        try:
            with open(args.json_out, 'w', encoding='utf-8') as f:
                f.write(as_json(report))
            print(f"\nSaved JSON report to: {args.json_out}")
        except Exception as e:
            print(f"Failed to write JSON report: {e}", file=sys.stderr)
            return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
