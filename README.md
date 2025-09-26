# Web Risk Scanner (Python)
An educational, single-file Python scanner that performs:
- **Concurrent TCP port checks** on a sensible default list  
- **TLS inspection** (protocol, cipher, cert subject/issuer, SANs, expiry)  
- **HTTP audit** (status, headers, cookie flags, directory listing, allowed methods, server banner)

> ⚠️ **Ethical Use Only** — Scan **only** systems you own or have explicit permission to test. This tool is designed for learning and portfolio demonstrations.

---

## ✨ What it checks

- **Ports**: quick TCP connect & lightweight banner peek on common services (web/ssh/db/mail/etc.)
- **TLS**: negotiated protocol (e.g., TLSv1.2/1.3), cipher, certificate metadata, SANs, days-to-expiry, and basic weakness hints
- **HTTP**:
  - Missing security headers:  
    `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`
  - Cookie flags (per `Set-Cookie`): `Secure`, `HttpOnly`, `SameSite`
  - Directory listing exposure (naive autoindex detection)
  - Allowed methods (via `OPTIONS`)
  - `Server` banner

---

## 📦 Requirements

- **Python 3.8+**
- Optional: `requests` (nicer HTTP handling). If not installed, the tool automatically falls back to `urllib`.

Install `requests` (optional):
```bash
pip install requests
