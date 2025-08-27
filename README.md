# scanner

A compact, heavily commented Python tool that demonstrates how to assess a host or web app for common security issues. It performs a selective TCP port scan, inspects TLS (protocol/cipher, certificate expiry & SANs), audits HTTP security headers (CSP, HSTS, XFO, XCTO, Referrer-Policy, Permissions-Policy), checks cookie flags (Secure/HttpOnly/SameSite), detects directory listings, and probes allowed HTTP methods. Outputs a human-readable summary and an optional JSON report for documentation.
Features
Concurrent TCP port scanning over a chosen list/range
TLS inspection: negotiated protocol/cipher, cert subject/issuer, SANs, days to expiry, weak-protocol warnings
HTTP hardening audit: required headers, cookie flags, server banner, directory index detection, OPTIONS allow-list
Report options: concise console summary + --json full report for audit trails
