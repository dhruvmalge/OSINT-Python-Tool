# OSINT Cybersecurity Lab — implementation notes

## Added in this build
- Consent-gated browser telemetry: viewport/screen, pixel ratio, color depth, platform, CPU and memory hints, touch points, locale/time zone, online status, UA client hints, and network API hints.
- IP-derived ISP, ASN, organization and network domain fields, plus approximate geo and VPN/proxy/Tor indicators.
- Random first-party session grouping (not a cross-site identity fingerprint).
- Optional media-device category counts using `enumerateDevices()`; no camera/microphone stream is opened, no media is captured, and labels are not stored.
- Browser-reported camera/microphone permission state where supported.
- Per-visit telemetry JSON visible in the protected link analytics page and CSV export.
- Additive database migration for the new Visit columns; local DB removed from the release archive.

## Important limitations
A web page cannot inspect arbitrary peripherals, installed applications, files, hardware serial numbers, other browser tabs, or OS sessions. Camera/microphone access requires an explicit browser permission and is intentionally not requested here. IP geolocation is approximate. Browser and network hints can be missing or spoofed. VPN/Tor use is not proof of malicious activity.

## Deployment hardening before public use
Set unique `SECRET_KEY`, `ADMIN_USER`, and `ADMIN_PASSWORD_HASH`; set `COOKIE_SECURE=1` behind HTTPS; configure `TRUST_PROXY=1` only behind a trusted proxy; use durable PostgreSQL; add rate limiting, MFA, audit logs, backups, monitoring, and a tested deletion workflow. Review applicable privacy law and the IP enrichment provider's terms. The included starter has not undergone a professional security audit.
