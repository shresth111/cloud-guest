# White Label & Custom Branding Architecture

This domain powers the customization engine, allowing B2B tenant organizations and individual branch locations to replace CloudGuest brand assets with their own visual elements on the captive portals, emails, and dashboards.

## Modules
- **Branding Engine**: Custom logos, color palettes (hex codes), favicons, support contacts, and compliance page pointers.
- **Theme Engine**: Complete landing layouts, advertisement spaces, and direct CSS/JS code insertions for captive Wi-Fi guest portals.
- **Domain Engine**: Registration of custom target hostnames (e.g., `wifi.tenant.com`), generation of DNS TXT ownership challenge tokens, and automated LetsEncrypt SSL certificate handshakes.
