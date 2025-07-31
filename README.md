# OriginIP Tool v1.0
**Discover the true origin IPs behind WAF/CDN-protected domains.**  
Developed by [@Maakthon](https://github.com/Maldevo)

---

## Overview

**OriginIP** is a powerful recon tool for uncovering real IP addresses behind domains protected by Web Application Firewalls (WAFs) or CDNs such as Cloudflare, Akamai, and others.

It gathers potential IPs from multiple intelligence sources (Shodan, VirusTotal, ViewDNS, etc.) and validates them using various techniques like reverse DNS, SSL certificate inspection, HTTP responses, and more.

---
## Usage
```
python OriginIP.py -u https://targetdomain.com
```
### All results are saved in the ./results/ directory.

***Example output files:***
```
targetdomain.com-2025-07-31-15:22:00.txt — raw IPs

targetdomain.com-validated-2025-07-31-15:22:00.txt — validated origin IPs

targetdomain.com-debug-2025-07-31-15:22:00.json — IP to hostname mappings
```

## Features

- 🔧 **Recon Stage** (gathers possible origin IPs from):
  - Favicon hash fingerprinting
  - Shodan search
  - ViewDNS, VirusTotal, SecurityTrails APIs
  - DNSHistory and SPF scraping
  - URLScan.io and AlienVault

- **WAF Detection**
  - Uses `wafw00f` to fingerprint known WAFs

- **Validation Stage**
  - Reverse DNS lookup
  - HTTP and HTTPS response checks
  - SSL Certificate CN/SAN analysis
  - IP-hostname mapping output

- Output
  - Raw IPs
  - Validated origin IPs
  - IP-hostname mapping (JSON)

---

## Installation

1. **Clone the repo**
   ```bash
   git clone https://github.com/maldevo/OriginIP
   cd OriginIP
   ```
2. **Clone the repo**
   ***Install dependencies***
   ```bash
   pip install -r requirements.txt
   ```
3. **Add your API keys**
   ```bash
    shodan=YOUR_SHODAN_KEY
    viewdns=YOUR_VIEWDNS_KEY
    securitytrails=YOUR_SECURITYTRAILS_KEY
    virustotal=YOUR_VIRUSTOTAL_KEY
    alienvault=YOUR_ALIENVAULT_KEY
  ```
```



Developed by Mahmoud Abdalkarim (@Maakthon)
