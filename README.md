<p align="center"> <em>a single-file network scanner, port auditor, banner grabber, TLS inspector and security finder — my networking exam project</em> </p><p align="center"> <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blueviolet?style=for-the-badge&logo=python"> <img alt="License" src="https://img.shields.io/badge/license-MIT-lightgrey?style=for-the-badge"> <img alt="Sockets" src="https://img.shields.io/badge/protocols-TCP%20%2B%20UDP%20%2B%20ARP%20%2B%20TLS-ff69b4?style=for-the-badge"> <img alt="Status" src="https://img.shields.io/badge/exam%20project-%E2%9C%94%20submitted-success?style=for-the-badge"> </p>

---
## hii
#### this is my networking/cybersecurity exam project and i'm so proud of how it turned out
#### it's called Network Toolkit and it's a single Python file that does the sort of thing you'd normally reach for nmap, sslyze, and a bunch of one-off scripts for — but in one place, with a GUI and a CLI, with safety rails and real findings.
#### i wrote it because our networking unit spent a whole term on sockets and protocol framing, and i wanted to build something that actually used all of it: raw TCP connects, UDP probes with service-specific payloads, DNS query construction, SNMP BER encoding, TLS handshakes, ARP scans, the works.
#### legal notice first: this tool is for authorized security testing only. only scan networks you own or have explicit written permission to test. it refuses to scan public IPs by default for exactly this reason — you have to flip a setting and accept the consequences.
---
## what it actually does
### discovery & scanning
- Host discovery with ICMP ping, TCP-ping fallback, and ARP (via arp-scan, arping, or the OS ARP table)
- TCP port scanning with configurable timeouts, thread pool, and token-bucket rate limiting
- UDP port scanning with service-specific probe payloads (DNS queries, SNMP GETs, SSDP M-SEARCH, memcached, Redis, etc.)
- Banner grabbing across HTTP, SSH, FTP, SMTP, IMAP, POP3, Redis, Memcached, MongoDB, and TLS endpoints
- Service identification via regex patterns on banners, falling back to well-known port names
- Version extraction from banners (OpenSSH, Apache, vsftpd, Exim, etc.)
- OS fingerprinting from TTL heuristics
- Traceroute with a TTL-walk fallback if the OS tool isn't available

### security auditing
- TLS deep inspection — protocol version, cipher suite, weak ciphers, expiry days, self-signed detection, SANs, issuer, SHA-256 fingerprint
- HTTP security header audit — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, plus server version disclosure
- HTTP endpoint enumeration — probes .git/HEAD, .env, .svn/entries, server-status, phpinfo.php, Spring Actuator, robots.txt, sitemap.xml, security.txt, and more
- Read-only service exposure checks — anonymous FTP, SMTP VRFY, Redis PING/INFO, memcached stats, Docker API, Elasticsearch health, MongoDB isMaster, LDAP anonymous bind, RDP X.224, SNMP community "public"
- CVE signature rules — Heartbleed, Terrapin, vsftpd 2.3.4 backdoor, ProFTPD 1.3.3 backdoor, Apache 2.4.49 path traversal, SMBv1 negotiation, EOL software versions
- Security findings engine with severity ranking (info → low → medium → high → critical)

### utilities
- Subnet calculator — network, broadcast, netmask, host range, host count
- DNS lookup — A/AAAA/MX/NS/TXT/CNAME/SOA (with dnspython) + reverse DNS
- Whois / RDAP — command-line whois first, HTTPS RDAP fallback
- DNS zone transfer (AXFR) attempt with dnspython
- Wake-on-LAN magic packet sender
- Nmap XML import for when you want to combine tools
- Diff vs previous scan — added / removed / changed hosts
- Monitor mode — auto-rescans every N seconds and logs diffs
- Session save/load with SHA-256 integrity checksums

### export formats and interfaces
- JSON, CSV, XML, Markdown, HTML, DOT (Graphviz), GraphML, plain text
- Tkinter GUI with six tabs: Scanner, Results, Findings, Dashboard, Tools, Settings
- Headless CLI with --target, --targets-file, --mode, --json, --rate, --udp
- Self-test suite with ~60 assertions (--selftest)
---

## installation
#### you'll need Python 3.10+. Tkinter is bundled with most Python installs.
#### optional but recommended:
```
pip install dnspython cryptography
```
- dnspython → full A/AAAA/MX/NS/TXT/SOA/CNAME records and AXFR
- cryptography → proper X.509 parsing (issuer, SAN, extension, serial)
- arp-scan (Linux) or arping → faster and more reliable ARP discovery
- whois — falls back to HTTPS RDAP if you don't have it
- traceroute / tracert — otherwise uses TTL-walk fallback
#### linux extras for ARP
```
sudo apt install arp-scan iputils-arping whois traceroute
```
### run it
```
# GUI (default)
python main.py

# self-test
python main.py --selftest

# headless CLI
python main.py --cli --target 192.168.1.0/24 --mode discover
```
---
