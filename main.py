from __future__ import annotations
import argparse, contextlib, csv, ctypes, re, select, shutil
import hashlib, html as _html, ipaddress
import itertools, json, logging, os, platform, queue, random
import signal, socket, ssl, string, struct, sys, subprocess
import tempfile, threading, time, traceback, webbrowser
import urllib.error, urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
    from tkinter.ttk import Notebook, PanedWindow, Treeview
    _HAVE_TK = True
except Exception:  # pragma: no cover
    tk = None  # type: ignore
    _HAVE_TK = False
try:
    import dns.resolver  # type: ignore
    import dns.reversename  # type: ignore
    import dns.zone  # type: ignore
    import dns.query  # type: ignore
    _HAVE_DNSPYTHON = True
except Exception:
    dns = None  # type: ignore
    _HAVE_DNSPYTHON = False
try:
    from cryptography import x509 as _x509  # type: ignore
    _HAVE_CRYPTOGRAPHY = True
except Exception:
    _x509 = None  # type: ignore
    _HAVE_CRYPTOGRAPHY = False
APP_NAME = "Network Toolkit"
APP_VERSION = "1.0"
DEFAULT_PORT_TIMEOUT = 0.6
DEFAULT_BANNER_TIMEOUT = 2.0
DEFAULT_PING_TIMEOUT = 1.0
DEFAULT_DNS_TIMEOUT = 3.0
DEFAULT_HTTP_TIMEOUT = 4.0
MAX_HOSTS_PER_SWEEP = 65536
MAX_SCAN_THREADS = 1024
DEFAULT_THREADS = 128
MAX_BANNER_LEN = 4096
LOG_QUEUE_MAX = 50000
MAX_ROWS_RENDER = 5000 
CONFIG_DIR = Path.home() / ".network_toolkit"
HISTORY_FILE = CONFIG_DIR / "history.json"
CONFIG_FILE = CONFIG_DIR / "config.json"
PRESETS_FILE = CONFIG_DIR / "port_presets.json"
AUDIT_FILE = CONFIG_DIR / "audit.log"
CRASH_FILE = CONFIG_DIR / "crash.log"
SESSION_FILE = CONFIG_DIR / "last_session.json"
DEFAULT_RATE_PPS = 0.0 
MONITOR_DEFAULT_INTERVAL = 60.0 
PRIVATE_NETWORKS: Tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
)
WELL_KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "KERBEROS", 110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP",
    135: "MSRPC", 137: "NETBIOS-NS", 138: "NETBIOS-DGM", 139: "NETBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP", 179: "BGP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    500: "ISAKMP", 514: "SYSLOG", 515: "LPD", 520: "RIP",
    548: "AFP", 554: "RTSP", 587: "SMTP-SUB", 631: "IPP",
    636: "LDAPS", 646: "LDP", 873: "RSYNC", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OPENVPN",
    1433: "MSSQL", 1434: "MSSQL-BROWSER", 1521: "ORACLE",
    1701: "L2TP", 1723: "PPTP", 1812: "RADIUS", 1883: "MQTT",
    1900: "SSDP", 2049: "NFS", 2082: "CPANEL", 2083: "CPANEL-SSL",
    2181: "ZOOKEEPER", 2222: "SSH-ALT", 2375: "DOCKER",
    2376: "DOCKER-TLS", 3000: "GRAFANA/NODE", 3128: "SQUID",
    3260: "ISCSI", 3306: "MYSQL", 3389: "RDP", 3690: "SVN",
    4444: "METASPLOIT", 5000: "UPNP", 5060: "SIP",
    5432: "POSTGRES", 5672: "AMQP", 5900: "VNC", 5901: "VNC-1",
    5984: "COUCHDB", 6379: "REDIS", 6443: "K8S-API",
    7001: "WEBLOGIC", 7002: "WEBLOGIC-SSL", 8000: "HTTP-ALT",
    8008: "HTTP-ALT", 8080: "HTTP-PROXY", 8081: "HTTP-ALT",
    8443: "HTTPS-ALT", 8888: "HTTP-ALT", 9000: "PHP-FPM",
    9090: "PROMETHEUS", 9200: "ELASTICSEARCH", 9300: "ELASTICSEARCH",
    9418: "GIT", 9999: "HTTP-ALT", 10000: "WEBMIN",
    11211: "MEMCACHED", 15672: "RABBITMQ-MGMT", 27017: "MONGODB",
    27018: "MONGODB-SHARD", 50000: "DB2", 50070: "HDFS",
}
_RAW_PATTERNS: Dict[str, List[str]] = {
    "SSH":       [r"SSH-([\d.]+)-([\w.]+)", r"OpenSSH[_\-]([\w.]+)", r"dropbear[_\-]?([\w.]*)"],
    "HTTP":      [r"HTTP/[\d.]+", r"Server:\s*([^\r\n]+)"],
    "HTTPS":     [r"HTTP/[\d.]+", r"Server:\s*([^\r\n]+)"],
    "FTP":       [r"220[- ].*FTP", r"vsftpd ([\d.]+)", r"ProFTPD ([\d.]+)", r"FileZilla"],
    "SMTP":      [r"220[- ].*SMTP", r"ESMTP", r"Postfix", r"Exim ([\d.]+)", r"Sendmail"],
    "POP3":      [r"\+OK", r"POP3", r"Dovecot"],
    "IMAP":      [r"\* OK", r"IMAP", r"Dovecot"],
    "MySQL":     [r"(\d+\.\d+\.\d+)[\-\w]*mysql", r"MariaDB", r"mysql_native_password"],
    "PostgreSQL":[r"PostgreSQL", r"FATAL.*password"],
    "Redis":     [r"-ERR", r"\+PONG", r"redis_version:([\d.]+)"],
    "MongoDB":   [r"MongoDB", r"ismaster", r"maxWireVersion"],
    "RDP":       [r"\x03\x00\x00", r"RDP"],
    "VNC":       [r"RFB (\d+\.\d+)"],
    "Telnet":    [r"login:", r"Password:", r"Welcome"],
    "SMB":       [r"\x00\x00\x00", r"SMB", r"NT LM 0\.12"],
    "LDAP":      [r"LDAP", r"objectClass"],
    "SNMP":      [r"SNMP", r"public"],
    "MQTT":      [r"MQTT", r"CONNACK"],
    "Docker":    [r"Docker", r"ApiVersion"],
    "Elastic":   [r"elasticsearch", r"cluster_name", r"\"version\""],
    "K8s":       [r"kubernetes", r"k8s", r"ApiServer"],
    "Memcached": [r"STAT ", r"VERSION ([\d.]+)"],
    "Kafka":     [r"kafka", r"broker"],
    "Zookeeper": [r"zookeeper", r"ZooKeeper"],
    "NTP":       [r"NTP", r"stratum"],
    "SIP":       [r"SIP/2\.0", r"REGISTER"],
    "Rsync":     [r"@RSYNCD", r"rsync"],
    "Git":       [r"git-upload-pack", r"git-receive-pack"],
    "Cassandra": [r"CQL_VERSION", r"cassandra"],
    "Neo4j":     [r"neo4j", r"Bolt"],
    "Prometheus":[r"prometheus", r"metrics"],
    "RabbitMQ":  [r"AMQP", r"rabbit"],
    "AMQP":      [r"AMQP"],
    "SMB2":      [r"SMB2", r"\xfeSMB"],
    "IKE":       [r"IKE", r"ISAKMP"],
}
SERVICE_PATTERNS: Dict[str, List[re.Pattern]] = {
    svc: [re.compile(p, re.IGNORECASE) for p in pats]
    for svc, pats in _RAW_PATTERNS.items()
}

_VERSION_OVERRIDES: Dict[str, List[str]] = {
    "SSH": [r"OpenSSH[_\-]([\w.]+)", r"dropbear[_\-]?([\w.]+)",
            r"SSH-[\d.]+-([\w.]+)"],
    "HTTP": [r"Server:\s*([^\r\n]+)", r"X-Powered-By:\s*([^\r\n]+)"],
    "HTTPS": [r"Server:\s*([^\r\n]+)"],
    "FTP": [r"vsftpd\s+([\d.]+)", r"ProFTPD\s+([\d.]+)",
            r"FileZilla[^0-9]*([\d.]+)"],
    "SMTP": [r"Exim\s+([\d.]+)", r"Postfix\s+([\d.]+)", r"([\d.]+)\s+ESMTP"],
    "VNC": [r"RFB\s+([\d.]+)"],
    "Memcached": [r"VERSION\s+([\w.]+)"],
}
_VERSION_PATTERNS: Dict[str, re.Pattern] = {}
for _svc, _ovs in _VERSION_OVERRIDES.items():
    for _p in _ovs:
        try:
            _c = re.compile(_p, re.IGNORECASE)
        except re.error:
            continue
        if _c.groups >= 1:
            _VERSION_PATTERNS[_svc] = _c
            break
for _svc, _pats in _RAW_PATTERNS.items():
    if _svc in _VERSION_PATTERNS:
        continue
    _vp = None
    for _p in _pats:
        try:
            _c = re.compile(_p, re.IGNORECASE)
        except re.error:
            continue
        if _c.groups >= 1:
            _vp = _c
            break
    if _vp is not None:
        _VERSION_PATTERNS[_svc] = _vp
FINDING_RULES: List[Dict[str, Any]] = [
    {"ports": [23],     "severity": "high",     "title": "Telnet exposed",
     "detail": "Telnet transmits credentials in cleartext. Replace with SSH."},
    {"ports": [21],     "severity": "medium",   "title": "FTP exposed",
     "detail": "FTP may allow anonymous login and sends credentials in cleartext."},
    {"ports": [445],    "severity": "high",     "title": "SMB exposed",
     "detail": "SMBv1 vulnerabilities (e.g., EternalBlue) may be present."},
    {"ports": [3389],   "severity": "high",     "title": "RDP exposed",
     "detail": "RDP exposed to the network — brute-force and BlueKeep risk."},
    {"ports": [3306],   "severity": "medium",   "title": "MySQL exposed",
     "detail": "Database reachable on the network — restrict to app servers."},
    {"ports": [5432],   "severity": "medium",   "title": "PostgreSQL exposed",
     "detail": "Database reachable on the network — restrict access."},
    {"ports": [6379],   "severity": "critical", "title": "Redis exposed",
     "detail": "Unauthenticated Redis is a common RCE vector."},
    {"ports": [27017],  "severity": "critical", "title": "MongoDB exposed",
     "detail": "MongoDB may have no auth by default."},
    {"ports": [9200],   "severity": "high",     "title": "Elasticsearch exposed",
     "detail": "Unauthenticated Elasticsearch allows data theft."},
    {"ports": [11211],  "severity": "high",     "title": "Memcached exposed",
     "detail": "Memcached can amplify DDoS and leak data."},
    {"ports": [2375],   "severity": "critical", "title": "Docker API exposed",
     "detail": "Unauthenticated Docker API = trivial host takeover."},
    {"ports": [5900, 5901], "severity": "high", "title": "VNC exposed",
     "detail": "VNC may use weak or no authentication."},
    {"ports": [2049],   "severity": "high",     "title": "NFS exposed",
     "detail": "NFS shares may be mounted without auth."},
    {"ports": [161],    "severity": "medium",   "title": "SNMP exposed",
     "detail": "SNMP v1/v2c uses community strings in cleartext."},
    {"ports": [389, 636],"severity": "medium",  "title": "LDAP exposed",
     "detail": "LDAP may allow anonymous binds."},
    {"ports": [1521],   "severity": "high",     "title": "Oracle DB exposed",
     "detail": "Oracle listener exposed on the network."},
    {"ports": [1433],   "severity": "high",     "title": "MSSQL exposed",
     "detail": "MSSQL exposed on the network."},
]
VULN_RULES: List[Dict[str, Any]] = [
    {"cve": "CVE-2014-6271", "severity": "critical",
     "pattern": r"vsftpd\s*2\.3\.4",
     "title": "vsftpd 2.3.4 backdoor",
     "detail": "vsftpd 2.3.4 ships a documented backdoor (port 6200). "
               "Rebuild from a trusted source and upgrade."},
    {"cve": "CVE-2011-2523", "severity": "critical",
     "pattern": r"ProFTPD\s*1\.3\.3c?",
     "title": "ProFTPD 1.3.3 backdoor",
     "detail": "ProFTPD 1.3.3c may contain a backdoor. Upgrade immediately."},
    {"cve": "CVE-2021-41773", "severity": "critical",
     "pattern": r"Apache[/ ]2\.4\.(49|50)(\D|$)",
     "title": "Apache path traversal / RCE",
     "detail": "Apache 2.4.49/2.4.50 are affected by path traversal & RCE "
               "(CVE-2021-41773 / CVE-2021-42013). Upgrade to 2.4.51+."},
    {"cve": "CVE-2014-0160", "severity": "critical",
     "pattern": r"OpenSSL[/ ]1\.0\.1([a-f]|[^0-9]|$)",
     "title": "OpenSSL Heartbleed",
     "detail": "OpenSSL 1.0.1–1.0.1f are vulnerable to Heartbleed memory "
               "disclosure (CVE-2014-0160). Upgrade and re-issue certs."},
    {"cve": "CVE-2023-48795", "severity": "medium",
     "pattern": r"OpenSSH[_\-](7\.[0-9]|8\.[0-9]|9\.[0-5])",
     "title": "OpenSSH Terrapin",
     "detail": "OpenSSH < 9.6 is affected by the Terrapin prefix-truncation "
               "attack (CVE-2023-48795). Upgrade or restrict CBC/ChaCha20."},
    {"cve": None, "severity": "high",
     "pattern": r"NT LM 0\.12",
     "title": "SMBv1 dialect negotiated",
     "detail": "SMBv1 is enabled — disable it to mitigate EternalBlue "
               "(MS17-010) and related risks."},
    {"cve": None, "severity": "medium",
     "pattern": r"Apache[/ ]2\.2\.\d+",
     "title": "Apache 2.2 end-of-life",
     "detail": "Apache 2.2 reached EOL in 2017 and no longer receives "
               "security fixes."},
    {"cve": None, "severity": "medium",
     "pattern": r"PHP[/ ]([57]\.\d|8\.0)\.\d+",
     "title": "PHP end-of-life version",
     "detail": "This PHP version no longer receives security updates; "
               "upgrade to a supported release."},
    {"cve": None, "severity": "high",
     "pattern": r"Microsoft-IIS[/ ]6\.0",
     "title": "IIS 6.0 end-of-life",
     "detail": "IIS 6.0 (Windows Server 2003) is EOL and affected by "
               "multiple RCEs (e.g. CVE-2017-7269 WebDAV)."},
    {"cve": None, "severity": "high",
     "pattern": r"\bTLS[/ ]?1\.0\b|\bSSL[/ ]?2\.0\b|\bSSL[/ ]?3\.0\b",
     "title": "Obsolete TLS/SSL protocol",
     "detail": "Server offers TLS 1.0 / SSL 2.0 / SSL 3.0 — disable them "
               "in favour of TLS 1.2+."},
    {"cve": None, "severity": "high",
     "pattern": r"Tomcat[/ ]([678]\.|9\.0\.[0-5])",
     "title": "Old Apache Tomcat",
     "detail": "This Tomcat version is past end-of-life; upgrade to a "
               "supported release."},
]
for _vr in VULN_RULES:
    try:
        _vr["regex"] = re.compile(_vr["pattern"], re.IGNORECASE)
    except re.error:
        _vr["regex"] = re.compile(re.escape(_vr["pattern"]), re.IGNORECASE)
_WEAK_CIPHER_RE = re.compile(
    r"(RC4|DES|3DES|NULL|EXPORT|anon|MD5)", re.IGNORECASE
)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
class ScanType(Enum):
    TCP_CONNECT = "TCP Connect"
    UDP = "UDP"
    PING = "Ping"
    ARP = "ARP"

class OutputFormat(Enum):
    TEXT = "Text"
    JSON = "JSON"
    CSV = "CSV"
    XML = "XML"
    MARKDOWN = "Markdown"
    HTML = "HTML"
    DOT = "DOT (Graphviz)"
    GRAPHML = "GraphML"

class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

@dataclass
class Finding:
    host: str
    port: Optional[int]
    title: str
    detail: str
    severity: Severity = Severity.INFO
    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host, "port": self.port,
            "title": self.title, "detail": self.detail,
            "severity": self.severity.value,
        }

@dataclass
class HostResult:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    os_guess: Optional[str] = None
    ttl: Optional[int] = None
    response_time: Optional[float] = None
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    banners: Dict[int, str] = field(default_factory=dict)
    versions: Dict[int, str] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d

@dataclass
class PortResult:
    host: str
    port: int
    state: str = "open"
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    protocol: str = "tcp"
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ScanStats:
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    hosts_scanned: int = 0
    hosts_up: int = 0
    ports_scanned: int = 0
    ports_open: int = 0
    banners_grabbed: int = 0
    errors: int = 0
    stopped: bool = False
    @property
    def duration(self) -> float:
        end = self.end_time if self.end_time is not None else time.time()
        return end - self.start_time
    def to_dict(self) -> Dict[str, Any]:
        return {
            "duration_seconds": round(self.duration, 2),
            "hosts_scanned": self.hosts_scanned,
            "hosts_up": self.hosts_up,
            "ports_scanned": self.ports_scanned,
            "ports_open": self.ports_open,
            "banners_grabbed": self.banners_grabbed,
            "errors": self.errors,
            "stopped": self.stopped,
        }

def _ensure_config_dir() -> None:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

def _setup_logging() -> None:
    _ensure_config_dir()
    logger = logging.getLogger("net_toolkit")
    if logger.handlers:
        return
    logger.setLevel(logging.INFO)
    try:
        handler = logging.FileHandler(AUDIT_FILE, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s"
        ))
        logger.addHandler(handler)
    except Exception:
        pass

def audit(action: str, **kwargs: Any) -> None:
    _setup_logging()
    logger = logging.getLogger("net_toolkit")
    try:
        logger.info(json.dumps({"action": action, **kwargs}, default=str))
    except Exception:
        pass

def save_crash_report(exc: BaseException, context: str = "") -> Path:
    _ensure_config_dir()
    try:
        with CRASH_FILE.open("a", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write(f"Time: {datetime.now().isoformat()}\n")
            f.write(f"Context: {context}\n")
            f.write(f"Exception: {exc!r}\n")
            f.write(traceback.format_exc())
            f.write("\n")
    except Exception:
        pass
    return CRASH_FILE

def is_windows() -> bool:
    return platform.system().lower().startswith("win")

def is_macos() -> bool:
    return platform.system().lower() == "darwin"

def is_admin() -> bool:
    try:
        if is_windows():
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False

def sanitize_log(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    text = _ANSI_RE.sub("", text)
    text = _CONTROL_RE.sub("", text)
    return text

def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    try:
        return any(addr in net for net in PRIVATE_NETWORKS)
    except TypeError:
        return False

def validate_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.strip())
        return isinstance(addr, ipaddress.IPv4Address)
    except (ValueError, AttributeError):
        return False

def validate_cidr(cidr: str) -> Optional[ipaddress.IPv4Network]:
    cidr = cidr.strip()
    if not cidr:
        return None
    try:
        if "/" not in cidr:
            return ipaddress.ip_network(f"{cidr}/32", strict=False)
        net = ipaddress.ip_network(cidr, strict=False)
        return net if isinstance(net, ipaddress.IPv4Network) else None
    except ValueError:
        return None

def network_host_count(net: ipaddress.IPv4Network) -> int:
    if net.prefixlen >= 31:
        return net.num_addresses
    return max(0, net.num_addresses - 2)

def network_first_host(net: ipaddress.IPv4Network) -> ipaddress.IPv4Address:
    if net.prefixlen >= 31:
        return net.network_address
    return net.network_address + 1

def network_last_host(net: ipaddress.IPv4Network) -> ipaddress.IPv4Address:
    if net.prefixlen >= 31:
        return net.broadcast_address
    return net.broadcast_address - 1

def parse_port_range(spec: str) -> Optional[List[int]]:
    spec = spec.strip()
    if not spec:
        return None
    ports: Set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            try:
                lo_s, hi_s = chunk.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                return None
            if not (0 < lo <= hi <= 65535):
                return None
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(chunk)
            except ValueError:
                return None
            if not (0 < p <= 65535):
                return None
            ports.add(p)
    return sorted(ports) if ports else None

def parse_targets(spec: str) -> List[str]:
    out: List[str] = []
    for line in spec.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for part in line.replace(",", " ").split():
            part = part.strip()
            if part:
                out.append(part)
    return out

def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"

def get_all_local_ips() -> List[str]:
    ips: Set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except socket.gaierror:
        pass
    try:
        ips.add(get_local_ip())
    except Exception:
        pass
    return sorted(ips)

def reverse_dns(ip: str, timeout: float = 2.0) -> Optional[str]:
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None

def format_mac(mac: str) -> str:
    clean = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(clean) != 12:
        return mac
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2)).upper()

_OUI_DB: Dict[str, str] = {
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:50:56": "VMware",
    "00:0C:29": "VMware", "00:05:69": "VMware", "00:1C:42": "Parallels",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "00:15:5D": "Microsoft Hyper-V", "00:16:3E": "Xen",
    "00:1B:63": "Apple", "00:1E:C2": "Apple", "00:1F:F3": "Apple",
    "00:21:E9": "Apple", "00:22:41": "Apple", "00:23:12": "Apple",
    "00:25:00": "Apple", "00:26:08": "Apple", "00:26:BB": "Apple",
    "3C:07:54": "Apple", "40:6C:8F": "Apple", "58:55:CA": "Apple",
    "7C:D1:C3": "Apple", "8C:85:90": "Apple", "98:01:A7": "Apple",
    "B8:17:C2": "Apple", "BC:52:B7": "Apple", "D0:23:DB": "Apple",
    "F0:18:98": "Apple", "FC:C7:34": "Apple",
    "00:1A:11": "Google", "3C:5A:B4": "Google", "54:60:09": "Google",
    "F4:F5:D8": "Google", "F4:F5:E8": "Google",
    "00:1B:2F": "NETGEAR", "00:14:6C": "NETGEAR", "00:18:4D": "NETGEAR",
    "00:22:3F": "NETGEAR", "00:24:B2": "NETGEAR", "20:4E:7F": "NETGEAR",
    "00:1E:58": "D-Link", "00:22:B0": "D-Link", "00:24:01": "D-Link",
    "00:26:5A": "D-Link", "1C:7E:E5": "D-Link", "28:10:7B": "D-Link",
    "00:18:39": "Cisco-Linksys", "00:1A:70": "Cisco-Linksys",
    "00:1C:10": "Cisco-Linksys", "00:1D:7E": "Cisco-Linksys",
    "00:1B:FC": "ASUSTek", "00:1E:8C": "ASUSTek", "00:22:15": "ASUSTek",
    "00:23:54": "ASUSTek", "00:24:8C": "ASUSTek", "00:26:18": "ASUSTek",
    "10:BF:48": "ASUSTek", "14:DA:E9": "ASUSTek", "1C:87:2C": "ASUSTek",
    "2C:56:DC": "ASUSTek", "30:5A:3A": "ASUSTek", "38:2C:4A": "ASUSTek",
    "00:1E:C9": "Intel", "00:21:6A": "Intel", "00:22:FB": "Intel",
    "00:24:D7": "Intel", "00:27:10": "Intel", "34:13:E8": "Intel",
    "3C:97:0E": "Intel", "44:85:00": "Intel", "48:51:B7": "Intel",
    "4C:34:88": "Intel", "50:76:AF": "Intel", "54:27:1E": "Intel",
    "5C:51:4F": "Intel", "60:36:DD": "Intel", "64:80:99": "Intel",
    "00:1A:2B": "Ayecom", "AC:DE:48": "Private",
    "00:0F:B5": "NETGEAR",
    "00:1F:33": "NETGEAR", "00:26:F2": "NETGEAR",
    "00:0C:41": "Linksys", "00:0E:08": "Linksys", "00:12:17": "Linksys",
    "00:13:10": "Linksys", "00:14:BF": "Linksys", "00:16:B6": "Linksys",
    "00:18:F8": "Linksys",
}

def get_vendor_from_mac(mac: str) -> Optional[str]:
    if not mac or len(mac) < 8:
        return None
    oui = mac[:8].upper()
    return _OUI_DB.get(oui)

def guess_device_type(
    hostname: Optional[str],
    mac: Optional[str],
    open_ports: List[int],
) -> str:
    hn = (hostname or "").lower()
    vendor = get_vendor_from_mac(mac) if mac else None
    hn_rules = [
        (("router", "gateway", "gw", "firewall", "pfsense", "opnsense"), "Router/Firewall"),
        (("switch", "sw-", "-sw"), "Switch"),
        (("printer", "print", "hp-", "canon", "epson", "brother"), "Printer"),
        (("camera", "cam", "ipcam", "nvr", "dvr"), "IP Camera"),
        (("nas", "storage", "synology", "qnap", "freenas", "truenas"), "NAS"),
        (("phone", "sip", "voip", "asterisk"), "VoIP Phone"),
        (("tv", "roku", "chromecast", "firestick", "appletv"), "Smart TV"),
        (("server", "srv", "dc-", "domain", "ad-"), "Server"),
        (("laptop", "desktop", "pc-", "workstation", "ws-"), "Workstation"),
        (("android", "iphone", "ipad", "mobile", "pixel", "galaxy"), "Mobile"),
        (("iot", "esp", "arduino", "raspberry", "rpi", "tasmota"), "IoT Device"),
        (("k8s", "kubernetes", "kube"), "K8s Node"),
    ]
    for keys, label in hn_rules:
        if any(k in hn for k in keys):
            return label
    if vendor:
        m = {
            "Apple": "Apple Device", "Google": "Google Device",
            "VMware": "Virtual Machine", "VirtualBox": "Virtual Machine",
            "QEMU/KVM": "Virtual Machine", "Microsoft Hyper-V": "Virtual Machine",
            "Xen": "Virtual Machine", "Parallels": "Virtual Machine",
            "Cisco": "Network Device", "NETGEAR": "Network Device",
            "D-Link": "Network Device", "Cisco-Linksys": "Network Device",
            "ASUSTek": "Network Device", "Intel": "PC/Laptop",
        }
        if vendor in m:
            return m[vendor]
    if 3389 in open_ports:
        return "Windows Server/PC"
    if 22 in open_ports and (80 in open_ports or 443 in open_ports):
        return "Linux Server"
    if 445 in open_ports:
        return "Windows Device"
    if 631 in open_ports or 515 in open_ports:
        return "Printer"
    if 554 in open_ports or 8554 in open_ports:
        return "IP Camera"
    if any(p in open_ports for p in (3306, 5432, 27017, 1433, 1521)):
        return "Database Server"
    if any(p in open_ports for p in (80, 443, 8080, 8443, 8000)):
        return "Web Server"
    if 53 in open_ports:
        return "DNS Server"
    return "Unknown"

def safe_font() -> Tuple[str, int]:
    candidates: List[str] = []
    if is_windows():
        candidates = ["Consolas", "Cascadia Mono", "Courier New"]
    elif is_macos():
        candidates = ["Menlo", "Monaco", "Courier"]
    else:
        candidates = ["DejaVu Sans Mono", "Liberation Mono", "Monospace", "Courier"]
    if _HAVE_TK:
        try:
            import tkinter.font as tkfont
            families = set(tkfont.families())
            for c in candidates:
                if c in families:
                    return (c, 10)
        except Exception:
            pass
    return ("Courier", 10)

def aggregate_cidrs(ips: Sequence[str]) -> List[str]:
    try:
        nets = [
            ipaddress.ip_network(f"{ip}/32", strict=False)
            for ip in ips if validate_ip(ip)
        ]
        if not nets:
            return list(ips)
        return [str(n) for n in ipaddress.collapse_addresses(nets)]
    except Exception:
        return list(ips)

def load_json(path: Path, default: Any = None) -> Any:
    _ensure_config_dir()
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path: Path, data: Any) -> None:
    _ensure_config_dir()
    try:
        with path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception:
        pass

def load_history() -> List[Dict[str, Any]]:
    return load_json(HISTORY_FILE, []) or []

def append_history(entry: Dict[str, Any], limit: int = 500) -> None:
    h = load_history()
    h.append(entry)
    if len(h) > limit:
        h = h[-limit:]
    save_json(HISTORY_FILE, h)

def load_config() -> Dict[str, Any]:
    return load_json(CONFIG_FILE, {}) or {}

def save_config(cfg: Dict[str, Any]) -> None:
    save_json(CONFIG_FILE, cfg)

class RateLimiter:
    def __init__(self, rate_pps: float = 0.0) -> None:
        self.rate = max(0.0, float(rate_pps))
        self._lock = threading.Lock()
        self._next = time.monotonic()

    def wait(self, stop_event: Optional[threading.Event] = None) -> bool:
        if self.rate <= 0:
            return stop_event is None or not stop_event.is_set()
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + 1.0 / self.rate
            delay = slot - now
        if delay > 0:
            if stop_event is not None:
                return not stop_event.wait(delay)
            time.sleep(delay)
        return True

def expand_target_spec(spec: str, limit: int = MAX_HOSTS_PER_SWEEP
                       ) -> Optional[List[str]]:
    out: Set[str] = set()
    for token in parse_targets(spec):
        if "/" in token:
            net = validate_cidr(token)
            if net is None:
                continue
            if network_host_count(net) > limit:
                raise ValueError(
                    f"Target range too large "
                    f"({net.num_addresses} addresses > {limit})")
            hosts = list(net.hosts()) or [net.network_address]
            out.update(str(h) for h in hosts)
        elif "-" in token:
            left, _, right = token.partition("-")
            left, right = left.strip(), right.strip()
            lo_ip = hi_ip = None
            if validate_ip(left):
                lo_ip = int(ipaddress.IPv4Address(left))
                if validate_ip(right):
                    hi_ip = int(ipaddress.IPv4Address(right))
                elif right.isdigit() and len(left.split(".")) == 4:
                    try:
                        hi_ip = int(ipaddress.IPv4Address(
                            ".".join(left.split(".")[:3] + [str(int(right))])))
                    except ValueError:
                        hi_ip = None
            if lo_ip is None or hi_ip is None:
                continue
            if lo_ip > hi_ip:
                lo_ip, hi_ip = hi_ip, lo_ip
            if hi_ip - lo_ip + 1 > limit:
                raise ValueError(
                    f"Target range too large ({hi_ip - lo_ip + 1} > {limit})")
            out.update(str(ipaddress.IPv4Address(i))
                       for i in range(lo_ip, hi_ip + 1))
        elif validate_ip(token):
            out.add(token)
    if not out:
        return None
    return sorted(out, key=lambda ip: int(ipaddress.IPv4Address(ip)))

def version_tuple(version: str) -> Tuple[int, ...]:
    parts = re.findall(r"\d+", version or "")
    return tuple(int(p) for p in parts[:4]) or (0,)

def version_lt(version: str, target: Tuple[int, ...]) -> bool:
    vt = version_tuple(version)
    width = max(len(vt), len(target))
    vt = vt + (0,) * (width - len(vt))
    tg = target + (0,) * (width - len(target))
    return vt < tg

def rdap_lookup(target: str) -> Optional[str]:
    if validate_ip(target):
        url = f"https://rdap.org/ip/{target}"
    else:
        url = f"https://rdap.org/domain/{target.strip()}"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": f"NetworkToolkit/{APP_VERSION}",
            "Accept": "application/rdap+json, application/json"})
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except Exception:
        return None
    try:
        lines: List[str] = [f"RDAP record for {target}", "-" * 50]
        for key in ("handle", "name", "ldhName", "status", "port43"):
            val = data.get(key)
            if val:
                lines.append(f"{key}: {val}")
        for evt in data.get("events", []) or []:
            if isinstance(evt, dict):
                lines.append(f"{evt.get('eventAction')}: {evt.get('eventDate')}")
        for ent in data.get("entities", []) or []:
            if not isinstance(ent, dict):
                continue
            roles = ",".join(ent.get("roles", []) or [])
            org = ""
            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if (isinstance(item, list) and len(item) >= 4
                            and item[0] == "fn"):
                        org = str(item[3])
                        break
            if roles or org:
                lines.append(f"entity [{roles}]: {org or ent.get('handle', '')}")
        if "startAddress" in data:
            lines.append(f"range: {data.get('startAddress')}-"
                         f"{data.get('endAddress')}")
            names = [n.get("ldhName") for n in (data.get("names") or [])
                     if isinstance(n, dict) and n.get("ldhName")]
            if names:
                lines.append(f"names: {', '.join(str(n) for n in names)}")
        return "\n".join(lines) if len(lines) > 2 else None
    except Exception:
        return None

def _severity_or_info(value: Any) -> Severity:
    try:
        return Severity(str(value))
    except ValueError:
        return Severity.INFO

def _coerce_port(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

def _coerce_float(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

def _coerce_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

def build_export_data(discovered: Sequence[HostResult],
                      scan_results: Sequence[PortResult],
                      findings: Sequence[Finding],
                      stats: Optional[ScanStats] = None) -> Dict[str, Any]:
    s = stats if stats is not None else ScanStats()
    return {
        "scan_time": datetime.now().isoformat(),
        "app_version": APP_VERSION,
        "report_id": "".join(
            random.choices(string.ascii_lowercase + string.digits, k=10)),
        "hosts": [h.to_dict() for h in discovered],
        "ports": [p.to_dict() for p in scan_results],
        "findings": [f.to_dict() for f in findings],
        "stats": s.to_dict() if hasattr(s, "to_dict") else dict(s),
    }

def save_session(path: Union[str, Path],
                 discovered: Sequence[HostResult],
                 scan_results: Sequence[PortResult],
                 findings: Sequence[Finding]) -> str:
    payload = {
        "app": APP_NAME,
        "version": APP_VERSION,
        "saved_at": datetime.now().isoformat(),
        "hosts": [h.to_dict() for h in discovered],
        "ports": [p.to_dict() for p in scan_results],
        "findings": [f.to_dict() for f in findings],
    }
    checksum = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump({"checksum": checksum, "payload": payload},
                  f, indent=2, default=str)
    return checksum

def load_session(path: Union[str, Path]
                 ) -> Optional[Tuple[List[HostResult], List[PortResult],
                                     List[Finding]]]:
    try:
        with Path(path).open("r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception:
        return None
    payload = doc.get("payload")
    if not isinstance(payload, dict):
        return None
    expected = doc.get("checksum", "")
    actual = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    if expected and expected != actual:
        return None
    hosts: List[HostResult] = []
    for h in payload.get("hosts", []) or []:
        if not isinstance(h, dict) or not h.get("ip"):
            continue
        h_findings = [Finding(
            host=str(f.get("host") or h["ip"]), port=_coerce_port(f.get("port")),
            title=str(f.get("title", "")), detail=str(f.get("detail", "")),
            severity=_severity_or_info(f.get("severity")))
            for f in (h.get("findings") or []) if isinstance(f, dict)]
        allowed = ("ip", "mac", "hostname", "vendor", "device_type",
                   "os_guess", "ttl", "response_time", "open_ports",
                   "services", "banners", "versions", "first_seen", "last_seen")
        kwargs = {k: h.get(k) for k in allowed if k in h}
        kwargs["ip"] = str(kwargs.get("ip") or "")
        for key in ("mac", "hostname", "vendor", "device_type", "os_guess",
                    "first_seen", "last_seen"):
            if kwargs.get(key) is not None:
                kwargs[key] = str(kwargs[key])
        kwargs["ttl"] = _coerce_int(kwargs.get("ttl"))
        kwargs["response_time"] = _coerce_float(kwargs.get("response_time"))
        kwargs["open_ports"] = [p for p in
                                (_coerce_port(x) for x in
                                 (kwargs.get("open_ports") or []))
                                if p is not None]
        for key in ("services", "banners", "versions"):
            mapping: Dict[int, str] = {}
            for k, v in (kwargs.get(key) or {}).items():
                port = _coerce_port(k)
                if port is not None:
                    mapping[port] = str(v)
            kwargs[key] = mapping
        hosts.append(HostResult(findings=h_findings, **kwargs))
    ports: List[PortResult] = []
    for p in payload.get("ports", []) or []:
        if not isinstance(p, dict) or "port" not in p:
            continue
        allowed = ("host", "port", "state", "service", "version",
                   "banner", "protocol")
        entry = {k: p.get(k) for k in allowed if k in p}
        port = _coerce_port(entry.get("port"))
        if port is None:
            continue
        entry["port"] = port
        for key in ("host", "state", "service", "version", "banner",
                    "protocol"):
            if entry.get(key) is not None:
                entry[key] = str(entry[key])
        ports.append(PortResult(**entry))
    findings = [Finding(
        host=str(f.get("host", "")), port=_coerce_port(f.get("port")),
        title=str(f.get("title", "")), detail=str(f.get("detail", "")),
        severity=_severity_or_info(f.get("severity")))
        for f in (payload.get("findings") or []) if isinstance(f, dict)]
    return hosts, ports, findings

class CancellableExecutor:
    def __init__(self, max_workers: int):
        self._executor = ThreadPoolExecutor(max_workers=max(1, max_workers))
        self._cancelled = threading.Event()
    def cancel(self) -> None:
        self._cancelled.set()
    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()
    def submit(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Future:
        def wrapped() -> Any:
            if self._cancelled.is_set():
                return None
            return fn(*args, **kwargs)
        return self._executor.submit(wrapped)
    def map_unordered(self, fn: Callable[[Any], Any], items: Iterable[Any]) -> Iterable[Any]:
        futures = [self.submit(fn, item) for item in items]
        for fut in as_completed(futures):
            if self._cancelled.is_set():
                break
            try:
                yield fut.result()
            except Exception:
                continue
    def shutdown(self, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=True)

class ARPScanner:
    @staticmethod
    def scan(
        network: ipaddress.IPv4Network,
        timeout: float = 2.0,
        log: Optional[Callable[[str], None]] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> Dict[str, str]:
        if is_windows():
            return ARPScanner._windows_arp_scan(network, timeout, log, stop_event)
        return ARPScanner._unix_arp_scan(network, timeout, log, stop_event)
    @staticmethod
    def _unix_arp_scan(
        network: ipaddress.IPv4Network,
        timeout: float,
        log: Optional[Callable[[str], None]] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> Dict[str, str]:
        results: Dict[str, str] = {}
        try:
            out = subprocess.check_output(
                ["arp-scan", "--localnet", "--quiet"],
                text=True, stderr=subprocess.DEVNULL, timeout=60,
            )
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and validate_ip(parts[0]):
                    ip = parts[0]
                    mac = parts[1].lower()
                    if ipaddress.ip_address(ip) in network:
                        results[ip] = mac
            if results:
                return results
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        try:
            hosts = list(itertools.islice(network.hosts(), 256))
            for host in hosts:
                if stop_event is not None and stop_event.is_set():
                    break
                ip = str(host)
                try:
                    out = subprocess.check_output(
                        ["arping", "-c", "1", "-w", str(int(timeout)), ip],
                        text=True, stderr=subprocess.DEVNULL,
                        timeout=timeout + 1,
                    )
                    m = re.search(r"\[([0-9a-fA-F:]{17})\]", out)
                    if m:
                        results[ip] = m.group(1).lower()
                except (FileNotFoundError, subprocess.CalledProcessError,
                        subprocess.TimeoutExpired):
                    continue
        except Exception:
            pass
        return results

    @staticmethod
    def _windows_arp_scan(
        network: ipaddress.IPv4Network,
        timeout: float,
        log: Optional[Callable[[str], None]] = None,
        stop_event: Optional[threading.Event] = None,
    ) -> Dict[str, str]:
        results: Dict[str, str] = {}
        hosts = list(itertools.islice(network.hosts(), 1024))
        def ping_one(ip: str) -> None:
            if stop_event is not None and stop_event.is_set():
                return
            try:
                subprocess.run(
                    ["ping", "-n", "1", "-w", "200", ip],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=1,
                )
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=128) as ex:
            list(ex.map(ping_one, (str(h) for h in hosts)))
        try:
            out = subprocess.check_output(
                ["arp", "-a"], text=True, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for line in out.splitlines():
                m = re.match(
                    r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{11,17})\s+",
                    line,
                )
                if m:
                    ip = m.group(1)
                    mac = m.group(2).lower().replace("-", ":")
                    try:
                        if ipaddress.ip_address(ip) in network:
                            results[ip] = mac
                    except ValueError:
                        continue
        except Exception:
            pass
        return results

class PacketBuilder:
    @staticmethod
    def checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\x00"
        s = sum(struct.unpack(f"!{len(data) // 2}H", data))
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF
    @staticmethod
    def build_ip_header(src_ip: str, dst_ip: str, protocol: int,
                        payload_len: int) -> bytes:
        version_ihl = (4 << 4) | 5
        total_len = 20 + payload_len
        ident = random.randint(0, 65535)
        flags_frag = 0x4000
        ttl = 64
        checksum = 0
        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)
        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl, 0, total_len, ident, flags_frag,
            ttl, protocol, checksum, src, dst,
        )
        checksum = PacketBuilder.checksum(header)
        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl, 0, total_len, ident, flags_frag,
            ttl, protocol, checksum, src, dst,
        )
        return header

    @staticmethod
    def build_tcp_syn(src_ip: str, dst_ip: str, src_port: int,
                      dst_port: int) -> bytes:
        seq = random.randint(0, 0xFFFFFFFF)
        data_offset = (5 << 4)
        flags = 0x02
        window = 65535
        urgent = 0
        pseudo = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
            0, socket.IPPROTO_TCP, 20,
        )
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            src_port, dst_port, seq, 0,
            data_offset, flags, window, 0, urgent,
        )
        checksum = PacketBuilder.checksum(pseudo + tcp_header)
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            src_port, dst_port, seq, 0,
            data_offset, flags, window, checksum, urgent,
        )
        return PacketBuilder.build_ip_header(src_ip, dst_ip, socket.IPPROTO_TCP, 20) + tcp_header

class WakeOnLan:
    @staticmethod
    def send(mac: str, broadcast: str = "255.255.255.255", port: int = 9) -> bool:
        clean = re.sub(r"[^0-9a-fA-F]", "", mac)
        if len(clean) != 12:
            return False
        try:
            mac_bytes = bytes.fromhex(clean)
        except ValueError:
            return False
        payload = b"\xff" * 6 + mac_bytes * 16
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.sendto(payload, (broadcast, port))
            return True
        except OSError:
            return False

class HTTPProber:
    @staticmethod
    def probe(host: str, port: int = 80, use_tls: bool = False,
              timeout: float = DEFAULT_HTTP_TIMEOUT,
              path: str = "/") -> Optional[Dict[str, Any]]:
        try:
            ctx = None
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                sock: Any = raw
                if use_tls:
                    sock = ctx.wrap_socket(raw, server_hostname=host)  # type: ignore
                with sock:
                    sock.settimeout(timeout)
                    req = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"User-Agent: NetworkToolkit/{APP_VERSION}\r\n"
                        f"Connection: close\r\n\r\n"
                    ).encode()
                    sock.sendall(req)
                    chunks: List[bytes] = []
                    total = 0
                    while total < 16384:
                        try:
                            data = sock.recv(4096)
                        except socket.timeout:
                            break
                        if not data:
                            break
                        chunks.append(data)
                        total += len(data)
            body = b"".join(chunks)
            text = body.decode("utf-8", errors="replace")
            head, _, rest = text.partition("\r\n\r\n")
            if not rest:
                head, _, rest = text.partition("\n\n")
            headers: Dict[str, str] = {}
            first_line = ""
            for i, line in enumerate(head.splitlines()):
                if i == 0:
                    first_line = line.strip()
                    continue
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()
            return {
                "status_line": first_line,
                "headers": headers,
                "body_preview": rest[:2048],
                "path": path,
            }
        except Exception:
            return None

    @staticmethod
    def audit_security_headers(probe: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        headers = probe.get("headers", {})
        checks = [
            ("strict-transport-security", "medium", "Missing HSTS",
             "Consider adding Strict-Transport-Security header."),
            ("content-security-policy", "low", "Missing CSP",
             "Content-Security-Policy mitigates XSS."),
            ("x-frame-options", "low", "Missing X-Frame-Options",
             "X-Frame-Options mitigates clickjacking."),
            ("x-content-type-options", "low", "Missing X-Content-Type-Options",
             "Set X-Content-Type-Options: nosniff."),
            ("referrer-policy", "info", "Missing Referrer-Policy",
             "Referrer-Policy limits referrer leakage."),
        ]
        for header, sev, title, detail in checks:
            if header not in headers:
                try:
                    severity = Severity(sev)
                except ValueError:
                    severity = Severity.INFO
                findings.append(Finding(
                    host="", port=None, title=title, detail=detail,
                    severity=severity,
                ))
        server = headers.get("server", "")
        if server and re.search(r"/[\d.]+", server):
            findings.append(Finding(
                host="", port=None, title="Server version disclosed",
                detail=f"Server header leaks version: {server}",
                severity=Severity.LOW,
            ))
        return findings

def tls_inspect(host: str, port: int = 443,
                timeout: float = DEFAULT_BANNER_TIMEOUT,
                servername: Optional[str] = None) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "host": host, "port": port, "tls_version": None, "cipher": None,
        "cipher_bits": None, "weak_cipher": False, "weak_protocol": False,
        "sni": servername or host, "subject_cn": None, "issuer": None,
        "san": [], "serial": None, "not_before": None, "not_after": None,
        "days_left": None, "expired": False, "self_signed": False,
        "fingerprint_sha256": None, "error": None,
    }
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=servername or host) as tls:
                info["tls_version"] = tls.version()
                cipher = tls.cipher()
                if cipher:
                    info["cipher"] = cipher[0]
                    info["cipher_bits"] = cipher[1] if len(cipher) > 1 else None
                    info["weak_cipher"] = bool(
                        _WEAK_CIPHER_RE.search(cipher[0]))
                info["weak_protocol"] = bool(re.search(
                    r"TLS[/ ]?1\.0|TLS[/ ]?1\.1|SSL[/ ]?2|SSL[/ ]?3",
                    info["tls_version"] or "", re.IGNORECASE))
                der = tls.getpeercert(binary_form=True)
                if der:
                    info["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
                    if _HAVE_CRYPTOGRAPHY:
                        try:
                            cert = _x509.load_der_x509_certificate(der)
                            cns = cert.subject.get_attributes_for_oid(
                                _x509.NameOID.COMMON_NAME)
                            info["subject_cn"] = cns[0].value if cns else None
                            try:
                                info["issuer"] = cert.issuer.rfc4514_string()
                                info["self_signed"] = (
                                    info["issuer"] ==
                                    cert.subject.rfc4514_string())
                            except Exception:
                                info["issuer"] = str(cert.issuer)
                            try:
                                ext = cert.extensions.get_extension_for_class(
                                    _x509.SubjectAlternativeName)
                                info["san"] = list(
                                    ext.value.get_values_for_type(
                                        _x509.DNSName))
                            except Exception:
                                info["san"] = []
                            info["serial"] = format(cert.serial_number, "x")
                            nb = getattr(cert, "not_valid_before_utc", None)
                            if nb is None:
                                nb = cert.not_valid_before
                            na = getattr(cert, "not_valid_after_utc", None)
                            if na is None:
                                na = cert.not_valid_after

                            def _naive(dt: "datetime") -> "datetime":
                                return (dt.replace(tzinfo=None)
                                        if dt.tzinfo is not None else dt)

                            tz = na.tzinfo
                            now = (_naive(datetime.now(tz)) if tz
                                   else _naive(datetime.now()))
                            info["not_before"] = _naive(nb).isoformat()
                            info["not_after"] = _naive(na).isoformat()
                            info["days_left"] = (_naive(na) - now).days
                            info["expired"] = _naive(na) <= now
                        except Exception:
                            pass
    except Exception as exc:
        info["error"] = str(exc)
    return info

def tls_assess(info: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    if info.get("error"):
        return findings
    host = str(info.get("host") or "")
    port = info.get("port") if isinstance(info.get("port"), int) else None
    def add(title: str, detail: str, sev: Severity) -> None:
        findings.append(Finding(host=host, port=port, title=title,
                                detail=detail, severity=sev))
    if info.get("weak_protocol"):
        add("Obsolete TLS protocol",
            f"Server negotiated {info.get('tls_version')} — require TLS 1.2+.",
            Severity.HIGH)
    if info.get("weak_cipher"):
        add("Weak TLS cipher",
            f"Cipher {info.get('cipher')} is weak or legacy.",
            Severity.HIGH)
    if info.get("expired"):
        add("TLS certificate expired",
            f"Certificate expired on {info.get('not_after')}.",
            Severity.HIGH)
    elif isinstance(info.get("days_left"), int) and info["days_left"] < 30:
        add("TLS certificate expiring soon",
            f"Certificate expires in {info['days_left']} day(s) "
            f"({info.get('not_after')}).", Severity.MEDIUM)
    if info.get("self_signed"):
        add("Self-signed TLS certificate",
            "Certificate is self-signed — clients will not trust it.",
            Severity.MEDIUM)
    if not info.get("san"):
        add("Certificate missing SAN",
            "No Subject Alternative Name — modern clients may reject it.",
            Severity.LOW)
    return findings

def _dns_query_bytes(name: str, qtype: int = 1,
                     txn_id: Optional[int] = None) -> bytes:
    tid = random.randint(0, 0xFFFF) if txn_id is None else txn_id
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in [l for l in name.strip(".").split(".") if l]:
        raw = label.encode("ascii", errors="ignore")[:63]
        q += bytes([len(raw)]) + raw
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    return header + q

def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    return bytes([0x80 | len(out)]) + bytes(out)

def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value

def snmp_v1_get(community: str = "public",
                oid: Sequence[int] = (1, 3, 6, 1, 2, 1, 1, 1, 0)) -> bytes:
    oid_bytes = bytearray([0x2B])
    for sub in list(oid)[2:]:
        if sub < 0x80:
            oid_bytes.append(sub)
        else:
            chunk = [sub & 0x7F]
            sub >>= 7
            while sub:
                chunk.append(0x80 | (sub & 0x7F))
                sub >>= 7
            oid_bytes.extend(reversed(chunk))
    varbind = _ber_tlv(0x30, _ber_tlv(0x06, bytes(oid_bytes)) +
                       _ber_tlv(0x05, b""))
    request_id = _ber_tlv(
        0x02, struct.pack("!i", random.randint(0, 0x7FFFFFFF)))
    error_status = _ber_tlv(0x02, struct.pack("!H", 0))
    error_index = _ber_tlv(0x02, struct.pack("!H", 0))
    pdu = _ber_tlv(0xA0, request_id + error_status + error_index +
                   _ber_tlv(0x30, varbind))
    return _ber_tlv(0x30, _ber_tlv(0x02, b"\x00") +
                    _ber_tlv(0x04, community.encode("ascii", "replace")) +
                    pdu)

def udp_probe_payload(port: int, host: str = "") -> bytes:
    if port == 53:
        if validate_ip(host):
            octets = host.strip().split(".")
            if len(octets) == 4 and all(o.isdigit() for o in octets):
                return _dns_query_bytes(
                    ".".join(reversed(octets)) + ".in-addr.arpa", 12)
            return _dns_query_bytes("localhost", 1)
        return _dns_query_bytes(host or "example.com", 1)
    if port == 5353:
        return _dns_query_bytes("_services._dns-sd._udp.local", 12)
    if port == 123:
        return b"\x1b" + b"\x00" * 47
    if port == 161:
        return snmp_v1_get()
    if port == 520:
        return b"\x01\x01\x00\x00" + b"\x00" * 20
    if port == 1900:
        return (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                b'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
    if port == 19:
        return b"*HELLO*\r\n"
    if port == 69:
        return b"\x00probe\x00octet\x00"
    if port == 11211:
        return b"stats\r\n"
    if port == 6379:
        return b"PING\r\n"
    return b"\x00"

class NetworkScanner:
    COMMON_BANNER_PORTS: Sequence[int] = (
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080,
        8443, 27017,
    )
    TOP_100_PORTS: List[int] = [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106,
        110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427,
        443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
        631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
        1080, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
        2121, 2222, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000,
        5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
        5900, 6000, 6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080,
        8081, 8443, 8888, 9100, 9200, 9999, 10000, 27017, 32768,
    ]
    TOP_1000_PORTS: List[int] = list(range(1, 1025))
    SLOW_PORTS: Set[int] = {25, 110, 143, 465, 587, 993, 995}
    TLS_PORTS: Set[int] = {443, 8443, 993, 995, 465, 636, 990, 2376, 6443}
    HTTP_PORTS: Set[int] = {80, 8000, 8008, 8080, 8081, 8888, 3000, 5000, 9090}
    def __init__(self) -> None:
        self._stats = ScanStats()
        self._stats_lock = threading.Lock()
    @property
    def stats(self) -> ScanStats:
        return self._stats
    def reset_stats(self) -> None:
        with self._stats_lock:
            self._stats = ScanStats()
    def _bump(self, **kwargs: int) -> None:
        with self._stats_lock:
            for k, v in kwargs.items():
                setattr(self._stats, k, getattr(self._stats, k) + v)
    def ping_host(self, ip: str, timeout: float = DEFAULT_PING_TIMEOUT
                  ) -> Tuple[bool, Optional[float], Optional[int]]:
        system = platform.system().lower()
        start = time.monotonic()
        try:
            if system.startswith("win"):
                cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
            elif system == "darwin":
                cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
            creationflags = subprocess.CREATE_NO_WINDOW if is_windows() else 0
            with subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=creationflags, text=True,
            ) as proc:
                try:
                    stdout, _ = proc.communicate(timeout=timeout + 1.0)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    return False, None, None
                elapsed = (time.monotonic() - start) * 1000
                if proc.returncode == 0:
                    ttl = None
                    m = re.search(r"TTL[=:](\d+)", stdout or "", re.IGNORECASE)
                    if m:
                        ttl = int(m.group(1))
                    return True, round(elapsed, 2), ttl
                return False, None, None
        except (FileNotFoundError, OSError, Exception):
            return False, None, None
    def tcp_ping(self, ip: str, port: int = 80, timeout: float = 1.0) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, port)) == 0
        except OSError:
            return False

    def udp_probe(self, ip: str, port: int, timeout: float = 1.0) -> bool:
        payload = udp_probe_payload(port, ip)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                try:
                    s.sendto(payload, (ip, port))
                    ready, _, _ = select.select([s], [], [], timeout)
                    if not ready:
                        return False
                    data, _ = s.recvfrom(2048)
                    return bool(data)
                except (socket.timeout, ConnectionRefusedError,
                        ConnectionResetError):
                    return False
                except OSError:
                    return False
        except OSError:
            return False

    def arp_table(self) -> Dict[str, str]:
        table: Dict[str, str] = {}
        try:
            if is_windows():
                out = subprocess.check_output(
                    ["arp", "-a"], stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW, text=True,
                )
                for line in out.splitlines():
                    m = re.match(
                        r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{11,17})\s+",
                        line,
                    )
                    if m:
                        table[m.group(1)] = m.group(2).lower().replace("-", ":")
            elif is_macos():
                out = subprocess.check_output(
                    ["arp", "-a"], text=True, stderr=subprocess.DEVNULL
                )
                for line in out.splitlines():
                    m = re.search(
                        r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line
                    )
                    if m:
                        table[m.group(1)] = m.group(2).lower()
            else:
                try:
                    out = subprocess.check_output(
                        ["ip", "neigh"], text=True, stderr=subprocess.DEVNULL
                    )
                    for line in out.splitlines():
                        parts = line.split()
                        if len(parts) >= 5 and parts[1] == "dev":
                            ip = parts[0]
                            if "lladdr" in parts:
                                mac = parts[parts.index("lladdr") + 1]
                                table[ip] = mac.lower()
                except (FileNotFoundError, subprocess.CalledProcessError):
                    out = subprocess.check_output(
                        ["arp", "-n"], text=True, stderr=subprocess.DEVNULL
                    )
                    for line in out.splitlines():
                        m = re.match(
                            r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F:]{17})",
                            line,
                        )
                        if m:
                            table[m.group(1)] = m.group(2).lower()
        except Exception:
            return {}
        return table

    def discover_hosts(
        self,
        cidr: str,
        log: Callable[[str], None],
        stop_event: Optional[threading.Event] = None,
        ping_timeout: float = DEFAULT_PING_TIMEOUT,
        max_workers: int = DEFAULT_THREADS,
        use_arp: bool = True,
        use_tcp_ping: bool = True,
        tcp_ping_ports: Sequence[int] = (80, 443, 22, 445, 3389),
        resolve_hostnames: bool = True,
        stealth_delay: float = 0.0,
        rate: float = DEFAULT_RATE_PPS,
    ) -> List[HostResult]:
        net = validate_cidr(cidr)
        if net is None:
            raise ValueError(f"Invalid or non-IPv4 network: {cidr!r}")
        count = network_host_count(net)
        if count > MAX_HOSTS_PER_SWEEP:
            raise ValueError(
                f"Network too large ({net.num_addresses} addresses). "
                f"Limit is {MAX_HOSTS_PER_SWEEP}."
            )
        hosts = list(net.hosts())
        if not hosts and net.prefixlen == 32:
            hosts = [net.network_address]
        if not hosts:
            log("[!] No usable hosts in range.")
            return []
        self.reset_stats()
        with self._stats_lock:
            self._stats.hosts_scanned = len(hosts)
        log(f"[*] Ping sweep of {net} — {len(hosts)} addresses …")
        results: Dict[str, HostResult] = {}
        lock = threading.Lock()
        stop = stop_event if stop_event is not None else threading.Event()
        limiter = RateLimiter(rate)
        def probe(ip: str) -> Optional[HostResult]:
            if stop.is_set():
                return None
            if not limiter.wait(stop):
                return None
            if stealth_delay > 0:
                time.sleep(random.uniform(0, stealth_delay))
            is_up, resp_time, ttl = self.ping_host(ip, timeout=ping_timeout)
            if not is_up and use_tcp_ping:
                for port in tcp_ping_ports:
                    if stop.is_set():
                        return None
                    if self.tcp_ping(ip, port, timeout=ping_timeout):
                        is_up = True
                        break
            if is_up:
                return HostResult(ip=ip, response_time=resp_time, ttl=ttl)
            return None
        ex = CancellableExecutor(max_workers=max_workers)
        try:
            for hr in ex.map_unordered(probe, [str(h) for h in hosts]):
                if stop.is_set():
                    break
                if hr is not None:
                    with lock:
                        results[hr.ip] = hr
        finally:
            ex.shutdown(wait=False)
        if use_arp and not stop.is_set():
            log("[*] Performing ARP scan …")
            try:
                arp_results = ARPScanner.scan(net, timeout=ping_timeout,
                                              log=log, stop_event=stop)
                merged = 0
                for ip, mac in arp_results.items():
                    if ip in results:
                        results[ip].mac = mac
                        results[ip].vendor = get_vendor_from_mac(mac)
                    else:
                        results[ip] = HostResult(
                            ip=ip, mac=mac, vendor=get_vendor_from_mac(mac)
                        )
                        merged += 1
                if merged:
                    log(f"[*] Added {merged} host(s) from ARP scan.")
            except Exception as exc:
                log(f"[!] ARP scan failed: {exc}")
        arp = self.arp_table()
        for ip, mac in arp.items():
            try:
                if ipaddress.ip_address(ip) in net:
                    if ip in results:
                        if not results[ip].mac:
                            results[ip].mac = mac
                            results[ip].vendor = get_vendor_from_mac(mac)
                    else:
                        results[ip] = HostResult(
                            ip=ip, mac=mac, vendor=get_vendor_from_mac(mac)
                        )
            except ValueError:
                continue
        if resolve_hostnames and results and not stop.is_set():
            log("[*] Resolving hostnames …")
            ips = list(results.keys())
            ex2 = CancellableExecutor(max_workers=min(64, len(ips)))
            try:
                for ip, hn in ex2.map_unordered(
                    lambda i: (i, reverse_dns(i, timeout=1.5)), ips
                ):
                    if stop.is_set():
                        break
                    if hn and ip in results:
                        results[ip].hostname = hn
            finally:
                ex2.shutdown(wait=False)
        with self._stats_lock:
            self._stats.hosts_up = len(results)
            self._stats.end_time = time.time()
        ordered = sorted(results.values(), key=lambda h: ipaddress.ip_address(h.ip))
        log(f"[+] Discovery complete: {len(ordered)} host(s) found "
            f"in {self._stats.duration:.1f}s.")
        return ordered
    
    def _scan_one_port(
        self, host: str, port: int, timeout: float, protocol: str
    ) -> bool:
        if protocol == "tcp":
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    return s.connect_ex((host, port)) == 0
            except OSError:
                return False
        return self.udp_probe(host, port, timeout)

    def scan_ports(
        self,
        host: str,
        ports: Iterable[int],
        log: Callable[[str], None],
        stop_event: Optional[threading.Event] = None,
        timeout: float = DEFAULT_PORT_TIMEOUT,
        max_workers: int = DEFAULT_THREADS,
        protocol: str = "tcp",
        stealth_delay: float = 0.0,
        rate: float = DEFAULT_RATE_PPS,
    ) -> List[PortResult]:
        if not validate_ip(host):
            raise ValueError(f"Invalid host address: {host!r}")
        port_list = list(ports)
        if not port_list:
            raise ValueError("No ports supplied.")
        self._bump(ports_scanned=len(port_list))
        log(f"[*] {protocol.upper()} scan of {host} — {len(port_list)} port(s) …")
        open_ports: List[int] = []
        lock = threading.Lock()
        stop = stop_event if stop_event is not None else threading.Event()
        limiter = RateLimiter(rate)

        def do(port: int) -> Optional[int]:
            if stop.is_set():
                return None
            if not limiter.wait(stop):
                return None
            if stealth_delay > 0:
                time.sleep(random.uniform(0, stealth_delay))
            to = timeout * (2.5 if port in self.SLOW_PORTS else 1.0)
            if self._scan_one_port(host, port, to, protocol):
                return port
            return None
        ex = CancellableExecutor(max_workers=max_workers)
        try:
            for r in ex.map_unordered(do, port_list):
                if stop.is_set():
                    break
                if r is not None:
                    with lock:
                        open_ports.append(r)
        finally:
            ex.shutdown(wait=False)

        results = sorted(
            (PortResult(host=host, port=p,
                        service=WELL_KNOWN_PORTS.get(p), protocol=protocol)
             for p in open_ports),
            key=lambda r: r.port,
        )
        self._bump(ports_open=len(results))
        log(f"[+] Port scan complete: {len(results)} open {protocol.upper()} "
            f"port(s) on {host}.")
        return results

    def _probe_payload(self, port: int, host: str) -> Optional[bytes]:
        if port in self.HTTP_PORTS or port in (80, 443, 8080):
            return (f"HEAD / HTTP/1.0\r\nHost: {host}\r\n"
                    f"User-Agent: NetworkToolkit/{APP_VERSION}\r\n\r\n").encode()
        if port == 6379:
            return b"PING\r\n"
        if port == 11211:
            return b"stats\r\n"
        if port in (25, 587, 110, 143):
            return b"\r\n"
        if port == 21:
            return None
        if port == 22:
            return None
        if port == 27017:
            body = b"isMaster\x00"
            msg = struct.pack("<i", 16 + len(body)) + b"\x00\x00\x00\x00" + body
            return msg
        return None

    def grab_banner(
        self, host: str, port: int, timeout: float = DEFAULT_BANNER_TIMEOUT
    ) -> Optional[str]:
        if port in self.TLS_PORTS:
            return self._grab_tls_banner(host, port, timeout)
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                payload = self._probe_payload(port, host)
                if payload:
                    try:
                        s.sendall(payload)
                    except OSError:
                        pass
                chunks: List[bytes] = []
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    try:
                        data = s.recv(4096)
                    except socket.timeout:
                        break
                    except (ConnectionResetError, OSError):
                        break
                    if not data:
                        break
                    chunks.append(data)
                    if sum(len(c) for c in chunks) >= 8192:
                        break
                raw = b"".join(chunks)
                if not raw:
                    return None
                text = raw.decode("utf-8", errors="replace")
                lines = [sanitize_log(ln.rstrip())
                         for ln in text.splitlines() if ln.strip()]
                banner = " | ".join(lines[:8])
                if not banner:
                    banner = "HEX:" + raw[:64].hex()
                return banner[:MAX_BANNER_LEN]
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def _grab_tls_banner(self, host: str, port: int, timeout: float) -> Optional[str]:
        det = tls_inspect(host, port, timeout=timeout)
        if det.get("error"):
            return None
        parts = [f"TLS {det.get('tls_version') or '?'}"]
        if det.get("cipher"):
            parts.append(str(det["cipher"]))
        if det.get("weak_cipher"):
            parts.append("WEAK-CIPHER")
        if det.get("weak_protocol"):
            parts.append("WEAK-PROTOCOL")
        if det.get("subject_cn"):
            parts.append(f"CN={det['subject_cn']}")
        if det.get("days_left") is not None:
            parts.append(f"expires_in={det['days_left']}d")
        if det.get("self_signed"):
            parts.append("SELF-SIGNED")
        if det.get("fingerprint_sha256"):
            parts.append(f"sha256={str(det['fingerprint_sha256'])[:16]}")
        return " ".join(parts)

    def grab_banners(
        self,
        host: str,
        ports: Sequence[int],
        log: Callable[[str], None],
        stop_event: Optional[threading.Event] = None,
        timeout: float = DEFAULT_BANNER_TIMEOUT,
        max_workers: int = 32,
    ) -> List[PortResult]:
        if not validate_ip(host):
            raise ValueError(f"Invalid host address: {host!r}")
        if not ports:
            raise ValueError("No ports supplied.")
        log(f"[*] Banner grabbing on {host} — {len(ports)} port(s) …")
        stop = stop_event if stop_event is not None else threading.Event()
        out: List[PortResult] = []
        out_lock = threading.Lock()
        def do(p: int) -> Optional[PortResult]:
            if stop.is_set():
                return None
            banner = self.grab_banner(host, p, timeout=timeout)
            service = self.identify_service(p, banner)
            version = self.extract_version(service, banner) if banner else None
            return PortResult(
                host=host, port=p, banner=banner,
                service=service or WELL_KNOWN_PORTS.get(p), version=version,
            )
        ex = CancellableExecutor(max_workers=max_workers)
        try:
            for r in ex.map_unordered(do, list(ports)):
                if stop.is_set():
                    break
                if r is None:
                    continue
                with out_lock:
                    out.append(r)
                if r.banner:
                    self._bump(banners_grabbed=1)
                    log(f"[+] {host}:{r.port} → {r.banner}")
                else:
                    log(f"[-] {host}:{r.port} → no banner")
        finally:
            ex.shutdown(wait=False)
        out.sort(key=lambda r: r.port)
        log("[+] Banner grabbing complete.")
        return out

    def tls_inspect(self, host: str, port: int = 443,
                    timeout: float = DEFAULT_BANNER_TIMEOUT) -> Dict[str, Any]:
        return tls_inspect(host, port, timeout=timeout)

    def http_enumerate(
        self, host: str, ports: Optional[Sequence[int]] = None,
        log: Optional[Callable[[str], None]] = None,
        stop_event: Optional[threading.Event] = None,
        timeout: float = DEFAULT_HTTP_TIMEOUT,
    ) -> Tuple[List[Dict[str, Any]], List[Finding]]:
        return http_enumerate(host, ports, timeout=timeout, log=log,
                              stop_event=stop_event)

    def service_checks(
        self, host: str, ports: Sequence[int],
        log: Optional[Callable[[str], None]] = None,
        stop_event: Optional[threading.Event] = None,
        timeout: float = DEFAULT_PORT_TIMEOUT,
    ) -> Tuple[List[Dict[str, Any]], List[Finding]]:
        return run_service_checks(host, ports, log=log,
                                  stop_event=stop_event, timeout=timeout)

    def identify_service(self, port: int, banner: Optional[str]) -> Optional[str]:
        if banner:
            for service, patterns in SERVICE_PATTERNS.items():
                for pattern in patterns:
                    if pattern.search(banner):
                        return service
        return WELL_KNOWN_PORTS.get(port)

    def extract_version(self, service: Optional[str],
                        banner: Optional[str]) -> Optional[str]:
        if not service or not banner:
            return None
        pat = _VERSION_PATTERNS.get(service)
        if not pat:
            return None
        m = pat.search(banner)
        if m and m.groups():
            try:
                return str(m.group(1))[:40]
            except (IndexError, TypeError):
                return None
        return None

    def os_fingerprint(self, host: str) -> Optional[str]:
        is_up, _, ttl = self.ping_host(host, timeout=2.0)
        if not is_up or ttl is None:
            return None
        if ttl <= 32:
            return "Embedded/Network Device"
        if ttl <= 64:
            return "Linux/Unix"
        if ttl <= 128:
            return "Windows"
        if ttl <= 255:
            return "Cisco/Network Device"
        return None

    def traceroute(
        self,
        host: str,
        max_hops: int = 30,
        timeout: float = 2.0,
        log: Optional[Callable[[str], None]] = None,
        on_hop: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> List[Dict[str, Any]]:
        hops: List[Dict[str, Any]] = []
        system = platform.system().lower()
        tool = "tracert" if system.startswith("win") else "traceroute"
        if shutil.which(tool) is None:
            if log:
                log(f"[*] '{tool}' unavailable — TTL-walk fallback engaged.")
            return self._traceroute_ttl_walk(host, max_hops, timeout, on_hop)
        try:
            if system.startswith("win"):
                cmd = ["tracert", "-d", "-h", str(max_hops),
                       "-w", str(int(timeout * 1000)), host]
            else:
                cmd = ["traceroute", "-n", "-m", str(max_hops),
                       "-w", str(int(timeout)), host]
            creationflags = subprocess.CREATE_NO_WINDOW if is_windows() else 0
            with subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, creationflags=creationflags,
            ) as proc:
                assert proc.stdout is not None
                for line in proc.stdout:
                    line = line.strip()
                    if not line:
                        continue
                    m = re.match(r"(\d+)\s+(.*)", line)
                    if not m:
                        continue
                    hop_num = int(m.group(1))
                    rest = m.group(2)
                    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
                    ip = ip_match.group(1) if ip_match else None
                    times = re.findall(r"([\d.]+)\s*ms", rest)
                    hop = {
                        "hop": hop_num, "ip": ip or "*",
                        "times": [float(t) for t in times] if times else [],
                    }
                    hops.append(hop)
                    if on_hop:
                        on_hop(hop)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception as exc:
            if log:
                log(f"[!] Traceroute error: {exc}")
        return hops

    def _traceroute_ttl_walk(
        self,
        host: str,
        max_hops: int = 30,
        timeout: float = 2.0,
        on_hop: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> List[Dict[str, Any]]:
        hops: List[Dict[str, Any]] = []
        system = platform.system().lower()
        creationflags = subprocess.CREATE_NO_WINDOW if is_windows() else 0
        for ttl in range(1, max_hops + 1):
            try:
                if system.startswith("win"):
                    cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)),
                           "-i", str(ttl), host]
                elif system == "darwin":
                    cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)),
                           "-m", str(ttl), host]
                else:
                    cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))),
                           "-t", str(ttl), host]
                out = subprocess.check_output(
                    cmd, text=True, stderr=subprocess.DEVNULL,
                    creationflags=creationflags, timeout=timeout + 2)
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", out)
                ip = m.group(1) if m else "*"
                t = re.findall(r"time[=<]([\d.]+)\s*ms", out, re.IGNORECASE)
                hop = {"hop": ttl, "ip": ip,
                       "times": [float(x) for x in t] if t else []}
            except Exception:
                hop = {"hop": ttl, "ip": "*", "times": []}
            hops.append(hop)
            if on_hop:
                on_hop(hop)
            if hop["ip"] != "*" and hop["ip"] == host:
                break
        return hops

    def dns_lookup(self, hostname: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "hostname": hostname, "addresses": [], "reverse": {}, "records": {},
        }
        try:
            addrs = socket.getaddrinfo(hostname, None)
            ips = sorted({info[4][0] for info in addrs})
            result["addresses"] = ips
        except socket.gaierror as e:
            result["error"] = str(e)
            return result

        for ip in result["addresses"]:
            result["reverse"][ip] = reverse_dns(ip)

        if _HAVE_DNSPYTHON and dns is not None:
            for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
                try:
                    answers = dns.resolver.resolve(hostname, rtype, lifetime=3.0)  # type: ignore
                    result["records"][rtype] = [str(a) for a in answers]
                except Exception:
                    result["records"][rtype] = []
        return result

    def whois_lookup(self, target: str) -> Optional[str]:
        try:
            if is_windows():
                for exe in ("whois.exe", "whois64.exe"):
                    try:
                        out = subprocess.check_output(
                            [exe, target], text=True,
                            stderr=subprocess.DEVNULL, timeout=15,
                        )
                        if out and out.strip():
                            return out
                    except FileNotFoundError:
                        continue
                    except (subprocess.CalledProcessError,
                            subprocess.TimeoutExpired):
                        continue
            else:
                out = subprocess.check_output(
                    ["whois", target], text=True,
                    stderr=subprocess.DEVNULL, timeout=15,
                )
                if out and out.strip():
                    return out
        except (FileNotFoundError, subprocess.CalledProcessError,
                subprocess.TimeoutExpired):
            pass
        return rdap_lookup(target)

    def dns_axfr(self, domain: str, nameserver: Optional[str] = None
                 ) -> Optional[List[str]]:
        if not _HAVE_DNSPYTHON or dns is None:
            return None
        try:
            if nameserver is None:
                ns_answers = dns.resolver.resolve(domain, "NS", lifetime=3.0)  # type: ignore
                nameserver = str(ns_answers[0])
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, lifetime=5.0))  # type: ignore
            return [str(name) for name in zone.nodes.keys()]
        except Exception:
            return None

    @staticmethod
    def subnet_info(cidr: str) -> Optional[Dict[str, Any]]:
        net = validate_cidr(cidr)
        if net is None:
            return None
        num_hosts = network_host_count(net)
        if num_hosts:
            first = network_first_host(net)
            last = network_last_host(net)
        else:
            first = last = net.network_address
        return {
            "network": str(net.network_address),
            "broadcast": str(net.broadcast_address),
            "netmask": str(net.netmask),
            "prefixlen": net.prefixlen,
            "num_addresses": net.num_addresses,
            "num_hosts": num_hosts,
            "first_host": str(first),
            "last_host": str(last),
            "is_private": is_private_ip(str(net.network_address)),
        }

    @staticmethod
    def analyze_findings(host: HostResult) -> List[Finding]:
        findings: List[Finding] = []
        ports = set(host.open_ports)
        for rule in FINDING_RULES:
            matched = sorted(p for p in rule["ports"] if p in ports)
            if not matched:
                continue
            try:
                sev = Severity(rule["severity"])
            except ValueError:
                sev = Severity.INFO
            for port in matched:
                findings.append(Finding(
                    host=host.ip, port=port,
                    title=rule["title"], detail=rule["detail"], severity=sev,
                ))
        findings.extend(NetworkScanner.analyze_vulnerabilities(host))
        return findings

    @staticmethod
    def analyze_vulnerabilities(host: HostResult) -> List[Finding]:
        out: List[Finding] = []
        seen: Set[str] = set()
        for port in host.open_ports:
            svc = host.services.get(port) or WELL_KNOWN_PORTS.get(port)
            ver = host.versions.get(port) or ""
            ban = host.banners.get(port) or ""
            text = f"{svc or ''} {ver} {ban}"
            for rule in VULN_RULES:
                try:
                    if not rule["regex"].search(text):
                        continue
                except Exception:
                    continue
                key = f"{rule['title']}@{port}"
                if key in seen:
                    continue
                seen.add(key)
                try:
                    sev = Severity(rule["severity"])
                except ValueError:
                    sev = Severity.INFO
                cve = rule.get("cve")
                out.append(Finding(
                    host=host.ip, port=port,
                    title=f"{rule['title']}" + (f" [{cve}]" if cve else ""),
                    detail=rule["detail"], severity=sev,
                ))
        return out

HTTP_ENUM_PATHS: Tuple[str, ...] = (
    "/", "/robots.txt", "/sitemap.xml", "/favicon.ico",
    "/.well-known/security.txt", "/security.txt",
    "/.git/HEAD", "/.env", "/.svn/entries", "/server-status",
    "/server-info", "/phpinfo.php", "/admin/", "/wp-login.php",
    "/actuator/health", "/api/",
)

def http_enumerate(
    host: str,
    ports: Optional[Sequence[int]] = None,
    timeout: float = DEFAULT_HTTP_TIMEOUT,
    log: Optional[Callable[[str], None]] = None,
    stop_event: Optional[threading.Event] = None,
) -> Tuple[List[Dict[str, Any]], List[Finding]]:
    if ports is None:
        ports = (80, 443, 8080, 8443)
    entries: List[Dict[str, Any]] = []
    findings: List[Finding] = []
    interesting: Dict[str, Tuple[str, str, str]] = {
        "/.git/HEAD": ("high", "Exposed Git repository",
                       "/.git/HEAD responds — source code and history may be public."),
        "/.env": ("critical", "Exposed .env file",
                  "/.env responds — secrets (keys, passwords) may be leaked."),
        "/.svn/entries": ("high", "Exposed SVN working copy",
                          "/.svn/entries responds — source metadata is public."),
        "/server-status": ("low", "Apache server-status exposed",
                           "/server-status reveals traffic and configuration."),
        "/phpinfo.php": ("medium", "phpinfo() exposed",
                         "phpinfo() discloses paths, versions and configuration."),
        "/actuator/health": ("medium", "Spring Actuator exposed",
                             "Actuator endpoints can leak internals."),
    }
    for port in ports:
        if stop_event is not None and stop_event.is_set():
            break
        use_tls = port in (443, 8443, 9443, 4443)
        base = HTTPProber.probe(host, port, use_tls=use_tls, timeout=timeout,
                                path="/")
        if base is None:
            continue
        entry: Dict[str, Any] = {
            "host": host, "port": port, "tls": use_tls,
            "status": base.get("status_line", ""), "title": "",
            "tech": [], "paths": {},
        }
        body = base.get("body_preview", "") or ""
        m = re.search(r"<title[^>]*>([^<]{1,120})", body, re.IGNORECASE)
        if m:
            entry["title"] = m.group(1).strip()
        hdrs = base.get("headers", {})
        for hk in ("server", "x-powered-by", "x-aspnet-version", "via",
                   "x-generator"):
            if hdrs.get(hk):
                entry["tech"].append(f"{hk}={hdrs[hk]}")
        ck = hdrs.get("set-cookie", "")
        if re.search(r"PHPSESSID", ck, re.IGNORECASE):
            entry["tech"].append("PHP")
        if re.search(r"JSESSIONID", ck, re.IGNORECASE):
            entry["tech"].append("Java")
        if re.search(r"ASP.NET", ck, re.IGNORECASE):
            entry["tech"].append("ASP.NET")
        if log:
            log(f"[*] HTTP{'S' if use_tls else ''} {host}:{port} "
                f"{entry['status']}"
                + (f' "{entry["title"]}"' if entry["title"] else ""))
            if entry["tech"]:
                log(f"    tech: {', '.join(entry['tech'])}")
        for path in HTTP_ENUM_PATHS:
            if stop_event is not None and stop_event.is_set():
                break
            if path == "/":
                entry["paths"][path] = entry["status"]
                continue
            pr = HTTPProber.probe(host, port, use_tls=use_tls, timeout=timeout,
                                  path=path)
            if pr is None:
                continue
            status = pr.get("status_line", "")
            entry["paths"][path] = status
            if re.search(r"\b200\b", status) and path in interesting:
                sev, title, detail = interesting[path]
                findings.append(Finding(host=host, port=port, title=title,
                                        detail=detail,
                                        severity=Severity(sev)))
                if log:
                    log(f"    [!] {title}: {path} → {status}")
        entries.append(entry)
    return entries, findings

def import_nmap_xml(path: str) -> Tuple[List[HostResult], List[PortResult]]:
    hosts: List[HostResult] = []
    ports: List[PortResult] = []
    tree = ET.parse(path)
    root = tree.getroot()
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break
        if not ip:
            continue
        mac = None
        vendor = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "mac":
                mac = (addr.get("addr") or "").lower()
                vendor = addr.get("vendor")
                break
        hostname = None
        hn_el = host_el.find("hostnames/hostname")
        if hn_el is not None:
            hostname = hn_el.get("name")
        hr = HostResult(ip=ip, mac=mac, vendor=vendor, hostname=hostname)
        for port_el in host_el.findall("ports/port"):
            try:
                pnum = int(port_el.get("portid", "0"))
            except ValueError:
                continue
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            svc = svc_el.get("name") if svc_el is not None else None
            ver = None
            if svc_el is not None:
                ver_parts = [svc_el.get("product"), svc_el.get("version")]
                ver = " ".join(p for p in ver_parts if p)
            hr.open_ports.append(pnum)
            if svc:
                hr.services[pnum] = svc
            if ver:
                hr.versions[pnum] = ver
            ports.append(PortResult(
                host=ip, port=pnum, service=svc, version=ver or None,
                state="open", protocol=port_el.get("protocol", "tcp"),
            ))
        hosts.append(hr)
    return hosts, ports

def diff_hosts(old: List[HostResult], new: List[HostResult]
               ) -> Dict[str, List[str]]:
    old_map = {h.ip: h for h in old}
    new_map = {h.ip: h for h in new}
    added = sorted(set(new_map) - set(old_map))
    removed = sorted(set(old_map) - set(new_map))
    changed: List[str] = []
    for ip in set(old_map) & set(new_map):
        o, n = old_map[ip], new_map[ip]
        if set(o.open_ports) != set(n.open_ports):
            changed.append(ip)
    return {"added": added, "removed": removed, "changed": changed}

class NetworkToolkitGUI:
    POLL_INTERVAL_MS: int = 100
    MAX_ROWS_RENDER: int = 5000
    SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
        "Quick": {
            "timeout": 0.5, "threads": 256, "top_ports": "top100",
            "use_arp": True, "use_tcp_ping": True, "resolve_dns": True,
            "stealth_delay": 0.0,
        },
        "Normal": {
            "timeout": 0.6, "threads": 128, "top_ports": "top1000",
            "use_arp": True, "use_tcp_ping": True, "resolve_dns": True,
            "stealth_delay": 0.0,
        },
        "Deep": {
            "timeout": 1.0, "threads": 128, "top_ports": "top1000",
            "use_arp": True, "use_tcp_ping": True, "resolve_dns": True,
            "stealth_delay": 0.0,
        },
        "Stealth": {
            "timeout": 1.5, "threads": 16, "top_ports": "top100",
            "use_arp": False, "use_tcp_ping": True, "resolve_dns": False,
            "stealth_delay": 0.2,
        },
    }

    def __init__(self, root: "tk.Tk") -> None:
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1400x900")
        self.root.minsize(1100, 700)
        try:
            self.root.iconname(APP_NAME)
        except tk.TclError:
            pass
        self.scanner = NetworkScanner()
        self._log_queue: "queue.Queue[Tuple[str, str]]" = queue.Queue(maxsize=LOG_QUEUE_MAX)
        self._ui_queue: "queue.Queue[Callable[[], None]]" = queue.Queue()
        self._worker: Optional[threading.Thread] = None
        self._stop_event: threading.Event = threading.Event()
        self._discovered: List[HostResult] = []
        self._scan_results: List[PortResult] = []
        self._findings: List[Finding] = []
        self._previous_hosts: List[HostResult] = []
        self._sort_reverse: Dict[str, bool] = {}
        self._render_limited = False
        cfg = load_config()
        self.allow_public_var = tk.BooleanVar(value=bool(cfg.get("allow_public", False)))
        self.auto_save_var = tk.BooleanVar(value=bool(cfg.get("auto_save", False)))
        self.save_dir_var = tk.StringVar(
            value=cfg.get("save_dir", str(Path.home() / "network_scans"))
        )
        self.theme_var = tk.StringVar(value=cfg.get("theme", "clam"))
        self.dark_mode_var = tk.BooleanVar(value=bool(cfg.get("dark_mode", True)))
        self.stealth_var = tk.DoubleVar(value=float(cfg.get("stealth_delay", 0.0)))
        self.filter_var = tk.StringVar()
        self.protocol_var = tk.StringVar(value="tcp")
        self.rate_var = tk.DoubleVar(value=float(cfg.get("rate_pps", 0.0)))
        self.monitor_var = tk.BooleanVar(value=False)
        self.monitor_interval_var = tk.DoubleVar(
            value=float(cfg.get("monitor_interval", MONITOR_DEFAULT_INTERVAL)))
        self._monitor_after: Optional[str] = None
        self._setup_styles()
        self._build_ui()
        self._poll_log_queue()
        self._bind_shortcuts()
        self._apply_dark_mode()
        self._print_banner()
        self._update_stats_label()

    def _setup_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use(self.theme_var.get())
        except tk.TclError:
            pass
        style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"))
        style.configure("Treeview", font=(safe_font()[0], 9), rowheight=22)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("Danger.TButton", foreground="#b00")
    def _apply_dark_mode(self) -> None:
        if self.dark_mode_var.get():
            bg, fg = "#0d1117", "#c9d1d9"
        else:
            bg, fg = "#ffffff", "#000000"
        for widget in (self.output, self.dns_result, self.trace_result):
            try:
                widget.configure(background=bg, foreground=fg, insertbackground=fg)
            except tk.TclError:
                pass
    def _bind_shortcuts(self) -> None:
        self.root.bind("<F5>", lambda e: self.on_discover())
        self.root.bind("<F6>", lambda e: self.on_scan_ports())
        self.root.bind("<F7>", lambda e: self.on_grab_banners())
        self.root.bind("<F8>", lambda e: self.on_interface_info())
        self.root.bind("<F9>", lambda e: self.on_full_scan())
        self.root.bind("<Escape>", lambda e: self.on_stop())
        self.root.bind("<Control-l>", lambda e: self.on_clear())
        self.root.bind("<Control-s>", lambda e: self.on_export())
        self.root.bind("<Control-q>", lambda e: self.on_quit())
        self.root.bind("<Control-h>", lambda e: self.on_show_history())
        self.root.bind("<Control-r>", lambda e: self.on_subnet_calc())
        self.root.bind("<Control-w>", lambda e: self.on_wol())
        self.root.bind("<Control-d>", lambda e: self.on_diff())
        self.root.bind("<Control-i>", lambda e: self.on_import_nmap())
        self.root.bind("<F10>", lambda e: self.on_tls_inspect())
        self.root.bind("<F11>", lambda e: self.on_service_checks())
        self.root.bind("<F12>", lambda e: self.on_http_enum())
        self.root.bind("<Control-t>", lambda e: self.on_html_report())
        self.root.bind("<Control-m>", lambda e: self.on_toggle_monitor())
        self.root.bind("<Control-n>", lambda e: self.on_clear_results())
    def _build_ui(self) -> None:
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)
        self.notebook = Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.scanner_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_tab, text="  Scanner  ")
        self._build_scanner_tab(self.scanner_tab)
        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="  Results  ")
        self._build_results_tab(self.results_tab)
        self.findings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.findings_tab, text="  Findings  ")
        self._build_findings_tab(self.findings_tab)
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="  Dashboard  ")
        self._build_dashboard_tab(self.dashboard_tab)
        self.tools_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.tools_tab, text="  Tools  ")
        self._build_tools_tab(self.tools_tab)
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="  Settings  ")
        self._build_settings_tab(self.settings_tab)
        self._build_statusbar(main_frame)

    def _build_scanner_tab(self, parent: "ttk.Frame") -> None:
        target_frame = ttk.LabelFrame(parent, text="Target", padding=8)
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(target_frame, text="Network (CIDR):").grid(
            row=0, column=0, sticky=tk.W, padx=(0, 6))
        self.network_var = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(target_frame, textvariable=self.network_var, width=30).grid(
            row=0, column=1, sticky=tk.W)
        ttk.Button(target_frame, text="Detect Local",
                   command=self.on_detect_local, width=12).grid(row=0, column=2, padx=5)
        ttk.Label(target_frame, text="Host:").grid(
            row=1, column=0, sticky=tk.W, pady=(6, 0))
        self.host_var = tk.StringVar()
        self.host_combo = ttk.Combobox(
            target_frame, textvariable=self.host_var, width=28, values=[])
        self.host_combo.grid(row=1, column=1, sticky=tk.W, pady=(6, 0))
        ttk.Label(target_frame, text="Ports:").grid(
            row=2, column=0, sticky=tk.W, pady=(6, 0))
        self.ports_var = tk.StringVar(value="22,80,443,8000-8100")
        ttk.Entry(target_frame, textvariable=self.ports_var, width=30).grid(
            row=2, column=1, sticky=tk.W, pady=(6, 0))
        preset_frame = ttk.Frame(target_frame)
        preset_frame.grid(row=2, column=2, padx=5, pady=(6, 0), sticky=tk.W)
        ttk.Button(preset_frame, text="Top 100", width=8,
                   command=lambda: self.ports_var.set(
                       ",".join(str(p) for p in NetworkScanner.TOP_100_PORTS))
                   ).pack(side=tk.LEFT, padx=1)
        ttk.Button(preset_frame, text="Top 1000", width=9,
                   command=lambda: self.ports_var.set(
                       ",".join(str(p) for p in NetworkScanner.TOP_1000_PORTS))
                   ).pack(side=tk.LEFT, padx=1)
        ttk.Button(preset_frame, text="All", width=5,
                   command=lambda: self.ports_var.set("1-65535")
                   ).pack(side=tk.LEFT, padx=1)
        ttk.Button(preset_frame, text="Save Preset", width=11,
                   command=self.on_save_preset).pack(side=tk.LEFT, padx=1)
        ttk.Button(preset_frame, text="Load Preset", width=11,
                   command=self.on_load_preset).pack(side=tk.LEFT, padx=1)
        options_frame = ttk.LabelFrame(parent, text="Scan Options", padding=8)
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        self.use_arp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="ARP Scan",
                        variable=self.use_arp_var).grid(row=0, column=0, sticky=tk.W, padx=5)
        self.use_tcp_ping_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="TCP Ping",
                        variable=self.use_tcp_ping_var).grid(row=0, column=1, sticky=tk.W, padx=5)
        self.resolve_dns_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Resolve DNS",
                        variable=self.resolve_dns_var).grid(row=0, column=2, sticky=tk.W, padx=5)
        self.os_detect_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="OS Detection",
                        variable=self.os_detect_var).grid(row=0, column=3, sticky=tk.W, padx=5)
        self.aggressive_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Aggressive",
                        variable=self.aggressive_var).grid(row=0, column=4, sticky=tk.W, padx=5)
        ttk.Label(options_frame, text="Threads:").grid(
            row=1, column=0, sticky=tk.W, padx=5, pady=(6, 0))
        self.threads_var = tk.IntVar(value=DEFAULT_THREADS)
        ttk.Spinbox(options_frame, from_=1, to=MAX_SCAN_THREADS,
                    textvariable=self.threads_var, width=8).grid(
            row=1, column=1, sticky=tk.W, padx=5, pady=(6, 0))
        ttk.Label(options_frame, text="Timeout (s):").grid(
            row=1, column=2, sticky=tk.W, padx=5, pady=(6, 0))
        self.timeout_var = tk.DoubleVar(value=DEFAULT_PORT_TIMEOUT)
        ttk.Spinbox(options_frame, from_=0.1, to=10.0, increment=0.1,
                    textvariable=self.timeout_var, width=8).grid(
            row=1, column=3, sticky=tk.W, padx=5, pady=(6, 0))
        ttk.Label(options_frame, text="Profile:").grid(
            row=1, column=4, sticky=tk.W, padx=5, pady=(6, 0))
        self.profile_var = tk.StringVar(value="Normal")
        profile_combo = ttk.Combobox(
            options_frame, textvariable=self.profile_var,
            values=list(self.SCAN_PROFILES.keys()), state="readonly", width=10)
        profile_combo.grid(row=1, column=5, sticky=tk.W, padx=5, pady=(6, 0))
        profile_combo.bind("<<ComboboxSelected>>", self._on_profile_change)
        ttk.Label(options_frame, text="Stealth delay (s):").grid(
            row=2, column=0, sticky=tk.W, padx=5, pady=(6, 0))
        ttk.Spinbox(options_frame, from_=0.0, to=5.0, increment=0.05,
                    textvariable=self.stealth_var, width=8).grid(
            row=2, column=1, sticky=tk.W, padx=5, pady=(6, 0))
        ttk.Label(options_frame, text="Protocol:").grid(
            row=2, column=2, sticky=tk.W, padx=5, pady=(6, 0))
        ttk.Combobox(options_frame, textvariable=self.protocol_var,
                     values=("tcp", "udp"), state="readonly", width=6).grid(
            row=2, column=3, sticky=tk.W, padx=5, pady=(6, 0))
        ttk.Label(options_frame, text="Rate (pkt/s, 0 = ∞):").grid(
            row=2, column=4, sticky=tk.W, padx=5, pady=(6, 0))
        ttk.Spinbox(options_frame, from_=0.0, to=10000.0, increment=50.0,
                    textvariable=self.rate_var, width=8).grid(
            row=2, column=5, sticky=tk.W, padx=5, pady=(6, 0))
        actions_frame = ttk.LabelFrame(parent, text="Actions", padding=8)
        actions_frame.pack(fill=tk.X, padx=5, pady=5)
        btn_config = [
            ("Discover Hosts", self.on_discover, "F5"),
            ("Scan Ports", self.on_scan_ports, "F6"),
            ("Grab Banners", self.on_grab_banners, "F7"),
            ("Interface Info", self.on_interface_info, "F8"),
            ("Traceroute", self.on_traceroute, ""),
            ("DNS Lookup", self.on_dns_lookup, ""),
            ("Full Scan", self.on_full_scan, "F9"),
            ("Whois", self.on_whois, ""),
            ("Subnet Calc", self.on_subnet_calc, "Ctrl+R"),
            ("Wake-on-LAN", self.on_wol, "Ctrl+W"),
            ("History", self.on_show_history, "Ctrl+H"),
            ("Analyze", self.on_analyze, ""),
            ("Diff vs Prev", self.on_diff, "Ctrl+D"),
            ("Import Nmap", self.on_import_nmap, "Ctrl+I"),
            ("Zone Transfer", self.on_axfr, ""),
            ("HTTP Audit", self.on_http_audit, ""),
            ("TLS Inspect", self.on_tls_inspect, "F10"),
            ("Service Checks", self.on_service_checks, "F11"),
            ("HTTP Enum", self.on_http_enum, "F12"),
            ("Save Session", self.on_save_session, ""),
            ("Load Session", self.on_load_session, ""),
            ("HTML Report", self.on_html_report, "Ctrl+T"),
            ("Monitor", self.on_toggle_monitor, "Ctrl+M"),
            ("Clear Results", self.on_clear_results, "Ctrl+N"),
        ]
        self._action_buttons: List[ttk.Button] = []
        for i, (text, cmd, shortcut) in enumerate(btn_config):
            btn = ttk.Button(actions_frame, text=text, command=cmd, width=15)
            btn.grid(row=i // 4, column=i % 4, padx=3, pady=3, sticky=tk.W)
            self._action_buttons.append(btn)
            self._add_tooltip(btn, f"{text}" + (f" ({shortcut})" if shortcut else ""))
        self.btn_stop = ttk.Button(
            actions_frame, text="Stop", command=self.on_stop, width=15,
            state=tk.DISABLED, style="Danger.TButton")
        self.btn_stop.grid(row=6, column=0, padx=3, pady=3, sticky=tk.W)
        ttk.Button(actions_frame, text="Clear Output",
                   command=self.on_clear, width=15).grid(row=6, column=1, padx=3, pady=3, sticky=tk.W)
        ttk.Button(actions_frame, text="Export Results",
                   command=self.on_export, width=15).grid(row=6, column=2, padx=3, pady=3, sticky=tk.W)
        ttk.Button(actions_frame, text="Open Save Dir",
                   command=self.on_open_save_dir, width=15).grid(row=6, column=3, padx=3, pady=3, sticky=tk.W)
        progress_frame = ttk.Frame(parent)
        progress_frame.pack(fill=tk.X, padx=5, pady=5)
        self.progress = ttk.Progressbar(progress_frame, mode="indeterminate", length=200)
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.progress_label = ttk.Label(progress_frame, text="", width=28)
        self.progress_label.pack(side=tk.RIGHT, padx=5)
        output_frame = ttk.LabelFrame(parent, text="Output", padding=5)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.output = scrolledtext.ScrolledText(
            output_frame, wrap=tk.WORD, font=safe_font(), state=tk.DISABLED,
            background="#0d1117", foreground="#c9d1d9",
            insertbackground="#c9d1d9", selectbackground="#264f78")
        self.output.pack(fill=tk.BOTH, expand=True)
        self.output.tag_configure("success", foreground="#3fb950")
        self.output.tag_configure("error", foreground="#f85149")
        self.output.tag_configure("warning", foreground="#d29922")
        self.output.tag_configure("info", foreground="#58a6ff")
        self.output.tag_configure("header", foreground="#c9d1d9",
                                  font=(safe_font()[0], 10, "bold"))
        self.output.tag_configure("critical", foreground="#ff6b6b",
                                  font=(safe_font()[0], 10, "bold"))

    def _build_results_tab(self, parent: "ttk.Frame") -> None:
        filter_bar = ttk.Frame(parent)
        filter_bar.pack(fill=tk.X, padx=5, pady=(5, 0))
        ttk.Label(filter_bar, text="Filter:").pack(side=tk.LEFT)
        ttk.Entry(filter_bar, textvariable=self.filter_var, width=40).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(filter_bar, text="Apply",
                   command=self._apply_filter).pack(side=tk.LEFT)
        ttk.Button(filter_bar, text="Clear",
                   command=lambda: (self.filter_var.set(""),
                                    self._apply_filter())).pack(side=tk.LEFT, padx=5)
        pane = PanedWindow(parent, orient=tk.VERTICAL)
        pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        hosts_frame = ttk.LabelFrame(pane, text="Discovered Hosts", padding=5)
        pane.add(hosts_frame, weight=1)
        columns = ("ip", "mac", "vendor", "hostname", "device", "os", "ports")
        self.hosts_tree = Treeview(hosts_frame, columns=columns, show="headings", height=8)
        for col, heading, width in (
            ("ip", "IP Address", 130), ("mac", "MAC Address", 150),
            ("vendor", "Vendor", 120), ("hostname", "Hostname", 180),
            ("device", "Device Type", 130), ("os", "OS Guess", 120),
            ("ports", "Open Ports", 220)):
            self.hosts_tree.heading(col, text=heading,
                                    command=lambda c=col: self._sort_tree(self.hosts_tree, c))
            self.hosts_tree.column(col, width=width, minwidth=60)
        hosts_scroll = ttk.Scrollbar(hosts_frame, orient=tk.VERTICAL,
                                     command=self.hosts_tree.yview)
        self.hosts_tree.configure(yscrollcommand=hosts_scroll.set)
        self.hosts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hosts_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.hosts_tree.bind("<Double-1>", self._on_host_double_click)
        self._add_tree_menu(self.hosts_tree, is_host=True)
        ports_frame = ttk.LabelFrame(pane, text="Port Scan Results", padding=5)
        pane.add(ports_frame, weight=1)
        port_columns = ("host", "port", "service", "version", "state", "banner")
        self.ports_tree = Treeview(ports_frame, columns=port_columns,
                                   show="headings", height=8)
        for col, heading, width in (
            ("host", "Host", 130), ("port", "Port", 70),
            ("service", "Service", 110), ("version", "Version", 110),
            ("state", "State", 70), ("banner", "Banner", 400)):
            self.ports_tree.heading(col, text=heading,
                                    command=lambda c=col: self._sort_tree(self.ports_tree, c))
            self.ports_tree.column(col, width=width, minwidth=50)
        ports_scroll = ttk.Scrollbar(ports_frame, orient=tk.VERTICAL,
                                     command=self.ports_tree.yview)
        self.ports_tree.configure(yscrollcommand=ports_scroll.set)
        self.ports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ports_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._add_tree_menu(self.ports_tree, is_host=False)

    def _build_findings_tab(self, parent: "ttk.Frame") -> None:
        frame = ttk.LabelFrame(parent, text="Security Findings", padding=5)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        columns = ("severity", "host", "port", "title", "detail")
        self.findings_tree = Treeview(frame, columns=columns,
                                      show="headings", height=20)
        for col, heading, width in (
            ("severity", "Severity", 90), ("host", "Host", 130),
            ("port", "Port", 70), ("title", "Title", 220),
            ("detail", "Detail", 520)):
            self.findings_tree.heading(col, text=heading,
                                       command=lambda c=col: self._sort_tree(self.findings_tree, c))
            self.findings_tree.column(col, width=width, minwidth=60)
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL,
                               command=self.findings_tree.yview)
        self.findings_tree.configure(yscrollcommand=scroll.set)
        self.findings_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        for sev in ("critical", "high", "medium", "low", "info"):
            color = {"critical": "#ff6b6b", "high": "#ff9f43",
                     "medium": "#feca57", "low": "#54a0ff",
                     "info": "#c9d1d9"}[sev]
            self.findings_tree.tag_configure(sev, foreground=color)

    def _build_tools_tab(self, parent: "ttk.Frame") -> None:
        dns_frame = ttk.LabelFrame(parent, text="DNS Lookup", padding=8)
        dns_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(dns_frame, text="Hostname:").grid(row=0, column=0, sticky=tk.W)
        self.dns_host_var = tk.StringVar()
        ttk.Entry(dns_frame, textvariable=self.dns_host_var, width=40).grid(
            row=0, column=1, padx=5)
        ttk.Button(dns_frame, text="Lookup",
                   command=self.on_dns_lookup).grid(row=0, column=2, padx=5)
        self.dns_result = scrolledtext.ScrolledText(
            dns_frame, height=6, font=(safe_font()[0], 9), state=tk.DISABLED,
            background="#0d1117", foreground="#c9d1d9")
        self.dns_result.grid(row=1, column=0, columnspan=3, sticky="ew", pady=5)
        trace_frame = ttk.LabelFrame(parent, text="Traceroute", padding=8)
        trace_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Label(trace_frame, text="Target:").grid(row=0, column=0, sticky=tk.W)
        self.trace_host_var = tk.StringVar()
        ttk.Entry(trace_frame, textvariable=self.trace_host_var, width=40).grid(
            row=0, column=1, padx=5)
        ttk.Button(trace_frame, text="Trace",
                   command=self.on_traceroute).grid(row=0, column=2, padx=5)
        self.trace_result = scrolledtext.ScrolledText(
            trace_frame, height=10, font=(safe_font()[0], 9), state=tk.DISABLED,
            background="#0d1117", foreground="#c9d1d9")
        self.trace_result.grid(row=1, column=0, columnspan=3,
                               sticky="nsew", pady=5)
        trace_frame.rowconfigure(1, weight=1)
        trace_frame.columnconfigure(1, weight=1)
        ref_frame = ttk.LabelFrame(parent, text="Port Reference", padding=8)
        ref_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.port_ref_tree = Treeview(ref_frame, columns=("port", "service"),
                                      show="headings", height=8)
        self.port_ref_tree.heading("port", text="Port")
        self.port_ref_tree.heading("service", text="Service")
        self.port_ref_tree.column("port", width=70)
        self.port_ref_tree.column("service", width=240)
        for port, service in sorted(WELL_KNOWN_PORTS.items()):
            self.port_ref_tree.insert("", tk.END, values=(port, service))
        self.port_ref_tree.pack(fill=tk.BOTH, expand=True)

    def _build_settings_tab(self, parent: "ttk.Frame") -> None:
        s = ttk.LabelFrame(parent, text="Application Settings", padding=10)
        s.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(s, text="Theme:").grid(row=0, column=0, sticky=tk.W, pady=5)
        theme_combo = ttk.Combobox(
            s, textvariable=self.theme_var,
            values=["clam", "alt", "default", "classic"], state="readonly", width=15)
        theme_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        theme_combo.bind("<<ComboboxSelected>>", self._on_theme_change)
        ttk.Checkbutton(s, text="Dark Mode", variable=self.dark_mode_var,
                        command=self._apply_dark_mode).grid(
            row=1, column=0, columnspan=2, sticky=tk.W, pady=5)
        ttk.Label(s, text="Default Timeout (s):").grid(
            row=2, column=0, sticky=tk.W, pady=5)
        self.default_timeout_var = tk.DoubleVar(value=DEFAULT_PORT_TIMEOUT)
        ttk.Spinbox(s, from_=0.1, to=10.0, increment=0.1,
                    textvariable=self.default_timeout_var, width=10).grid(
            row=2, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Label(s, text="Default Threads:").grid(
            row=3, column=0, sticky=tk.W, pady=5)
        self.default_threads_var = tk.IntVar(value=DEFAULT_THREADS)
        ttk.Spinbox(s, from_=1, to=MAX_SCAN_THREADS,
                    textvariable=self.default_threads_var, width=10).grid(
            row=3, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Checkbutton(s, text="Auto-save results after full scan",
                        variable=self.auto_save_var).grid(
            row=4, column=0, columnspan=2, sticky=tk.W, pady=5)
        ttk.Checkbutton(s, text="Allow public IP targets (NOT recommended)",
                        variable=self.allow_public_var).grid(
            row=5, column=0, columnspan=2, sticky=tk.W, pady=5)
        ttk.Label(s, text="Save Directory:").grid(
            row=6, column=0, sticky=tk.W, pady=5)
        ttk.Entry(s, textvariable=self.save_dir_var, width=40).grid(
            row=6, column=1, sticky=tk.W, padx=5, pady=5)
        ttk.Button(s, text="Browse",
                   command=self._browse_save_dir).grid(row=6, column=2, padx=5, pady=5)
        ttk.Button(s, text="Save Settings",
                   command=self._save_settings).grid(
            row=7, column=0, columnspan=2, pady=8)
        about = ttk.LabelFrame(parent, text="About", padding=10)
        about.pack(fill=tk.X, padx=10, pady=10)
        text = f"""
{APP_NAME} v{APP_VERSION}

A network scanning and analysis toolkit.

Features:
• Host discovery (ICMP, TCP, ARP) with token-bucket rate limiting
• TCP/UDP port scanning (service-specific UDP probe payloads)
• Banner grabbing, service & version detection
• TLS deep inspection (SAN, issuer, expiry, weak protocol/cipher)
• HTTP security header audit + endpoint enumeration (.git/.env/…)
• Read-only exposure checks (Redis, Docker, FTP, SMTP, SNMP, LDAP …)
• CVE signature rules (Heartbleed, Terrapin, vsftpd, Apache 2.4.49 …)
• OS fingerprinting (TTL heuristics)
• Traceroute (TTL-walk fallback), DNS, Whois/RDAP, DNS AXFR
• Subnet calculator, Wake-on-LAN, monitor mode, saved sessions
• Security findings heuristics, Dashboard charts
• Diff against previous scan, Nmap XML import
• Export: JSON / CSV / XML / Markdown / HTML / DOT / GraphML

Optional: dnspython, cryptography

Disclaimer: For authorized security testing only.
"""
        ttk.Label(about, text=text, justify=tk.LEFT).pack(anchor=tk.W)
    def _build_statusbar(self, parent: "ttk.Frame") -> None:
        bar = ttk.Frame(parent, relief=tk.SUNKEN)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.status_var, anchor=tk.W).pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.stats_var = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.stats_var, anchor=tk.E).pack(
            side=tk.RIGHT, padx=5)

    def _add_tooltip(self, widget: "tk.Widget", text: str) -> None:
        state: List[Optional["tk.Toplevel"]] = [None]
        def enter(event: "tk.Event") -> None:
            if state[0] is not None:
                return
            try:
                x = widget.winfo_rootx() + 25
                y = widget.winfo_rooty() + widget.winfo_height() + 5
                tw = tk.Toplevel(widget)
                tw.wm_overrideredirect(True)
                tw.wm_geometry(f"+{x}+{y}")
                ttk.Label(tw, text=text, background="#ffffe0",
                          relief=tk.SOLID, borderwidth=1, padding=3).pack()
                state[0] = tw
            except tk.TclError:
                pass

        def leave(event: "tk.Event") -> None:
            if state[0] is not None:
                try:
                    state[0].destroy()
                except tk.TclError:
                    pass
                state[0] = None
        widget.bind("<Enter>", enter, add="+")
        widget.bind("<Leave>", leave, add="+")

    def _add_tree_menu(self, tree: "Treeview", is_host: bool) -> None:
        menu = tk.Menu(tree, tearoff=0)
        menu.add_command(label="Copy row", command=lambda: self._copy_tree_row(tree))
        menu.add_command(label="Copy IP", command=lambda: self._copy_tree_ip(tree))
        menu.add_command(label="Send to target",
                         command=lambda: self._send_row_to_target(tree, is_host))
        menu.add_separator()
        menu.add_command(label="Open in browser (http)",
                         command=lambda: self._open_in_browser(tree))

        def popup(event: "tk.Event") -> None:
            row_id = tree.identify_row(event.y)
            if row_id:
                tree.selection_set(row_id)
                try:
                    menu.tk_popup(event.x_root, event.y_root)
                finally:
                    menu.grab_release()
        tree.bind("<Button-3>", popup)
        tree.bind("<Button-2>", popup)

    def _copy_tree_row(self, tree: "Treeview") -> None:
        sel = tree.selection()
        if not sel:
            return
        values = tree.item(sel[0], "values")
        self.root.clipboard_clear()
        self.root.clipboard_append("\t".join(str(v) for v in values))
        self.status_var.set("Row copied to clipboard.")

    def _copy_tree_ip(self, tree: "Treeview") -> None:
        sel = tree.selection()
        if not sel:
            return
        ip = tree.item(sel[0], "values")[0]
        self.root.clipboard_clear()
        self.root.clipboard_append(str(ip))
        self.status_var.set(f"Copied: {ip}")

    def _send_row_to_target(self, tree: "Treeview", is_host: bool) -> None:
        sel = tree.selection()
        if not sel:
            return
        ip = tree.item(sel[0], "values")[0]
        self.host_var.set(ip)
        self.trace_host_var.set(ip)
        self.dns_host_var.set(ip)
        self.notebook.select(self.scanner_tab)
        self.status_var.set(f"Target set to {ip}")

    def _open_in_browser(self, tree: "Treeview") -> None:
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0], "values")
        if not vals:
            return
        host = vals[0]
        port = None
        if len(vals) > 1 and str(vals[1]).isdigit():
            port = int(vals[1])
        url = f"http://{host}" + (f":{port}" if port else "")
        try:
            webbrowser.open(url)
        except Exception:
            pass

    def _sort_tree(self, tree: "Treeview", col: str) -> None:
        reverse = self._sort_reverse.get(col, False)
        items = [(tree.set(item, col), item) for item in tree.get_children("")]
        def key(t: Tuple[str, str]) -> Any:
            v = t[0]
            try:
                return (0, float(v))
            except (ValueError, TypeError):
                return (1, v.lower())
        items.sort(key=key, reverse=reverse)
        for index, (_, item) in enumerate(items):
            tree.move(item, "", index)
        self._sort_reverse[col] = not reverse

    def _on_host_double_click(self, event: "tk.Event") -> None:
        sel = self.hosts_tree.selection()
        if sel:
            values = self.hosts_tree.item(sel[0], "values")
            if values:
                self.host_var.set(values[0])
                self.notebook.select(self.scanner_tab)

    def _on_theme_change(self, event: "tk.Event") -> None:
        try:
            ttk.Style().theme_use(self.theme_var.get())
        except tk.TclError:
            pass

    def _on_profile_change(self, event: "tk.Event") -> None:
        cfg = self.SCAN_PROFILES.get(self.profile_var.get())
        if not cfg:
            return
        self.timeout_var.set(cfg["timeout"])
        self.threads_var.set(cfg["threads"])
        self.use_arp_var.set(cfg["use_arp"])
        self.use_tcp_ping_var.set(cfg["use_tcp_ping"])
        self.resolve_dns_var.set(cfg["resolve_dns"])
        self.stealth_var.set(cfg.get("stealth_delay", 0.0))

    def _browse_save_dir(self) -> None:
        dir_path = filedialog.askdirectory(initialdir=self.save_dir_var.get())
        if dir_path:
            self.save_dir_var.set(dir_path)

    def _save_settings(self) -> None:
        cfg = {
            "allow_public": self.allow_public_var.get(),
            "auto_save": self.auto_save_var.get(),
            "save_dir": self.save_dir_var.get(),
            "theme": self.theme_var.get(),
            "dark_mode": self.dark_mode_var.get(),
            "default_timeout": self.default_timeout_var.get(),
            "default_threads": self.default_threads_var.get(),
            "stealth_delay": self.stealth_var.get(),
            "rate_pps": self.rate_var.get(),
            "monitor_interval": self.monitor_interval_var.get(),
        }
        save_config(cfg)
        self.status_var.set("Settings saved.")

    def _append(self, text: str, tag: str = "") -> None:
        text = sanitize_log(text)
        self.output.configure(state=tk.NORMAL)
        if tag:
            self.output.insert(tk.END, text + "\n", tag)
        else:
            self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.output.configure(state=tk.DISABLED)

    def _append_dns(self, text: str) -> None:
        text = sanitize_log(text)
        self.dns_result.configure(state=tk.NORMAL)
        self.dns_result.insert(tk.END, text + "\n")
        self.dns_result.see(tk.END)
        self.dns_result.configure(state=tk.DISABLED)

    def _append_trace(self, text: str) -> None:
        text = sanitize_log(text)
        self.trace_result.configure(state=tk.NORMAL)
        self.trace_result.insert(tk.END, text + "\n")
        self.trace_result.see(tk.END)
        self.trace_result.configure(state=tk.DISABLED)

    def _log(self, text: str) -> None:
        try:
            self._log_queue.put_nowait((text, ""))
        except queue.Full:
            try:
                self._log_queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._log_queue.put_nowait((text, ""))
            except queue.Full:
                pass

    def _ui(self, fn: Callable[[], None]) -> None:
        try:
            self._ui_queue.put_nowait(fn)
            return
        except queue.Full:
            pass
        except Exception:
            pass
        try:
            self.root.after(0, fn)
        except Exception:
            pass

    def _drain_ui_queue(self) -> None:
        drained = 0
        while drained < 200:
            try:
                fn = self._ui_queue.get_nowait()
            except queue.Empty:
                return
            drained += 1
            try:
                fn()
            except tk.TclError:
                pass
            except Exception as exc:
                self._append(f"[!] UI error: {exc}", "error")

    def _poll_log_queue(self) -> None:
        self._drain_ui_queue()
        drained = 0
        try:
            while drained < 500:
                msg, tag = self._log_queue.get_nowait()
                if not tag:
                    if msg.startswith("[+]"):
                        tag = "success"
                    elif msg.startswith("[!]"):
                        tag = "warning"
                    elif msg.startswith("[-]"):
                        tag = "error"
                    elif msg.startswith("[*]"):
                        tag = "info"
                    elif msg.startswith("="):
                        tag = "header"
                    elif msg.startswith("[CRIT]"):
                        tag = "critical"
                self._append(msg, tag)
                drained += 1
        except queue.Empty:
            pass
        self.root.after(self.POLL_INTERVAL_MS, self._poll_log_queue)

    def _busy(self, busy: bool, status: str = "") -> None:
        state = tk.DISABLED if busy else tk.NORMAL
        for btn in self._action_buttons:
            btn.configure(state=state)
        self.btn_stop.configure(state=tk.NORMAL if busy else tk.DISABLED)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress_label.configure(text="")
        if status:
            self.status_var.set(status)
        elif not busy:
            self.status_var.set("Ready")

    def _run_in_background(self, fn: Callable[[], None], status: str) -> None:
        if self._worker and self._worker.is_alive():
            messagebox.showinfo("Busy", "Another operation is already running.")
            return
        self._stop_event = threading.Event()
        self._busy(True, status)
        def wrapper() -> None:
            try:
                fn()
            except Exception as exc:
                tb = traceback.format_exc()
                save_crash_report(exc, context=status)
                self._log(f"[!] Error: {exc}")
                for line in tb.splitlines():
                    self._log(f"    {line}")
            finally:
                self._ui(lambda: self._busy(False))
                self._ui(self._update_stats_label)
        self._worker = threading.Thread(target=wrapper, daemon=True, name="scan-worker")
        self._worker.start()

    def _confirm_scan(self, description: str) -> bool:
        return messagebox.askyesno(
            "Confirm Scan",
            f"{description}\n\nOnly scan networks and hosts you own or have "
            "explicit permission to test.\n\nProceed?",
            icon=messagebox.WARNING)

    def _require_private_network(self, cidr: str) -> Optional[ipaddress.IPv4Network]:
        net = validate_cidr(cidr)
        if net is None:
            messagebox.showerror("Invalid Network", f"Not a valid IPv4 CIDR: {cidr!r}")
            return None
        if not self.allow_public_var.get() and not is_private_ip(str(net.network_address)):
            messagebox.showerror(
                "Refused",
                "Only private/loopback ranges are allowed by default.\n"
                "Enable 'Allow public IP targets' in Settings if you have "
                "explicit permission to test public ranges.")
            return None
        return net

    def _require_private_host(self, host: str) -> bool:
        if not validate_ip(host):
            messagebox.showerror("Invalid Host", f"Not a valid IP: {host!r}")
            return False
        if not self.allow_public_var.get() and not is_private_ip(host):
            messagebox.showerror(
                "Refused",
                "Only private/loopback addresses are allowed by default.\n"
                "Enable 'Allow public IP targets' in Settings if you have "
                "explicit permission to test public hosts.")
            return False
        return True
    def _print_banner(self) -> None:
        self._append("=" * 62)
        self._append(f"  {APP_NAME} v{APP_VERSION}")
        self._append("=" * 62)
        self._append("")
        self._append("[*] Network Scanning Toolkit")
        self._append("[*] Discovery • Port scan • Banner • OS • Findings")
        self._append("[*] Traceroute • DNS • Whois • AXFR • HTTP audit • WOL")
        self._append("")
        self._append("[!] LEGAL NOTICE: Only scan networks you own or have")
        self._append("    explicit permission to test. Unauthorized scanning")
        self._append("    may be illegal in your jurisdiction.")
        self._append("")
        self._append(f"[*] Running as admin: {'Yes' if is_admin() else 'No'}")
        self._append(f"[*] Local IP: {get_local_ip()}")
        self._append(f"[*] dnspython: {'available' if _HAVE_DNSPYTHON else 'not installed'}")
        self._append(f"[*] cryptography: {'available' if _HAVE_CRYPTOGRAPHY else 'not installed'}")
        self._append("")

    def on_detect_local(self) -> None:
        local_ip = get_local_ip()
        if local_ip and local_ip != "127.0.0.1":
            parts = local_ip.split(".")
            self.network_var.set(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
            self._log(f"[*] Detected local network: {self.network_var.get()}")
        else:
            messagebox.showwarning("Detection Failed", "Could not detect local network.")

    def on_open_save_dir(self) -> None:
        d = Path(self.save_dir_var.get())
        d.mkdir(parents=True, exist_ok=True)
        try:
            if is_windows():
                os.startfile(str(d))  # type: ignore[attr-defined]
            elif is_macos():
                subprocess.Popen(["open", str(d)])
            else:
                subprocess.Popen(["xdg-open", str(d)])
        except Exception as exc:
            messagebox.showerror("Error", f"Could not open folder: {exc}")

    def on_save_preset(self) -> None:
        name = simpledialog.askstring("Save Preset", "Preset name:", parent=self.root)
        if not name:
            return
        spec = self.ports_var.get().strip()
        presets = load_json(PRESETS_FILE, {}) or {}
        presets[name] = spec
        save_json(PRESETS_FILE, presets)
        self._log(f"[+] Saved preset '{name}' = {spec}")

    def on_load_preset(self) -> None:
        presets = load_json(PRESETS_FILE, {}) or {}
        if not presets:
            messagebox.showinfo("No Presets", "No presets saved yet.")
            return
        names = list(presets.keys())
        name = simpledialog.askstring(
            "Load Preset", f"Available: {', '.join(names)}\n\nPreset name:",
            parent=self.root)
        if not name or name not in presets:
            return
        self.ports_var.set(presets[name])
        self._log(f"[*] Loaded preset '{name}' = {presets[name]}")

    def on_discover(self) -> None:
        cidr = self.network_var.get().strip()
        net = self._require_private_network(cidr)
        if net is None:
            return
        if not self._confirm_scan(f"Ping-sweep {net} for live hosts?"):
            return
        def job() -> None:
            t0 = time.time()
            hosts = self.scanner.discover_hosts(
                str(net), log=self._log, stop_event=self._stop_event,
                ping_timeout=self.timeout_var.get(),
                max_workers=self.threads_var.get(),
                use_arp=self.use_arp_var.get(),
                use_tcp_ping=self.use_tcp_ping_var.get(),
                resolve_hostnames=self.resolve_dns_var.get(),
                stealth_delay=self.stealth_var.get(),
                rate=self.rate_var.get())
            self._previous_hosts = list(self._discovered)
            self._discovered = hosts
            def update() -> None:
                self.host_combo.configure(values=[h.ip for h in hosts])
                if hosts and not self.host_var.get():
                    self.host_var.set(hosts[0].ip)
                self._update_hosts_tree()
                self._update_stats_label()
            self._ui(update)
            self._log("")
            if not hosts:
                self._log("[!] No hosts responded.")
                return
            self._log(f"{'IP':<16} {'MAC':<18} {'VENDOR':<16} HOSTNAME")
            self._log("-" * 80)
            for h in hosts:
                self._log(f"{h.ip:<16} {(h.mac or '-'):<18} "
                          f"{(h.vendor or '-'):<16} {h.hostname or '-'}")
            self._log("")
            append_history({
                "action": "discover", "target": str(net),
                "hosts_up": len(hosts),
                "duration": round(time.time() - t0, 2),
                "timestamp": datetime.now().isoformat(),
            })
            audit("discover", target=str(net), hosts=len(hosts))
        self._run_in_background(job, f"Discovering hosts in {net} …")

    def on_scan_ports(self) -> None:
        host = self.host_var.get().strip()
        if not self._require_private_host(host):
            return
        ports = parse_port_range(self.ports_var.get())
        if ports is None:
            messagebox.showerror(
                "Invalid Ports",
                "Use comma-separated ports and/or ranges, e.g. 22,80,443 or 1-1024.")
            return
        proto = (self.protocol_var.get() or "tcp").lower()
        if proto not in ("tcp", "udp"):
            proto = "tcp"
        if not self._confirm_scan(
                f"{proto.upper()} scan of {host} ({len(ports)} ports)?"):
            return
        def job() -> None:
            t0 = time.time()
            results = self.scanner.scan_ports(
                host, ports, log=self._log, stop_event=self._stop_event,
                timeout=self.timeout_var.get(),
                max_workers=self.threads_var.get(),
                protocol=proto, stealth_delay=self.stealth_var.get(),
                rate=self.rate_var.get())
            existing = {(r.host, r.port): r for r in self._scan_results}
            for r in results:
                existing[(r.host, r.port)] = r
            self._scan_results = sorted(existing.values(),
                                        key=lambda x: (x.host, x.port))
            self._ui(self._update_ports_tree)
            host_entry = next((h for h in self._discovered if h.ip == host), None)
            if host_entry is None:
                host_entry = HostResult(ip=host)
                self._discovered.append(host_entry)
            host_entry.open_ports = sorted({r.port for r in results} |
                                           set(host_entry.open_ports))
            for r in results:
                if r.service:
                    host_entry.services[r.port] = r.service
            host_entry.findings = NetworkScanner.analyze_findings(host_entry)
            self._findings = [f for f in self._findings if f.host != host]
            self._findings.extend(host_entry.findings)
            self._ui(self._update_hosts_tree)
            self._ui(self._update_findings_tree)
            self._log("")
            if not results:
                self._log(f"[-] No open {proto.upper()} ports on {host}.")
            else:
                self._log(f"Open {proto.upper()} ports on {host}:")
                self._log(f"{'PORT':<8} {'SERVICE':<16} STATE")
                self._log("-" * 40)
                for r in results:
                    self._log(f"{r.port:<8} {r.service or '-':<16} {r.state}")
            self._log("")
            append_history({
                "action": "scan_ports", "target": host,
                "port_count": len(ports), "open_count": len(results),
                "duration": round(time.time() - t0, 2),
                "timestamp": datetime.now().isoformat(),
            })
        self._run_in_background(job, f"Scanning {host} …")

    def on_grab_banners(self) -> None:
        host = self.host_var.get().strip()
        if not self._require_private_host(host):
            return
        ports = parse_port_range(self.ports_var.get())
        if ports is None:
            messagebox.showerror("Invalid Ports", "Invalid port specification.")
            return
        if not self._confirm_scan(f"Grab banners from {host} ({len(ports)} ports)?"):
            return
        def job() -> None:
            results = self.scanner.grab_banners(
                host, ports, log=self._log, stop_event=self._stop_event,
                timeout=DEFAULT_BANNER_TIMEOUT)
            for r in results:
                existing = next(
                    (x for x in self._scan_results
                     if x.host == r.host and x.port == r.port), None)
                if existing:
                    existing.banner = r.banner or existing.banner
                    existing.service = r.service or existing.service
                    existing.version = r.version or existing.version
                else:
                    self._scan_results.append(r)
            self._scan_results.sort(key=lambda x: (x.host, x.port))
            self._ui(self._update_ports_tree)
            host_entry = next((h for h in self._discovered if h.ip == host), None)
            if host_entry:
                for r in results:
                    if r.banner:
                        host_entry.banners[r.port] = r.banner
                    if r.version:
                        host_entry.versions[r.port] = r.version
            self._log("")
        self._run_in_background(job, f"Grabbing banners from {host} …")

    def on_interface_info(self) -> None:
        def job() -> None:
            info = self.scanner.interface_info()
            for line in info.splitlines():
                self._log(line)
            self._log("")
        self._run_in_background(job, "Collecting interface information …")

    def on_traceroute(self) -> None:
        host = self.trace_host_var.get().strip() or self.host_var.get().strip()
        if not host:
            messagebox.showerror("No Target", "Enter a target host for traceroute.")
            return
        if not validate_ip(host):
            try:
                host = socket.gethostbyname(host)
            except socket.gaierror:
                messagebox.showerror("Invalid Target", f"Cannot resolve: {host}")
                return
        def job() -> None:
            def on_hop(hop: Dict[str, Any]) -> None:
                times = (" ".join(f"{t:.1f}ms" for t in hop["times"])
                         if hop["times"] else "*")
                line = f"{hop['hop']:>3}  {hop['ip']:<16} {times}"
                self._ui(lambda l=line: self._append_trace(l))
            def start() -> None:
                self._clear_trace()
                self._append_trace(f"Traceroute to {host}")
                self._append_trace("=" * 60)
            self._ui(start)
            self.scanner.traceroute(host, max_hops=30, timeout=2.0,
                                    log=self._log, on_hop=on_hop)
            def finish() -> None:
                self._append_trace("")
                self._append_trace("Traceroute complete.")
            self._ui(finish)
        self._run_in_background(job, f"Tracing route to {host} …")

    def _clear_trace(self) -> None:
        self.trace_result.configure(state=tk.NORMAL)
        self.trace_result.delete("1.0", tk.END)
        self.trace_result.configure(state=tk.DISABLED)

    def _clear_dns(self) -> None:
        self.dns_result.configure(state=tk.NORMAL)
        self.dns_result.delete("1.0", tk.END)
        self.dns_result.configure(state=tk.DISABLED)

    def on_dns_lookup(self) -> None:
        hostname = self.dns_host_var.get().strip() or self.host_var.get().strip()
        if not hostname:
            messagebox.showerror("No Target", "Enter a hostname or IP for DNS lookup.")
            return
        def job() -> None:
            def emit(text: str) -> None:
                self._ui(lambda t=text: self._append_dns(t))
            def start() -> None:
                self._clear_dns()
            self._ui(start)
            emit(f"DNS Lookup: {hostname}")
            emit("=" * 60)
            result = self.scanner.dns_lookup(hostname)
            if "error" in result:
                emit(f"Error: {result['error']}")
                return
            emit(f"Hostname: {result['hostname']}")
            emit("")
            emit("Addresses:")
            for ip in result.get("addresses", []):
                emit(f"  {ip}")
            emit("")
            emit("Reverse DNS:")
            for ip, name in result.get("reverse", {}).items():
                emit(f"  {ip} → {name or 'N/A'}")
            if result.get("records"):
                emit("")
                emit("Records:")
                for rtype, values in result["records"].items():
                    if values:
                        emit(f"  {rtype}: {', '.join(values[:5])}")
            emit("")
        self._run_in_background(job, f"Looking up {hostname} …")

    def on_whois(self) -> None:
        target = self.dns_host_var.get().strip() or self.host_var.get().strip()
        if not target:
            messagebox.showerror("No Target", "Enter a domain or IP for whois.")
            return
        def job() -> None:
            self._log(f"[*] Whois lookup: {target}")
            out = self.scanner.whois_lookup(target)
            if out is None:
                self._log("[!] Whois not available (install `whois`).")
                return
            for line in out.splitlines():
                self._log(f"  {line}")
        self._run_in_background(job, f"Whois {target} …")

    def on_axfr(self) -> None:
        domain = simpledialog.askstring(
            "DNS Zone Transfer",
            "Domain to attempt AXFR (e.g. example.com):",
            parent=self.root)
        if not domain:
            return
        def job() -> None:
            self._log(f"[*] Attempting AXFR for {domain} …")
            records = self.scanner.dns_axfr(domain)
            if records is None:
                self._log("[-] AXFR failed or not permitted.")
                return
            self._log(f"[+] AXFR returned {len(records)} record(s):")
            for r in records[:200]:
                self._log(f"  {r}")
        self._run_in_background(job, f"AXFR {domain} …")

    def on_http_audit(self) -> None:
        host = self.host_var.get().strip()
        if not self._require_private_host(host):
            return
        def job() -> None:
            ports_to_try = [80, 8080, 8000, 443, 8443]
            for port in ports_to_try:
                use_tls = port in (443, 8443)
                probe = HTTPProber.probe(host, port, use_tls=use_tls)
                if probe is None:
                    continue
                self._log(f"[*] HTTP{'S' if use_tls else ''} on {host}:{port}")
                self._log(f"    {probe['status_line']}")
                for k, v in list(probe["headers"].items())[:15]:
                    self._log(f"    {k}: {v}")
                for fi in HTTPProber.audit_security_headers(probe):
                    fi.host = host
                    fi.port = port
                    self._findings.append(fi)
                    self._log(f"    [!] {fi.severity.value.upper()}: {fi.title} — {fi.detail}")
                break
            self._ui(self._update_findings_tree)
        self._run_in_background(job, f"HTTP audit {host} …")

    def on_tls_inspect(self) -> None:
        host = self.host_var.get().strip()
        if not self._require_private_host(host):
            return
        port = simpledialog.askinteger(
            "TLS Inspect", "Port to inspect:", initialvalue=443,
            minvalue=1, maxvalue=65535, parent=self.root)
        if not port:
            return
        def job() -> None:
            info = tls_inspect(host, port)
            if info.get("error"):
                self._log(f"[-] TLS {host}:{port} → {info['error']}")
                return
            self._log(f"[*] TLS inspection {host}:{port}")
            for key in ("tls_version", "cipher", "cipher_bits", "weak_cipher",
                        "weak_protocol", "subject_cn", "issuer", "san",
                        "serial", "not_before", "not_after", "days_left",
                        "expired", "self_signed", "fingerprint_sha256"):
                val = info.get(key)
                if val not in (None, "", []):
                    self._log(f"    {key}: {val}")
            new_f = tls_assess(info)
            for f in new_f:
                f.host = host
                f.port = port
                self._findings.append(f)
                self._log(f"    [!] {f.severity.value.upper()}: {f.title} "
                          f"— {f.detail}")
            if not new_f:
                self._log("[+] No TLS weaknesses detected.")
            self._ui(self._update_findings_tree)
        self._run_in_background(job, f"TLS inspect {host}:{port} …")

    def on_service_checks(self) -> None:
        host = self.host_var.get().strip()
        if not self._require_private_host(host):
            return
        host_entry = next((h for h in self._discovered if h.ip == host), None)
        ports: List[int] = []
        if host_entry and host_entry.open_ports:
            ports = sorted(host_entry.open_ports)
        else:
            ports = (parse_port_range(self.ports_var.get())
                     or list(NetworkScanner.COMMON_BANNER_PORTS))
        if not self._confirm_scan(
                f"Run exposure checks against {host} ({len(ports)} ports)?"):
            return
        def job() -> None:
            _checks, new_f = run_service_checks(
                host, ports, log=self._log, stop_event=self._stop_event)
            self._log("")
            for f in new_f:
                f.host = host
                self._findings.append(f)
            if new_f:
                self._log(f"[!] {len(new_f)} exposure finding(s) added.")
            else:
                self._log("[-] No exposure findings from service checks.")
            self._ui(self._update_findings_tree)
        self._run_in_background(job, f"Service checks on {host} …")

    def on_http_enum(self) -> None:
        host = self.host_var.get().strip()
        if not self._require_private_host(host):
            return
        if not self._confirm_scan(
                f"Enumerate common HTTP endpoints on {host}?"):
            return
        def job() -> None:
            entries, new_f = http_enumerate(
                host, log=self._log, stop_event=self._stop_event)
            for f in new_f:
                f.host = host
                self._findings.append(f)
            if not entries:
                self._log("[-] No HTTP services responded.")
            elif new_f:
                self._log(f"[!] {len(new_f)} exposure finding(s) added.")
            self._ui(self._update_findings_tree)
        self._run_in_background(job, f"HTTP enumeration {host} …")

    def on_wol(self) -> None:
        mac = simpledialog.askstring(
            "Wake-on-LAN", "MAC address (e.g. AA:BB:CC:DD:EE:FF):",
            parent=self.root)
        if not mac:
            return
        bcast = simpledialog.askstring(
            "Wake-on-LAN", "Broadcast address:",
            initialvalue="255.255.255.255", parent=self.root) or "255.255.255.255"
        if WakeOnLan.send(mac, bcast):
            self._log(f"[+] WOL magic packet sent to {mac} via {bcast}")
        else:
            self._log(f"[-] Failed to send WOL packet to {mac}")

    def on_subnet_calc(self) -> None:
        cidr = simpledialog.askstring(
            "Subnet Calculator", "Enter CIDR (e.g. 192.168.1.0/24):",
            initialvalue=self.network_var.get(), parent=self.root)
        if not cidr:
            return
        info = NetworkScanner.subnet_info(cidr)
        if info is None:
            messagebox.showerror("Invalid CIDR", f"Not a valid CIDR: {cidr}")
            return
        self._log("")
        self._log("=" * 60)
        self._log(f"SUBNET: {cidr}")
        self._log("=" * 60)
        for k, v in info.items():
            self._log(f"  {k:<16}: {v}")
        self._log("")

    def on_show_history(self) -> None:
        history = load_history()
        if not history:
            messagebox.showinfo("History", "No scan history found.")
            return
        win = tk.Toplevel(self.root)
        win.title("Scan History")
        win.geometry("800x500")
        cols = ("timestamp", "action", "target", "detail")
        tree = Treeview(win, columns=cols, show="headings")
        for c, w in (("timestamp", 170), ("action", 120),
                     ("target", 180), ("detail", 300)):
            tree.heading(c, text=c.title())
            tree.column(c, width=w)
        for h in reversed(history):
            detail = " | ".join(f"{k}={v}" for k, v in h.items()
                                if k not in ("timestamp", "action", "target"))
            tree.insert("", tk.END, values=(
                h.get("timestamp", ""), h.get("action", ""),
                h.get("target", ""), detail))
        tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=5)

    def on_analyze(self) -> None:
        self._findings = []
        for h in self._discovered:
            h.findings = NetworkScanner.analyze_findings(h)
            self._findings.extend(h.findings)
        self._update_findings_tree()
        self._log(f"[*] Analysis complete: {len(self._findings)} finding(s).")

    def on_save_session(self) -> None:
        if not self._discovered and not self._scan_results:
            messagebox.showinfo("No Data", "Nothing to save yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("Session JSON", "*.json"), ("All files", "*.*")],
            initialdir=self.save_dir_var.get(),
            initialfile=f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        if not path:
            return
        try:
            chk = save_session(path, self._discovered, self._scan_results,
                               self._findings)
            self._log(f"[+] Session saved (sha256 {chk[:16]}…) → {path}")
        except Exception as exc:
            save_crash_report(exc, "save_session")
            messagebox.showerror("Save Failed", f"Error: {exc}")

    def on_load_session(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("Session JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        loaded = load_session(path)
        if loaded is None:
            messagebox.showerror(
                "Load Failed",
                "Session file is missing, corrupt, or fails checksum.")
            return
        hosts, ports, findings = loaded
        self._previous_hosts = list(self._discovered)
        self._discovered = hosts
        self._scan_results = ports
        self._findings = findings
        self.host_combo.configure(values=[h.ip for h in hosts])
        if hosts and not self.host_var.get():
            self.host_var.set(hosts[0].ip)
        self._update_hosts_tree()
        self._update_ports_tree()
        self._update_findings_tree()
        self._update_stats_label()
        self._log(f"[+] Loaded session: {len(hosts)} host(s), "
                  f"{len(ports)} port(s), {len(findings)} finding(s) "
                  f"from {path}")

    def on_html_report(self) -> None:
        if not self._discovered and not self._scan_results:
            messagebox.showinfo("No Data", "Nothing to report yet.")
            return
        save_dir = Path(self.save_dir_var.get())
        try:
            save_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            messagebox.showerror("Error", f"Cannot create save dir: {exc}")
            return
        path = save_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        try:
            self._save_results_to(str(path))
            self._log(f"[+] HTML report written: {path}")
            webbrowser.open(path.as_uri())
        except Exception as exc:
            save_crash_report(exc, "html_report")
            messagebox.showerror("Report Failed", f"Error: {exc}")

    def on_clear_results(self) -> None:
        if self._worker and self._worker.is_alive():
            messagebox.showinfo("Busy",
                                "Wait for the current operation to finish.")
            return
        self._discovered = []
        self._scan_results = []
        self._findings = []
        self._previous_hosts = []
        self.host_combo.configure(values=[])
        self.host_var.set("")
        self._update_hosts_tree()
        self._update_ports_tree()
        self._update_findings_tree()
        self._update_stats_label()
        self._log("[*] All results cleared.")

    def on_diff(self) -> None:
        if not self._previous_hosts:
            messagebox.showinfo("Diff", "No previous scan to compare against.")
            return
        d = diff_hosts(self._previous_hosts, self._discovered)
        self._log("")
        self._log("=" * 60)
        self._log("DIFF vs PREVIOUS SCAN")
        self._log("=" * 60)
        self._log(f"  Added:   {', '.join(d['added']) or '(none)'}")
        self._log(f"  Removed: {', '.join(d['removed']) or '(none)'}")
        self._log(f"  Changed: {', '.join(d['changed']) or '(none)'}")
        self._log("")

    def on_toggle_monitor(self) -> None:
        if self.monitor_var.get():
            self.monitor_var.set(False)
            if self._monitor_after is not None:
                with contextlib.suppress(Exception):
                    self.root.after_cancel(self._monitor_after)
                self._monitor_after = None
            self._log("[*] Monitor mode stopped.")
            self.status_var.set("Monitor stopped")
            return
        interval = simpledialog.askfloat(
            "Monitor Mode",
            "Seconds between automatic discovery sweeps:",
            initialvalue=self.monitor_interval_var.get(),
            minvalue=5.0, maxvalue=3600.0, parent=self.root)
        if interval is None:
            return
        self.monitor_interval_var.set(float(interval))
        self.monitor_var.set(True)
        self._log(f"[+] Monitor mode ON — sweeping every {interval:.0f}s.")
        self.status_var.set("Monitor running")
        self._schedule_monitor()

    def _schedule_monitor(self) -> None:
        if not self.monitor_var.get():
            return
        ms = int(max(1.0, self.monitor_interval_var.get()) * 1000)
        self._monitor_after = self.root.after(ms, self._monitor_tick)

    def _monitor_tick(self) -> None:
        self._monitor_after = None
        if not self.monitor_var.get():
            return
        if self._worker and self._worker.is_alive():
            self._log("[*] Monitor: worker busy — sweep skipped.")
            self._schedule_monitor()
            return
        cidr = self.network_var.get().strip()
        net = validate_cidr(cidr)
        if net is None or (not self.allow_public_var.get()
                           and not is_private_ip(str(net.network_address))):
            self._log("[!] Monitor: invalid or blocked target — stopping.")
            self.monitor_var.set(False)
            return

        def job() -> None:
            hosts = self.scanner.discover_hosts(
                str(net), log=self._log, stop_event=self._stop_event,
                ping_timeout=self.timeout_var.get(),
                max_workers=self.threads_var.get(),
                use_arp=self.use_arp_var.get(),
                use_tcp_ping=self.use_tcp_ping_var.get(),
                resolve_hostnames=self.resolve_dns_var.get(),
                stealth_delay=self.stealth_var.get(),
                rate=self.rate_var.get())
            old = self._discovered
            self._previous_hosts = list(old)
            self._discovered = hosts
            stamp = datetime.now().strftime("%H:%M:%S")
            if old:
                d = diff_hosts(old, hosts)
                if d["added"] or d["removed"] or d["changed"]:
                    self._log(f"[MONITOR {stamp}] changes detected:")
                    if d["added"]:
                        self._log(f"    + added:   {', '.join(d['added'])}")
                    if d["removed"]:
                        self._log(f"    - removed: {', '.join(d['removed'])}")
                    if d["changed"]:
                        self._log(f"    ~ changed: {', '.join(d['changed'])}")
                else:
                    self._log(f"[MONITOR {stamp}] no changes "
                              f"({len(hosts)} hosts).")
            else:
                self._log(f"[MONITOR {stamp}] {len(hosts)} host(s) found.")
            self._ui(lambda: (self._update_hosts_tree(),
                              self._update_stats_label()))

        self._run_in_background(job, f"Monitor sweep of {net} …")
        self._schedule_monitor()

    def on_import_nmap(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Nmap XML",
            filetypes=[("Nmap XML", "*.xml"), ("All files", "*.*")])
        if not path:
            return
        try:
            hosts, ports = import_nmap_xml(path)
        except Exception as exc:
            messagebox.showerror("Import Failed", f"Error: {exc}")
            return
        self._discovered = hosts
        self._scan_results = ports
        self._findings = []
        for h in hosts:
            h.findings = NetworkScanner.analyze_findings(h)
            self._findings.extend(h.findings)
        self.host_combo.configure(values=[h.ip for h in hosts])
        self._update_hosts_tree()
        self._update_ports_tree()
        self._update_findings_tree()
        self._log(f"[+] Imported {len(hosts)} host(s), {len(ports)} port(s) from {path}")

    def on_full_scan(self) -> None:
        cidr = self.network_var.get().strip()
        net = self._require_private_network(cidr)
        if net is None:
            return
        if not self._confirm_scan(
            f"Full scan of {net}?\n\nThis will:\n"
            "• Discover live hosts\n• Scan common ports on each host\n"
            "• Grab banners\n• Detect OS\n• Generate findings\n\n"
            "This may take a while."):
            return

        def job() -> None:
            t0 = time.time()
            self._log("")
            self._log("=" * 60)
            self._log("FULL SCAN STARTED")
            self._log("=" * 60)
            self._log("")
            self._log("[PHASE 1] Host Discovery")
            self._log("-" * 40)
            hosts = self.scanner.discover_hosts(
                str(net), log=self._log, stop_event=self._stop_event,
                ping_timeout=self.timeout_var.get(),
                max_workers=self.threads_var.get(),
                use_arp=self.use_arp_var.get(),
                use_tcp_ping=self.use_tcp_ping_var.get(),
                resolve_hostnames=self.resolve_dns_var.get(),
                stealth_delay=self.stealth_var.get(),
                rate=self.rate_var.get())
            self._previous_hosts = list(self._discovered)
            self._discovered = hosts
            self._scan_results = []
            if not hosts:
                self._log("[!] No hosts found. Aborting full scan.")
                return
            self._log("")
            self._log(f"[+] Found {len(hosts)} host(s)")
            self._log("")
            self._log("[PHASE 2] Port Scanning")
            self._log("-" * 40)
            for i, host in enumerate(hosts):
                if self._stop_event.is_set():
                    self._log("[!] Full scan aborted.")
                    break
                self._ui(lambda i=i, h=host: self.progress_label.configure(
                    text=f"{i + 1}/{len(hosts)}: {h.ip}"))
                self._log(f"[*] Scanning {host.ip} ({i + 1}/{len(hosts)}) …")
                results = self.scanner.scan_ports(
                    host.ip, NetworkScanner.TOP_100_PORTS,
                    log=lambda x: None, stop_event=self._stop_event,
                    timeout=self.timeout_var.get(),
                    max_workers=self.threads_var.get(),
                    rate=self.rate_var.get())
                host.open_ports = [r.port for r in results]
                host.services = {r.port: (r.service or "") for r in results}
                if results:
                    self._log(f"  [+] {len(results)} open port(s): "
                              f"{', '.join(str(r.port) for r in results[:10])}"
                              f"{'...' if len(results) > 10 else ''}")
                else:
                    self._log("  [-] No open ports found")
                self._scan_results.extend(results)
            self._log("")
            self._log("[PHASE 3] Banner Grabbing")
            self._log("-" * 40)
            all_banner_ports: List[Tuple[str, int]] = []
            for host in hosts:
                for port in host.open_ports[:30]:
                    all_banner_ports.append((host.ip, port))
            def grab_one(ip: str, port: int) -> Optional[Tuple[str, int, str, Optional[str]]]:
                if self._stop_event.is_set():
                    return None
                banner = self.scanner.grab_banner(ip, port)
                if banner:
                    svc = self.scanner.identify_service(port, banner)
                    ver = self.scanner.extract_version(svc, banner)
                    return ip, port, banner, ver
                return None
            ex = CancellableExecutor(max_workers=min(64, self.threads_var.get()))
            try:
                for fut in [ex.submit(grab_one, ip, p) for ip, p in all_banner_ports]:
                    if self._stop_event.is_set():
                        break
                    try:
                        r = fut.result(timeout=DEFAULT_BANNER_TIMEOUT + 2)
                    except Exception:
                        continue
                    if r is None:
                        continue
                    ip, port, banner, ver = r
                    host = next((h for h in hosts if h.ip == ip), None)
                    if host:
                        host.banners[port] = banner
                        if ver:
                            host.versions[port] = ver
                    for pr in self._scan_results:
                        if pr.host == ip and pr.port == port:
                            pr.banner = banner
                            if ver:
                                pr.version = ver
                            break
            finally:
                ex.shutdown(wait=False)
            self._log("")
            self._log("[PHASE 4] OS Detection")
            self._log("-" * 40)
            for host in hosts:
                if self._stop_event.is_set():
                    break
                os_guess = self.scanner.os_fingerprint(host.ip)
                host.os_guess = os_guess
                if os_guess:
                    self._log(f"  {host.ip}: {os_guess}")
            self._findings = []
            for host in hosts:
                host.device_type = guess_device_type(
                    host.hostname, host.mac, host.open_ports)
                host.findings = NetworkScanner.analyze_findings(host)
                self._findings.extend(host.findings)
            self._log("")
            self._log("=" * 60)
            self._log("FULL SCAN COMPLETE")
            self._log("=" * 60)
            self._log("")
            self._log("SUMMARY")
            self._log("-" * 40)
            self._log(f"Hosts discovered: {len(hosts)}")
            self._log(f"Total open ports: {len(self._scan_results)}")
            self._log(f"Findings: {len(self._findings)}")
            self._log("")
            self._log(f"{'IP':<16} {'DEVICE':<16} {'OS':<14} PORTS")
            self._log("-" * 70)
            for h in hosts:
                ports_str = ", ".join(str(p) for p in h.open_ports[:8])
                if len(h.open_ports) > 8:
                    ports_str += f" (+{len(h.open_ports) - 8})"
                self._log(f"{h.ip:<16} {(h.device_type or '-'):<16} "
                          f"{(h.os_guess or '-'):<14} {ports_str or '-'}")
            self._log("")
            def update() -> None:
                self.host_combo.configure(values=[h.ip for h in hosts])
                if hosts and not self.host_var.get():
                    self.host_var.set(hosts[0].ip)
                self._update_hosts_tree()
                self._update_ports_tree()
                self._update_findings_tree()
                self._update_stats_label()
            self._ui(update)
            append_history({
                "action": "full_scan", "target": str(net),
                "hosts_up": len(hosts), "open_ports": len(self._scan_results),
                "findings": len(self._findings),
                "duration": round(time.time() - t0, 2),
                "timestamp": datetime.now().isoformat(),
            })
            audit("full_scan", target=str(net), hosts=len(hosts),
                  findings=len(self._findings))
            with contextlib.suppress(Exception):
                save_session(SESSION_FILE, self._discovered,
                             self._scan_results, self._findings)
            if self.auto_save_var.get():
                self._save_results()
        self._run_in_background(job, f"Full scan of {net} …")

    def on_stop(self) -> None:
        if self._worker and self._worker.is_alive():
            self._stop_event.set()
            self._log("[!] Stop requested — waiting for workers to finish …")
            self.status_var.set("Stopping …")

    def on_clear(self) -> None:
        self.output.configure(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.configure(state=tk.DISABLED)
        self.status_var.set("Output cleared.")

    def _apply_filter(self) -> None:
        self._update_hosts_tree()
        self._update_ports_tree()
        self._update_dashboard()

    def _matches_filter(self, values: Sequence[Any]) -> bool:
        f = self.filter_var.get().strip().lower()
        if not f:
            return True
        return any(f in str(v).lower() for v in values)

    def on_export(self) -> None:
        if not self._discovered and not self._scan_results:
            messagebox.showinfo("No Data", "No scan results to export.")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"), ("CSV files", "*.csv"),
                ("XML files", "*.xml"), ("Markdown files", "*.md"),
                ("HTML files", "*.html"), ("DOT files", "*.dot"),
                ("GraphML files", "*.graphml"), ("Text files", "*.txt"),
                ("All files", "*.*")],
            initialdir=self.save_dir_var.get(),
            initialfile=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        if not file_path:
            return
        try:
            self._save_results_to(file_path)
            self._log(f"[+] Results exported to {file_path}")
            messagebox.showinfo("Export Complete", f"Results saved to:\n{file_path}")
        except Exception as exc:
            save_crash_report(exc, "export")
            messagebox.showerror("Export Failed", f"Error: {exc}")

    def _save_results(self) -> None:
        save_dir = Path(self.save_dir_var.get())
        try:
            save_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            self._log(f"[!] Cannot create save dir: {exc}")
            return
        filename = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        file_path = save_dir / filename
        try:
            self._save_results_to(str(file_path))
            self._log(f"[+] Auto-saved to {file_path}")
        except Exception as exc:
            self._log(f"[!] Auto-save failed: {exc}")

    def _save_results_to(self, file_path: str) -> None:
        ext = Path(file_path).suffix.lower()
        data = {
            "scan_time": datetime.now().isoformat(),
            "app_version": APP_VERSION,
            "hosts": [h.to_dict() for h in self._discovered],
            "ports": [p.to_dict() for p in self._scan_results],
            "findings": [f.to_dict() for f in self._findings],
            "stats": self.scanner.stats.to_dict(),
        }
        if ext == ".json":
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        elif ext == ".csv":
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["HOSTS"])
                w.writerow(["IP", "MAC", "Vendor", "Hostname", "Device",
                            "OS", "Open Ports"])
                for h in self._discovered:
                    w.writerow([
                        h.ip, h.mac or "", h.vendor or "", h.hostname or "",
                        h.device_type or "", h.os_guess or "",
                        ",".join(str(p) for p in h.open_ports)])
                w.writerow([])
                w.writerow(["PORTS"])
                w.writerow(["Host", "Port", "Service", "Version", "State", "Banner"])
                for p in self._scan_results:
                    w.writerow([p.host, p.port, p.service or "",
                                p.version or "", p.state, (p.banner or "")[:500]])
                w.writerow([])
                w.writerow(["FINDINGS"])
                w.writerow(["Severity", "Host", "Port", "Title", "Detail"])
                for fi in self._findings:
                    w.writerow([fi.severity.value, fi.host, fi.port or "",
                                fi.title, fi.detail])
        elif ext == ".xml":
            self._export_xml(file_path, data)
        elif ext == ".md":
            self._export_markdown(file_path, data)
        elif ext == ".html":
            self._export_html(file_path, data)
        elif ext == ".dot":
            self._export_dot(file_path)
        elif ext == ".graphml":
            self._export_graphml(file_path)
        else:
            self._export_text(file_path, data)

    def _export_xml(self, file_path: str, data: Dict[str, Any]) -> None:
        root = ET.Element("NetworkScan")
        root.set("app", APP_NAME)
        root.set("version", APP_VERSION)
        root.set("time", data["scan_time"])
        hosts_el = ET.SubElement(root, "Hosts")
        for h in self._discovered:
            h_el = ET.SubElement(hosts_el, "Host")
            h_el.set("ip", h.ip)
            for attr in ("mac", "vendor", "hostname", "device_type", "os_guess"):
                v = getattr(h, attr)
                if v:
                    ET.SubElement(h_el, attr).text = str(v)
            ports_el = ET.SubElement(h_el, "OpenPorts")
            for p in h.open_ports:
                ET.SubElement(ports_el, "Port").text = str(p)
        ports_el = ET.SubElement(root, "Ports")
        for p in self._scan_results:
            p_el = ET.SubElement(ports_el, "Port")
            p_el.set("host", p.host)
            p_el.set("number", str(p.port))
            p_el.set("state", p.state)
            p_el.set("protocol", p.protocol)
            if p.service:
                ET.SubElement(p_el, "Service").text = p.service
            if p.version:
                ET.SubElement(p_el, "Version").text = p.version
            if p.banner:
                ET.SubElement(p_el, "Banner").text = p.banner
        findings_el = ET.SubElement(root, "Findings")
        for fi in self._findings:
            f_el = ET.SubElement(findings_el, "Finding")
            f_el.set("severity", fi.severity.value)
            f_el.set("host", fi.host)
            if fi.port is not None:
                f_el.set("port", str(fi.port))
            ET.SubElement(f_el, "Title").text = fi.title
            ET.SubElement(f_el, "Detail").text = fi.detail
        tree = ET.ElementTree(root)
        with contextlib.suppress(Exception):
            ET.indent(tree, space="  ")  # type: ignore[attr-defined]
        tree.write(file_path, encoding="utf-8", xml_declaration=True)

    def _export_markdown(self, file_path: str, data: Dict[str, Any]) -> None:
        L: List[str] = []
        L.append(f"# {APP_NAME} v{APP_VERSION} — Scan Report\n")
        L.append(f"**Scan time:** {data['scan_time']}\n")
        L.append(f"**Stats:** {data['stats']}\n")
        L.append("## Hosts\n")
        L.append("| IP | MAC | Vendor | Hostname | Device | OS | Ports |")
        L.append("|---|---|---|---|---|---|---|")
        for h in self._discovered:
            ports_str = ", ".join(str(p) for p in h.open_ports[:12])
            if len(h.open_ports) > 12:
                ports_str += f" (+{len(h.open_ports) - 12})"
            L.append(f"| {h.ip} | {h.mac or ''} | {h.vendor or ''} | "
                     f"{h.hostname or ''} | {h.device_type or ''} | "
                     f"{h.os_guess or ''} | {ports_str} |")
        L.append("\n## Ports\n")
        L.append("| Host | Port | Service | Version | State | Banner |")
        L.append("|---|---|---|---|---|---|")
        for p in self._scan_results:
            banner = (p.banner or "").replace("|", "\\|")[:120]
            L.append(f"| {p.host} | {p.port} | {p.service or ''} | "
                     f"{p.version or ''} | {p.state} | {banner} |")
        if self._findings:
            L.append("\n## Findings\n")
            for fi in sorted(self._findings, key=lambda x: -x.severity.rank):
                L.append(f"### [{fi.severity.value.upper()}] {fi.title}")
                L.append(f"- **Host:** {fi.host}")
                if fi.port is not None:
                    L.append(f"- **Port:** {fi.port}")
                L.append(f"- {fi.detail}\n")
        Path(file_path).write_text("\n".join(L), encoding="utf-8")

    def _export_html(self, file_path: str, data: Dict[str, Any]) -> None:
        parts: List[str] = []
        parts.append("<!DOCTYPE html><html><head><meta charset='utf-8'>")
        parts.append(f"<title>{_html.escape(APP_NAME)} Report</title>")
        parts.append(
            "<style>body{font-family:Arial,sans-serif;margin:20px;}"
            "table{border-collapse:collapse;width:100%;margin:10px 0;}"
            "th,td{border:1px solid #ccc;padding:4px 8px;font-size:13px;}"
            "th{background:#eee;}tr:nth-child(even){background:#f9f9f9;}"
            ".critical{color:#b00;font-weight:bold;}"
            ".high{color:#e67e22;font-weight:bold;}"
            ".medium{color:#b8860b;}.low{color:#2980b9;}.info{color:#333;}"
            "</style>")
        parts.append("</head><body>")
        parts.append(f"<h1>{_html.escape(APP_NAME)} v{APP_VERSION} — Report</h1>")
        parts.append(f"<p><b>Scan time:</b> {_html.escape(data['scan_time'])}</p>")
        parts.append(f"<p><b>Stats:</b> {_html.escape(str(data['stats']))}</p>")
        parts.append("<h2>Hosts</h2><table>")
        parts.append("<tr><th>IP</th><th>MAC</th><th>Vendor</th>"
                     "<th>Hostname</th><th>Device</th><th>OS</th><th>Ports</th></tr>")
        for h in self._discovered:
            parts.append(
                f"<tr><td>{_html.escape(h.ip)}</td>"
                f"<td>{_html.escape(h.mac or '')}</td>"
                f"<td>{_html.escape(h.vendor or '')}</td>"
                f"<td>{_html.escape(h.hostname or '')}</td>"
                f"<td>{_html.escape(h.device_type or '')}</td>"
                f"<td>{_html.escape(h.os_guess or '')}</td>"
                f"<td>{_html.escape(', '.join(str(p) for p in h.open_ports))}</td></tr>")
        parts.append("</table>")
        parts.append("<h2>Ports</h2><table>")
        parts.append("<tr><th>Host</th><th>Port</th><th>Service</th>"
                     "<th>Version</th><th>State</th><th>Banner</th></tr>")
        for p in self._scan_results:
            parts.append(
                f"<tr><td>{_html.escape(p.host)}</td><td>{p.port}</td>"
                f"<td>{_html.escape(p.service or '')}</td>"
                f"<td>{_html.escape(p.version or '')}</td>"
                f"<td>{_html.escape(p.state)}</td>"
                f"<td>{_html.escape((p.banner or '')[:200])}</td></tr>")
        parts.append("</table>")
        if self._findings:
            parts.append("<h2>Findings</h2><table>")
            parts.append("<tr><th>Severity</th><th>Host</th><th>Port</th>"
                         "<th>Title</th><th>Detail</th></tr>")
            for fi in sorted(self._findings, key=lambda x: -x.severity.rank):
                parts.append(
                    f"<tr><td class='{fi.severity.value}'>"
                    f"{fi.severity.value.upper()}</td>"
                    f"<td>{_html.escape(fi.host)}</td>"
                    f"<td>{fi.port or ''}</td>"
                    f"<td>{_html.escape(fi.title)}</td>"
                    f"<td>{_html.escape(fi.detail)}</td></tr>")
            parts.append("</table>")
        parts.append("</body></html>")
        Path(file_path).write_text("\n".join(parts), encoding="utf-8")

    def _export_dot(self, file_path: str) -> None:
        lines = ["graph network {", "  layout=neato;", "  overlap=false;",
                 '  node [shape=box, style=rounded, fontname="Arial"];']
        for h in self._discovered:
            label = h.ip
            if h.hostname:
                label += f"\\n{h.hostname}"
            if h.device_type and h.device_type != "Unknown":
                label += f"\\n[{h.device_type}]"
            color = "lightblue"
            if h.findings:
                if any(f.severity == Severity.CRITICAL for f in h.findings):
                    color = "red"
                elif any(f.severity == Severity.HIGH for f in h.findings):
                    color = "orange"
                elif any(f.severity == Severity.MEDIUM for f in h.findings):
                    color = "yellow"
            lines.append(f'  "{h.ip}" [label="{label}", fillcolor="{color}", '
                         f'style="filled,rounded"];')
        subnets: Dict[str, List[str]] = defaultdict(list)
        for h in self._discovered:
            try:
                net = ipaddress.ip_network(f"{h.ip}/24", strict=False)
                subnets[str(net)].append(h.ip)
            except ValueError:
                pass
        for subnet, ips in subnets.items():
            if len(ips) > 1:
                lines.append(f'  subgraph "cluster_{subnet.replace(".", "_").replace("/", "_")}" {{')
                lines.append(f'    label="{subnet}";')
                for ip in ips:
                    lines.append(f'    "{ip}";')
                lines.append("  }")
        lines.append("}")
        Path(file_path).write_text("\n".join(lines), encoding="utf-8")

    def _export_graphml(self, file_path: str) -> None:
        root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
        for key_id, name, ktype in (
            ("ip", "ip", "string"), ("hostname", "hostname", "string"),
            ("device", "device", "string"), ("os", "os", "string"),
            ("ports", "ports", "string"), ("findings", "findings", "string"),
        ):
            key = ET.SubElement(root, "key")
            key.set("id", key_id)
            key.set("for", "node")
            key.set("attr.name", name)
            key.set("attr.type", ktype)
        graph = ET.SubElement(root, "graph", edgedefault="undirected")
        for h in self._discovered:
            node = ET.SubElement(graph, "node")
            node.set("id", h.ip)
            for kid, val in (("ip", h.ip), ("hostname", h.hostname or ""),
                             ("device", h.device_type or ""),
                             ("os", h.os_guess or ""),
                             ("ports", ",".join(str(p) for p in h.open_ports)),
                             ("findings", str(len(h.findings)))):
                d = ET.SubElement(node, "data")
                d.set("key", kid)
                d.text = val
        tree = ET.ElementTree(root)
        with contextlib.suppress(Exception):
            ET.indent(tree, space="  ")  # type: ignore[attr-defined]
        tree.write(file_path, encoding="utf-8", xml_declaration=True)

    def _export_text(self, file_path: str, data: Dict[str, Any]) -> None:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(f"{APP_NAME} v{APP_VERSION}\n")
            f.write(f"Scan Time: {data['scan_time']}\n")
            f.write("=" * 60 + "\n\n")
            f.write("DISCOVERED HOSTS\n")
            f.write("-" * 60 + "\n")
            for h in self._discovered:
                f.write(f"IP:       {h.ip}\n")
                f.write(f"MAC:      {h.mac or 'N/A'}\n")
                f.write(f"Vendor:   {h.vendor or 'N/A'}\n")
                f.write(f"Hostname: {h.hostname or 'N/A'}\n")
                f.write(f"Device:   {h.device_type or 'N/A'}\n")
                f.write(f"OS:       {h.os_guess or 'N/A'}\n")
                f.write(f"Ports:    {', '.join(str(p) for p in h.open_ports) or 'None'}\n\n")
            f.write("\nOPEN PORTS\n")
            f.write("-" * 60 + "\n")
            for p in self._scan_results:
                f.write(f"{p.host}:{p.port} - {p.service or 'unknown'} ({p.state})\n")
                if p.version:
                    f.write(f"  Version: {p.version}\n")
                if p.banner:
                    f.write(f"  Banner: {p.banner}\n")
            if self._findings:
                f.write("\nFINDINGS\n")
                f.write("-" * 60 + "\n")
                for fi in sorted(self._findings, key=lambda x: -x.severity.rank):
                    f.write(f"[{fi.severity.value.upper()}] {fi.host}:{fi.port or ''} "
                            f"- {fi.title}\n  {fi.detail}\n")

    def _render_limited_warning(self, total: int, shown: int) -> None:
        if total > shown:
            self._log(f"[!] Showing {shown} of {total} rows (performance cap). "
                      "Use filter to narrow results.")

    def _update_hosts_tree(self) -> None:
        for item in self.hosts_tree.get_children():
            self.hosts_tree.delete(item)
        shown = 0
        total = len(self._discovered)
        for h in self._discovered:
            ports_str = ", ".join(str(p) for p in h.open_ports[:6])
            if len(h.open_ports) > 6:
                ports_str += f" (+{len(h.open_ports) - 6})"
            values = (
                h.ip, format_mac(h.mac) if h.mac else "-",
                h.vendor or "-", h.hostname or "-",
                h.device_type or "-", h.os_guess or "-",
                ports_str or "-")
            if not self._matches_filter(values):
                continue
            self.hosts_tree.insert("", tk.END, values=values)
            shown += 1
            if shown >= self.MAX_ROWS_RENDER:
                self._render_limited_warning(total, shown)
                break
        self._update_dashboard()

    def _update_ports_tree(self) -> None:
        for item in self.ports_tree.get_children():
            self.ports_tree.delete(item)
        shown = 0
        total = len(self._scan_results)
        for p in self._scan_results:
            banner = p.banner or ""
            if len(banner) > 120:
                banner = banner[:117] + "..."
            values = (p.host, p.port, p.service or "-", p.version or "-",
                      p.state, banner or "-")
            if not self._matches_filter(values):
                continue
            self.ports_tree.insert("", tk.END, values=values)
            shown += 1
            if shown >= self.MAX_ROWS_RENDER:
                self._render_limited_warning(total, shown)
                break

    def _update_findings_tree(self) -> None:
        for item in self.findings_tree.get_children():
            self.findings_tree.delete(item)
        for f in sorted(self._findings, key=lambda x: -x.severity.rank):
            self.findings_tree.insert(
                "", tk.END,
                values=(f.severity.value.upper(), f.host,
                        f.port if f.port is not None else "-",
                        f.title, f.detail),
                tags=(f.severity.value,))
        self._update_dashboard()

    def _build_dashboard_tab(self, parent: "ttk.Frame") -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(bar, text="Refresh",
                   command=self._update_dashboard).pack(side=tk.LEFT)
        self.dash_summary_var = tk.StringVar(value="")
        ttk.Label(bar, textvariable=self.dash_summary_var).pack(
            side=tk.LEFT, padx=12)
        self.dash_canvas = tk.Canvas(parent, background="#0d1117",
                                     highlightthickness=0, height=520)
        self.dash_canvas.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _update_dashboard(self) -> None:
        canvas = getattr(self, "dash_canvas", None)
        if canvas is None:
            return
        try:
            canvas.delete("all")
        except tk.TclError:
            return
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in self._findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        services: Dict[str, int] = defaultdict(int)
        for p in self._scan_results:
            services[p.service or "unknown"] += 1
        hosts = len(self._discovered)
        open_ports = len(self._scan_results)
        if hasattr(self, "dash_summary_var"):
            self.dash_summary_var.set(
                f"hosts: {hosts}   open ports: {open_ports}   "
                f"findings: {len(self._findings)}   "
                f"critical: {counts.get('critical', 0)}")
        try:
            w = max(int(canvas.winfo_width()), 400)
            h = max(int(canvas.winfo_height()), 200)
        except tk.TclError:
            return
        colors = {"critical": "#ff6b6b", "high": "#ff9f43",
                  "medium": "#feca57", "low": "#54a0ff", "info": "#8b949e"}
        font = safe_font()
        canvas.create_text(20, 18, anchor="w", fill="#c9d1d9",
                           font=(font[0], 11, "bold"),
                           text="Findings by severity")
        max_sev = max(counts.values()) or 1
        bar_max_w = max(w // 2 - 80, 40)
        y = 44
        for sev in ("critical", "high", "medium", "low", "info"):
            val = counts.get(sev, 0)
            bw = int(bar_max_w * (val / max_sev))
            canvas.create_text(20, y + 8, anchor="w", fill="#c9d1d9",
                               font=font, text=f"{sev:<10}")
            canvas.create_rectangle(110, y, 110 + max(bw, 2), y + 16,
                                    fill=colors[sev], width=0)
            canvas.create_text(118 + max(bw, 2), y + 8, anchor="w",
                               fill="#c9d1d9", font=font, text=str(val))
            y += 26
        canvas.create_text(w // 2 + 10, 18, anchor="w", fill="#c9d1d9",
                           font=(font[0], 11, "bold"),
                           text="Top open services")
        top = sorted(services.items(), key=lambda kv: -kv[1])[:8]
        if not top:
            canvas.create_text(w // 2 + 10, 48, anchor="w", fill="#8b949e",
                               font=font, text="(no port data yet)")
        max_svc = top[0][1] if top else 1
        y = 44
        svc_w = max(w // 2 - 120, 40)
        for name, val in top:
            bw = int(svc_w * (val / max_svc))
            canvas.create_text(w // 2 + 10, y + 8, anchor="w", fill="#c9d1d9",
                               font=font, text=f"{name[:18]:<18}")
            canvas.create_rectangle(w // 2 + 150, y,
                                    w // 2 + 150 + max(bw, 2), y + 16,
                                    fill="#58a6ff", width=0)
            canvas.create_text(w // 2 + 158 + max(bw, 2), y + 8, anchor="w",
                               fill="#c9d1d9", font=font, text=str(val))
            y += 26
        canvas.create_text(20, h - 16, anchor="w", fill="#8b949e", font=font,
                           text="Refresh after each scan — detailed rows live "
                                "in the Results and Findings tabs.")

    def _update_stats_label(self) -> None:
        s = self.scanner.stats
        self.stats_var.set(
            f"hosts up: {len(self._discovered)} | "
            f"ports open: {len(self._scan_results)} | "
            f"findings: {len(self._findings)} | "
            f"duration: {s.duration:.1f}s")

    def on_quit(self) -> None:
        if self._worker and self._worker.is_alive():
            if not messagebox.askyesno(
                "Scan in Progress",
                "A scan is currently running. Quit anyway?"):
                return
            self._stop_event.set()
            with contextlib.suppress(Exception):
                self._worker.join(timeout=2.0)
        with contextlib.suppress(Exception):
            self._save_settings()
        with contextlib.suppress(Exception):
            self.root.quit()
            self.root.destroy()

def _mongo_ismaster() -> bytes:
    req = b"{isMaster:1}\x00"
    coll = b"admin.$cmd\x00"
    body = struct.pack("<i", 0) + coll + struct.pack("<ii", 0, 1) + req
    total = 16 + len(body)
    return (struct.pack("<iiii", total, random.randint(0, 0x7FFFFFFF), 0,
                        2004) + body)

def run_service_checks(
    host: str,
    ports: Sequence[int],
    log: Optional[Callable[[str], None]] = None,
    stop_event: Optional[threading.Event] = None,
    timeout: float = DEFAULT_PORT_TIMEOUT,
) -> Tuple[List[Dict[str, Any]], List[Finding]]:
    results: List[Dict[str, Any]] = []
    findings: List[Finding] = []

    def note(port: int, check: str, detail: str, risk: bool = False) -> None:
        results.append({"port": port, "check": check, "detail": detail,
                        "risk": risk})
        if log:
            log(f"  {'[+]' if risk else '[-]'} {port}/{check}: {detail}")

    def tcp(port: int, payload: Optional[bytes],
            read_len: int = 4096) -> Optional[bytes]:
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                if payload:
                    try:
                        s.sendall(payload)
                    except OSError:
                        return None
                chunks: List[bytes] = []
                total = 0
                deadline = time.monotonic() + timeout
                while total < read_len and time.monotonic() < deadline:
                    try:
                        data = s.recv(min(4096, read_len - total))
                    except socket.timeout:
                        break
                    if not data:
                        break
                    chunks.append(data)
                    total += len(data)
                return b"".join(chunks)
        except OSError:
            return None

    for port in ports:
        if stop_event is not None and stop_event.is_set():
            break
        try:
            if port == 21:
                resp = tcp(21, b"USER anonymous\r\n", 512)
                if resp and (b"230" in resp or b"331" in resp):
                    anon = b"230" in resp
                    note(21, "ftp-anon",
                         "Anonymous FTP login accepted" if anon else
                         "FTP accepts credentials (331) — anonymous may work",
                         risk=anon)
                    if anon:
                        findings.append(Finding(
                            host=host, port=21,
                            title="Anonymous FTP login allowed",
                            detail="FTP server accepts anonymous logins — "
                                   "data exposure risk.",
                            severity=Severity.MEDIUM))
                continue
            if port in (25, 587):
                resp = tcp(port, b"VRFY root\r\n", 512)
                if resp and (b"252" in resp or b"250 " in resp):
                    note(port, "smtp-vrfy",
                         "VRFY accepted — SMTP user enumeration possible",
                         risk=True)
                    findings.append(Finding(
                        host=host, port=port,
                        title="SMTP user enumeration (VRFY)",
                        detail="VRFY discloses valid users — disable VRFY/EXPN.",
                        severity=Severity.LOW))
                continue
            if port == 6379:
                resp = tcp(6379, b"PING\r\n", 512)
                if resp and (b"+PONG" in resp or b"-NOAUTH" in resp):
                    unauth = b"+PONG" in resp
                    ver = ""
                    if unauth:
                        info = tcp(6379, b"INFO server\r\n", 2048) or b""
                        m = re.search(rb"redis_version:(\S+)", info)
                        if m:
                            ver = m.group(1).decode("ascii", "replace")
                    note(6379, "redis-auth",
                         ("Redis unauthenticated"
                          + (f" (v{ver})" if ver else "")
                          if unauth else "Redis requires AUTH"),
                         risk=unauth)
                    if unauth:
                        findings.append(Finding(
                            host=host, port=6379,
                            title="Redis unauthenticated access",
                            detail="PING/INFO succeed without credentials — "
                                   "data theft & RCE risk.",
                            severity=Severity.CRITICAL))
                continue
            if port == 11211:
                resp = tcp(11211, b"stats\r\n", 1024)
                if resp and b"VERSION" in resp:
                    m = re.search(rb"VERSION\s+(\S+)", resp)
                    ver = m.group(1).decode("ascii", "replace") if m else "?"
                    note(11211, "memcached-stats",
                         f"Memcached stats exposed (v{ver})", risk=True)
                    findings.append(Finding(
                        host=host, port=11211,
                        title="Memcached exposed",
                        detail="Statistics readable without auth — amplification "
                               "DDoS & info-leak risk.",
                        severity=Severity.HIGH))
                continue
            if port == 2375:
                pr = HTTPProber.probe(host, 2375, use_tls=False,
                                      timeout=timeout, path="/version")
                if pr and '"Version"' in (pr.get("body_preview") or ""):
                    note(2375, "docker-api",
                         "Docker API answers without authentication",
                         risk=True)
                    findings.append(Finding(
                        host=host, port=2375,
                        title="Docker API unauthenticated",
                        detail="Engine API reachable without auth — trivial "
                               "host takeover.",
                        severity=Severity.CRITICAL))
                continue
            if port == 9200:
                pr = HTTPProber.probe(host, 9200, use_tls=False,
                                      timeout=timeout,
                                      path="/_cluster/health")
                if pr and '"status"' in (pr.get("body_preview") or ""):
                    note(9200, "es-health",
                         "Cluster health readable without auth", risk=True)
                    findings.append(Finding(
                        host=host, port=9200,
                        title="Elasticsearch unauthenticated",
                        detail="Cluster state/data readable without auth.",
                        severity=Severity.HIGH))
                continue
            if port == 27017:
                resp = tcp(27017, _mongo_ismaster(), 4096)
                if resp and b"ismaster" in resp.lower():
                    note(27017, "mongo-ismaster",
                         "isMaster handshake answered (build info disclosed)")
                continue
            if port == 389:
                req = _ber_tlv(
                    0x30,
                    _ber_tlv(0x02, b"\x01") +
                    _ber_tlv(0x60, _ber_tlv(0x02, b"\x03") +
                             _ber_tlv(0x04, b"") + _ber_tlv(0x80, b"")))
                resp = tcp(389, req, 512)
                if resp and b"\x0a\x01\x00" in resp:
                    note(389, "ldap-anon",
                         "LDAP anonymous bind allowed", risk=True)
                    findings.append(Finding(
                        host=host, port=389,
                        title="LDAP anonymous bind allowed",
                        detail="Directory data may be readable anonymously.",
                        severity=Severity.MEDIUM))
                continue
            if port == 3389:
                x224 = (b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00"
                        b"\x01\x00\x08\x00\x03\x00\x00\x00")
                resp = tcp(3389, x224, 64)
                if resp and resp.startswith(b"\x03\x00"):
                    note(3389, "rdp", "RDP confirmed via X.224 handshake")
                continue
            if port == 161:
                try:
                    with socket.socket(socket.AF_INET,
                                       socket.SOCK_DGRAM) as u:
                        u.settimeout(timeout)
                        u.sendto(snmp_v1_get("public"), (host, 161))
                        data, _ = u.recvfrom(2048)
                    if data:
                        note(161, "snmp-public",
                             "SNMPv1 responds to community 'public'",
                             risk=True)
                        findings.append(Finding(
                            host=host, port=161,
                            title="SNMP community 'public' accepted",
                            detail="v1/v2c communities travel in cleartext — "
                                   "restrict and upgrade to SNMPv3.",
                            severity=Severity.MEDIUM))
                except OSError:
                    pass
                continue
        except Exception as exc:
            if log:
                log(f"[!] check {port} failed: {exc}")
    return results, findings

def collect_interface_info() -> str:
    lines = [
        "=" * 60, "LOCAL HOST INFORMATION", "=" * 60,
        f"Hostname     : {socket.gethostname()}",
        f"FQDN         : {socket.getfqdn()}",
        f"Platform     : {platform.platform()}",
        f"System       : {platform.system()} {platform.release()}",
        f"Architecture : {platform.machine()}",
        f"Python       : {sys.version.split()[0]}",
        f"Admin        : {'Yes' if is_admin() else 'No'}",
        f"Primary IPv4 : {get_local_ip()}", "",
        "Local IPv4 Addresses:",
    ]
    for a in get_all_local_ips():
        lines.append(f"  • {a}")
    lines += ["", "=" * 60, "NETWORK INTERFACES", "=" * 60]
    try:
        if is_windows():
            out = subprocess.check_output(
                ["ipconfig", "/all"], text=True, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
        elif is_macos():
            out = subprocess.check_output(
                ["ifconfig"], text=True, stderr=subprocess.DEVNULL)
        else:
            try:
                out = subprocess.check_output(
                    ["ip", "addr"], text=True, stderr=subprocess.DEVNULL)
            except FileNotFoundError:
                out = subprocess.check_output(
                    ["ifconfig"], text=True, stderr=subprocess.DEVNULL)
        lines.append(out.rstrip())
    except Exception as exc:
        lines.append(f"(unable to enumerate interfaces: {exc})")
    return "\n".join(lines)

if not hasattr(NetworkScanner, "interface_info"):
    NetworkScanner.interface_info = staticmethod(collect_interface_info)  # type: ignore

def _configure_console_encoding() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError, AttributeError):
            pass

def cli_main(args: argparse.Namespace) -> int:
    scanner = NetworkScanner()
    mode = getattr(args, "mode", "auto") or "auto"
    as_json = bool(getattr(args, "json", False))
    quiet = bool(getattr(args, "quiet", False)) or as_json
    protocol = "udp" if getattr(args, "udp", False) else "tcp"
    rate = float(getattr(args, "rate", 0.0) or 0.0)
    log: Callable[[str], None] = ((lambda s: None) if quiet
                                  else (lambda s: print(s)))
    spec = args.target.strip()
    tf = getattr(args, "targets_file", "")
    if tf:
        try:
            file_spec = Path(tf).read_text(encoding="utf-8-sig")
        except OSError as exc:
            print(f"Cannot read targets file: {exc}", file=sys.stderr)
            return 2
        except UnicodeDecodeError as exc:
            print(f"Targets file is not valid UTF-8 text: {exc}",
                  file=sys.stderr)
            return 2
        spec = f"{spec}\n{file_spec}" if spec else file_spec
    if not spec:
        print("--cli requires --target or --targets-file", file=sys.stderr)
        return 2
    nets: List[ipaddress.IPv4Network] = []
    singles: List[str] = []
    for token in parse_targets(spec):
        net = validate_cidr(token)
        if net is not None:
            nets.append(net)
        elif validate_ip(token):
            singles.append(token)
        else:
            expanded: Optional[List[str]] = None
            with contextlib.suppress(ValueError):
                expanded = expand_target_spec(token)
            if expanded:
                singles.extend(expanded)
            else:
                print(f"Invalid target: {token}", file=sys.stderr)
                return 2
    if not nets and not singles:
        print("No valid targets.", file=sys.stderr)
        return 2

    if not getattr(args, "allow_public", False):
        public = [str(n) for n in nets
                  if not is_private_ip(str(n.network_address))]
        public += [i for i in singles if not is_private_ip(i)]
        if public:
            print("Refused public target(s): "
                  + ", ".join(public[:5]) + (" …" if len(public) > 5 else "")
                  + "\nPass --allow-public only with explicit permission.",
                  file=sys.stderr)
            return 2

    if mode == "auto":
        mode = "discover" if nets and not singles else "ports"
    hosts: List[HostResult] = []
    port_results: List[PortResult] = []
    findings: List[Finding] = []
    ports_spec = parse_port_range(args.ports) or NetworkScanner.TOP_100_PORTS
    try:
        if mode in ("discover", "full"):
            for n in nets:
                log(f"[*] Discovering hosts in {n} …")
                hosts.extend(scanner.discover_hosts(
                    str(n), log=log, ping_timeout=args.timeout,
                    max_workers=args.threads, use_arp=True,
                    use_tcp_ping=True, resolve_hostnames=True, rate=rate))
        if mode in ("ports", "banners", "full"):
            targets = list(singles)
            if mode == "full":
                targets.extend(h.ip for h in hosts)
            if not targets:
                for n in nets:  # ports mode given only a CIDR
                    targets.extend(str(h) for h in n.hosts())
            if not targets:
                print("No hosts to scan.", file=sys.stderr)
                return 2
            for ip in targets:
                scan_list = (NetworkScanner.TOP_100_PORTS if mode == "full"
                             else ports_spec)
                results = scanner.scan_ports(
                    ip, scan_list, log=log, timeout=args.timeout,
                    max_workers=args.threads, protocol=protocol, rate=rate)
                port_results.extend(results)
                if mode in ("ports", "banners") and not as_json:
                    print(f"  {ip}:")
                    for r in results:
                        print(f"    {r.port}/{protocol}  {r.service or '?'}")
                he = next((h for h in hosts if h.ip == ip), None)
                if he is None:
                    he = HostResult(ip=ip)
                    hosts.append(he)
                he.open_ports = sorted({r.port for r in results} |
                                       set(he.open_ports))
                for r in results:
                    if r.service:
                        he.services[r.port] = r.service
            if mode == "banners":
                for he in hosts:
                    if not he.open_ports:
                        continue
                    banners = scanner.grab_banners(
                        he.ip, he.open_ports[:30], log=log)
                    for b in banners:
                        he.banners[b.port] = b.banner or ""
                        if b.version:
                            he.versions[b.port] = b.version
                        for pr in port_results:
                            if pr.host == b.host and pr.port == b.port:
                                pr.banner = b.banner
                                pr.version = b.version
        for he in hosts:
            he.findings = NetworkScanner.analyze_findings(he)
            findings.extend(he.findings)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130

    if mode == "discover" and not as_json:
        print(f"[+] {len(hosts)} host(s) up.")
        for h in hosts:
            print(f"  {h.ip}  {h.mac or '-'}  {h.hostname or '-'}")
    if as_json:
        print(json.dumps({
            "mode": mode, "protocol": protocol,
            "started": datetime.now().isoformat(),
            "hosts": [h.to_dict() for h in hosts],
            "ports": [p.to_dict() for p in port_results],
            "findings": [f.to_dict() for f in findings],
            "stats": scanner.stats.to_dict(),
        }, indent=2, default=str))
    elif findings:
        print(f"\n[!] {len(findings)} finding(s):")
        for f in sorted(findings, key=lambda x: -x.severity.rank):
            print(f"  [{f.severity.value.upper():<8}] {f.host}:"
                  f"{f.port or ''} {f.title}")
    return 0

def selftest() -> int:
    failures = 0
    def check(name: str, cond: bool, detail: Any = "") -> None:
        nonlocal failures
        if cond:
            print(f"  PASS  {name}")
        else:
            suffix = f"  ({detail})" if detail != "" else ""
            print(f"  FAIL  {name}{suffix}")
            failures += 1
    print(f"[*] Running {APP_NAME} v{APP_VERSION} self-test\n")
    check("parse_port_range simple", parse_port_range("80") == [80])
    check("parse_port_range range", parse_port_range("80-82") == [80, 81, 82])
    check("parse_port_range mix", parse_port_range("22,80,443") == [22, 80, 443])
    check("parse_port_range invalid", parse_port_range("abc") is None)
    check("parse_port_range out of range", parse_port_range("99999") is None)
    check("validate_ip 192.168.1.1", validate_ip("192.168.1.1"))
    check("validate_ip invalid", not validate_ip("999.999.999.999"))
    check("validate_cidr /24",
          validate_cidr("192.168.1.0/24") is not None)
    check("validate_cidr invalid",
          validate_cidr("192.168.1.0/33") is None)
    check("is_private 10.0.0.1", is_private_ip("10.0.0.1"))
    check("is_private 127.0.0.1", is_private_ip("127.0.0.1"))
    check("is_private 192.168.1.1", is_private_ip("192.168.1.1"))
    check("is_private 8.8.8.8", not is_private_ip("8.8.8.8"))
    check("sanitize ANSI", "\x1b[31m" not in sanitize_log("\x1b[31mhello"))
    check("sanitize control", "\x00" not in sanitize_log("a\x00b"))
    info = NetworkScanner.subnet_info("192.168.1.0/24")
    check("subnet num_addresses",
          info is not None and info["num_addresses"] == 256)
    check("subnet first_host",
          info is not None and info["first_host"] == "192.168.1.1")
    check("format_mac", format_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF")
    check("vendor Apple",
          get_vendor_from_mac("00:1b:63:aa:bb:cc") == "Apple")
    check("device router",
          guess_device_type("router.local", None, []) == "Router/Firewall")
    check("device printer",
          guess_device_type("printer", None, []) == "Printer")
    check("device unknown",
          guess_device_type("xyz", None, []) == "Unknown")
    check("WOL bad MAC", WakeOnLan.send("not a mac") is False)
    hr = HostResult(ip="10.0.0.1", open_ports=[23, 3389])
    fs = NetworkScanner.analyze_findings(hr)
    check("findings detects telnet+rdp", len(fs) == 2)
    check("expand CIDR", expand_target_spec("192.168.5.0/30") ==
          ["192.168.5.1", "192.168.5.2"])
    check("expand dash range",
          expand_target_spec("10.0.0.5-7") ==
          ["10.0.0.5", "10.0.0.6", "10.0.0.7"])
    check("expand suffix range",
          expand_target_spec("10.0.0.10-12") ==
          ["10.0.0.10", "10.0.0.11", "10.0.0.12"])
    check("expand invalid", expand_target_spec("not-an-ip") is None)
    check("rate limiter unlimited", RateLimiter(0.0).wait() is True)
    check("version extract SSH",
          NetworkScanner().extract_version(
              "SSH", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4") == "8.9p1")
    check("aggregate_cidrs",
          aggregate_cidrs(["192.168.1.4", "192.168.1.5"]) ==
          ["192.168.1.4/31"])
    check("aggregate_cidrs single",
          aggregate_cidrs(["10.0.0.7"]) == ["10.0.0.7/32"])
    check("udp payload DNS", udp_probe_payload(53, "192.168.1.1") != b"")
    check("udp payload SNMP", udp_probe_payload(161).startswith(b"\x30"))
    check("ber tlv", _ber_tlv(0x04, b"ab") == b"\x04\x02ab")
    check("tls assess flags", len(tls_assess({
        "host": "1.2.3.4", "port": 443, "error": None,
        "weak_protocol": True, "weak_cipher": True,
        "cipher": "RC4-MD5", "tls_version": "TLSv1.0",
        "expired": False, "days_left": 400,
        "self_signed": False, "san": ["example.com"],
    })) >= 2)
    check("tls assess clean", tls_assess({
        "host": "1.2.3.4", "port": 443, "error": None,
        "weak_protocol": False, "weak_cipher": False,
        "expired": False, "days_left": 400,
        "self_signed": False, "san": ["example.com"],
    }) == [])
    vuln_host = HostResult(ip="10.0.0.9", open_ports=[21])
    vuln_host.versions[21] = "2.3.4"
    vuln_host.banners[21] = "vsftpd 2.3.4"
    vulns = NetworkScanner.analyze_vulnerabilities(vuln_host)
    check("vuln rule vsftpd backdoor",
          any("CVE-2014-6271" in v.title for v in vulns))
    export = build_export_data([hr], [], [], None)
    check("build_export_data",
          "report_id" in export and "stats" in export)
    check("http enum paths", "/.git/HEAD" in HTTP_ENUM_PATHS)

    def _ber_probe(b: bytes, off: int) -> Tuple[int, int, int]:
        tag = b[off]; off += 1
        ln = b[off]; off += 1
        if ln & 0x80:
            n = ln & 0x7F
            ln = int.from_bytes(b[off:off + n], "big"); off += n
        return tag, off, ln
    pkt = snmp_v1_get("public")
    _t, _o, _l = _ber_probe(pkt, 0)
    _t1, o1, l1 = _ber_probe(pkt, _o)
    _t2, o2, l2 = _ber_probe(pkt, o1 + l1)
    t3, o3, l3 = _ber_probe(pkt, o2 + l2)
    pdu = pkt[o3:o3 + l3]
    _a, oa, la = _ber_probe(pdu, 0)
    _b, ob, lb = _ber_probe(pdu, oa + la)
    _c, oc, lc = _ber_probe(pdu, ob + lb)
    _d, od, ld = _ber_probe(pdu, oc + lc)
    check("snmp PDU tag is GetRequest", t3 == 0xA0)
    check("snmp request-id is 4 bytes", la == 4, la)
    check("snmp error-status is 2 bytes", lb == 2, lb)
    check("snmp error-index is 2 bytes", lc == 2, lc)
    check("snmp PDU fully consumed", od + ld == len(pdu),
          f"{od + ld} of {len(pdu)}")
    dns_probe = udp_probe_payload(53, "192.168.1.1")
    check("udp DNS probe is a PTR query",
          struct.unpack("!H", dns_probe[-4:-2])[0] == 12)
    check("udp DNS probe hostname is an A query",
          struct.unpack("!H", udp_probe_payload(53, "example.com")[-4:-2])[0]
          == 1)
    for cidr in ("192.168.1.0/24", "10.0.0.0/8", "10.0.0.0/31",
                 "10.0.0.5/32", "192.168.1.128/25"):
        _net = ipaddress.ip_network(cidr)
        check(f"host count {cidr}",
              network_host_count(_net) == len(list(_net.hosts())))
    try:
        expand_target_spec("10.0.0.0/8")
        check("oversized CIDR rejected", False, "no ValueError")
    except ValueError:
        check("oversized CIDR rejected", True)
    _big = NetworkScanner.subnet_info("10.0.0.0/8")
    check("subnet_info on /8 is O(1)",
          _big is not None and _big["num_hosts"] == 16777214
          and _big["first_host"] == "10.0.0.1"
          and _big["last_host"] == "10.255.255.254", _big)
    ldap_only = NetworkScanner.analyze_findings(
        HostResult(ip="10.0.0.1", open_ports=[636]))
    check("finding reports the open port, not the rule's first",
          any(f.port == 636 for f in ldap_only)
          and not any(f.port == 389 for f in ldap_only),
          [(f.port, f.title) for f in ldap_only])
    check("OUI table has no duplicate keys",
          len(_OUI_DB) == len(set(_OUI_DB)))
    check("NETGEAR vendor casing is consistent",
          get_vendor_from_mac("00:1f:33:aa:bb:cc") == "NETGEAR")
    check("_coerce_port rejects non-numeric", _coerce_port("abc") is None)
    check("_coerce_port accepts numeric strings", _coerce_port("80") == 80)
    check("_coerce_port rejects bool", _coerce_port(True) is None)
    before = sys.stdout
    _configure_console_encoding()
    check("console reconfigure is safe to call repeatedly",
          sys.stdout is before)
    try:
        with tempfile.TemporaryDirectory() as td:
            sp = Path(td) / "session.json"
            save_session(sp, [hr],
                         [PortResult(host="10.0.0.1", port=22)], fs)
            loaded = load_session(sp)
            check("session round-trip",
                  loaded is not None and len(loaded[0]) == 1
                  and loaded[0][0].ip == "10.0.0.1")
            if loaded is not None:
                check("session findings preserved",
                      len(loaded[2]) == len(fs))
            doc = json.loads(sp.read_text(encoding="utf-8"))
            doc["payload"]["hosts"][0]["ip"] = "10.0.0.2"
            sp.write_text(json.dumps(doc), encoding="utf-8")
            check("session checksum detects tamper",
                  load_session(sp) is None)
    except Exception as e:
        print(f"  FAIL  session: {e}")
        failures += 1
    check("os fingerprint table exists",
          hasattr(NetworkScanner, "os_fingerprint"))
    check("scanner wrappers exist",
          all(hasattr(NetworkScanner, m) for m in
              ("tls_inspect", "http_enumerate", "service_checks")))
    check("snmp packet starts with sequence",
          snmp_v1_get("public").startswith(b"\x30"))
    print()
    if failures == 0:
        print("[+] All self-tests passed.")
    else:
        print(f"[!] {failures} self-test failure(s).")
    return 0 if failures == 0 else 1

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=f"{APP_NAME} v{APP_VERSION}")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {APP_VERSION}")
    parser.add_argument("--selftest", action="store_true",
                        help="Run internal self-test")
    parser.add_argument("--cli", action="store_true",
                        help="Run headless CLI mode")
    parser.add_argument("--target", "-t", default="",
                        help="Target IP or CIDR (CLI mode)")
    parser.add_argument("--ports", "-p", default="22,80,443",
                        help="Port spec (CLI mode)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_PORT_TIMEOUT,
                        help="Probe timeout (s)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help="Max threads")
    parser.add_argument("--mode", choices=("auto", "discover", "ports",
                                           "banners", "full"),
                        default="auto", help="CLI scan mode")
    parser.add_argument("--udp", action="store_true",
                        help="Use UDP probes in ports/banners mode")
    parser.add_argument("--rate", type=float, default=DEFAULT_RATE_PPS,
                        help="Max probes/second (0 = unlimited)")
    parser.add_argument("--targets-file", default="",
                        help="File containing targets (CIDR/IP/ranges)")
    parser.add_argument("--allow-public", action="store_true",
                        help="Allow non-private targets (requires permission)")
    parser.add_argument("--json", action="store_true",
                        help="Emit machine-readable JSON output")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress progress logs")
    args = parser.parse_args(argv)
    _configure_console_encoding()
    if args.selftest:
        return selftest()
    if args.cli:
        if not args.target and not args.targets_file:
            parser.error("--cli requires --target and/or --targets-file")
        return cli_main(args)
    if not _HAVE_TK:
        print("[!] Tkinter not available; use --cli or --selftest.",
              file=sys.stderr)
        return 1
    try:
        root = tk.Tk()
        app = NetworkToolkitGUI(root)
        root.protocol("WM_DELETE_WINDOW", app.on_quit)
        def _sigint(sig: int, frame: Any) -> None:
            app.on_quit()
        with contextlib.suppress(Exception):
            signal.signal(signal.SIGINT, _sigint)
        root.mainloop()
        return 0
    except Exception as exc:
        save_crash_report(exc, "main")
        print(f"Fatal error: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
